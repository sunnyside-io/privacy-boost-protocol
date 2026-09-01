// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2026 Sunnyside Labs Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
pragma solidity 0.8.34;

import {GatewayBaseTest} from "./GatewayBase.t.sol";
import {
    GatewayAction,
    GatewayReceipt,
    GatewaySlot,
    GatewaySettlementOutcome,
    Output,
    Withdrawal,
    EpochTreeState,
    TreeRootPair,
    DepositEntry
} from "src/interfaces/IStructs.sol";
import {IPrivacyBoost} from "src/interfaces/IPrivacyBoost.sol";
import {DepositCiphertext, DepositOrigin} from "src/interfaces/IStructs.sol";
import {Poseidon2T4} from "src/hash/Poseidon2T4.sol";
import {DOMAIN_NOTE} from "src/interfaces/Constants.sol";
import {LibDigest} from "src/lib/LibDigest.sol";
import {EpochHelpers} from "test/helpers/EpochHelpers.sol";

/// @notice Regression tests for gateway-origin deposit handling and gateway digest binding.
contract GatewayOriginAndDigestBindingTest is GatewayBaseTest {
    bytes32 constant RC = keccak256("rc-regression");

    /// @notice A gateway-origin pending deposit must be materializable via submitDepositEpoch.
    ///         The pool stores `commitmentsHash` in the sequential `computeCommitmentsHashStep(0, c)` form,
    ///         which `submitDepositEpoch` re-derives and compares.
    function test_gatewayOriginDepositMaterializesEndToEnd() public {
        // Trigger an external ERC-4626 deposit → gateway-origin pending deposit.
        Withdrawal memory w = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot = _erc4626DepositSlot(0, 100 ether, 1, RC, 10);
        _submitOneWithdrawal(w, _slotArr1(slot));
        GatewayReceipt memory r = slot.receipt;

        // Reconstruct the deterministic depositRequestId.
        uint256 commitment = Poseidon2T4.hash4(DOMAIN_NOTE, r.npk, uint256(r.outputTokenId), uint256(uint96(100 ether)));
        uint256 commitmentsHash = LibDigest.computeCommitmentsHashStep(0, commitment);
        uint256 depositRequestId = LibDigest.computeDepositRequestId(
            block.chainid, address(pool), address(externalGateway), idVault4626, uint96(100 ether), 0, commitmentsHash
        );

        // Verify the stored pending deposit shape is consistent with a normal one-commitment deposit.
        (,,,, uint32 nonce, uint16 commitmentCount, uint256 storedHash, bytes32 storedRescue) =
            pool.pendingDeposits(depositRequestId);
        assertEq(nonce, 0);
        assertEq(commitmentCount, 1);
        assertEq(storedHash, commitmentsHash, "sequential hash, not raw commitment");
        assertEq(storedRescue, RC);

        // Run submitDepositEpoch on this single deposit. We have to advance to a new tree state and
        // append exactly 1 commitment.
        uint256 rootOld = pool.treeRoot(pool.currentTreeNumber());
        uint32 countOld = pool.treeCount(pool.currentTreeNumber());
        TreeRootPair[] memory usedRoots = EpochHelpers.buildUsedRoots(0, rootOld);

        // Use the same circuit shape as submitDepositEpoch: maxSlots = batchSize. The first output
        // carries the gateway-origin commitment; the rest are dummies (zeros).
        Output[] memory depOutputs = new Output[](BATCH_SIZE);
        depOutputs[0] = EpochHelpers.makeOutput(commitment);
        depOutputs[1] = EpochHelpers.makeOutput(0); // padding

        DepositEntry[] memory deposits = new DepositEntry[](1);
        deposits[0] = DepositEntry({depositRequestId: depositRequestId});

        EpochTreeState memory tree =
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, _someNewRoot(), countOld + 1, false);

        vm.prank(relayer);
        pool.submitDepositEpoch(tree, 1, depOutputs, deposits, EpochHelpers.dummyProof());

        // Pool marked deposit processed.
        assertTrue(pool.processedDeposits(depositRequestId));
    }

    function _someNewRoot() internal pure returns (uint256) {
        // MockVerifier accepts anything; any non-zero is fine.
        return uint256(keccak256("dummy-new-root"));
    }

    /// @notice `submitEpoch` must NOT accept a withdrawal whose target is
    ///         an approved gateway address. Without this, a relay could send funds to a gateway with
    ///         no paired GatewaySlot, leaving them stuck and skipping the receipt-deposit.
    function test_plainSubmitEpoch_rejectsGatewayTarget() public {
        // Build a normal (non-Gateway) submitEpoch call whose withdrawal targets the gateway.
        Withdrawal memory w = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        (
            Output[] memory outputs,
            uint256[] memory nullifiers,
            Output[] memory feeOutputs,
            Withdrawal[] memory withdrawals,
            uint32[] memory withdrawalSlots
        ) = _buildSingleWithdrawalEpoch(w);

        uint256 rootOld = pool.treeRoot(pool.currentTreeNumber());
        uint32 countOld = pool.treeCount(pool.currentTreeNumber());
        TreeRootPair[] memory usedRoots = EpochHelpers.buildUsedRoots(0, rootOld);
        EpochTreeState memory tree = EpochHelpers.buildTreeState(usedRoots, 0, countOld, 1, countOld + 2, false);
        TreeRootPair[] memory usedAuthRoots = EpochHelpers.buildAuthRoots(0, 1);

        vm.prank(relayer);
        vm.expectRevert(IPrivacyBoost.MissingGatewaySlot.selector);
        pool.submitEpoch(
            tree,
            usedAuthRoots,
            2,
            1,
            1,
            _u32arr(1, 2),
            _u32arr(1, 2),
            _wrap2D(nullifiers, 2),
            _buildTransfersN(outputs, 2),
            EpochHelpers.buildFeeTransfer(feeOutputs),
            withdrawals,
            withdrawalSlots,
            uint64(block.timestamp),
            EpochHelpers.dummyProof(),
            new GatewaySlot[](0)
        );
    }

    /// @notice The GatewaySlot is bound into the per-withdrawal digest via
    ///         `PB:WITHDRAW:GATEWAY:v2`. Plain WITHDRAW digest must differ from gateway-withdraw digest so
    ///         a user signature for one cannot be replayed against the other.
    function test_gatewayWithdrawalDigest_differsFromPlainDigest() public view {
        Withdrawal memory w = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = 123;
        Output[] memory outputs = new Output[](1);
        outputs[0] = EpochHelpers.makeOutput(456);
        GatewaySlot memory slot = _erc4626DepositSlot(0, 100 ether, 1, RC, 99);

        (uint256 plainHi, uint256 plainLo) = LibDigest.computeWithdrawalDigest(
            block.chainid, address(pool), nullifiers, outputs, w, bytes32(0), bytes32(0)
        );
        (uint256 gatewayHi, uint256 gatewayLo) = this.computeGatewayWithdrawalDigestExternal(
            block.chainid, address(pool), nullifiers, outputs, w, bytes32(0), bytes32(0), slot
        );
        assertTrue(plainHi != gatewayHi || plainLo != gatewayLo, "gateway digest must differ from plain");
    }

    function computeGatewayWithdrawalDigestExternal(
        uint256 chainId,
        address poolAddress,
        uint256[] calldata nullifiers,
        Output[] calldata outputs,
        Withdrawal calldata withdrawal,
        bytes32 viewingKey,
        bytes32 teeWrapKey,
        GatewaySlot calldata slot
    ) external pure returns (uint256 hi, uint256 lo) {
        return LibDigest.computeGatewayWithdrawalDigest(
            chainId, poolAddress, nullifiers, outputs, withdrawal, viewingKey, teeWrapKey, slot
        );
    }

    /// @notice Gateway-origin pending deposits should be visible to a normal indexer
    ///         that subscribes to `DepositRequested` (spec §4.3). This test confirms the event shape.
    function test_gatewayOriginEmitsStandardDepositRequested() public {
        Withdrawal memory w = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot = _erc4626DepositSlot(0, 100 ether, 1, RC, 50);
        GatewayReceipt memory r = slot.receipt;

        uint256 commitment = Poseidon2T4.hash4(DOMAIN_NOTE, r.npk, uint256(r.outputTokenId), uint256(uint96(100 ether)));
        uint256 commitmentsHash = LibDigest.computeCommitmentsHashStep(0, commitment);
        uint256 depositRequestId = LibDigest.computeDepositRequestId(
            block.chainid, address(pool), address(externalGateway), idVault4626, uint96(100 ether), 0, commitmentsHash
        );

        // Just listen for the standard event with matching indexed fields.
        vm.expectEmit(true, true, true, false, address(pool));
        emit IPrivacyBoost.DepositRequested(
            depositRequestId,
            address(externalGateway),
            DepositOrigin.GatewayRedeposit,
            idVault4626,
            uint96(100 ether),
            1,
            commitmentsHash,
            new uint256[](0), // unchecked
            new DepositCiphertext[](0) // unchecked
        );
        _submitOneWithdrawal(w, _slotArr1(slot));
    }

    function test_gatewayOriginEmitsCompanionForExternalDeposit() public {
        Withdrawal memory w = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot = _erc4626DepositSlot(0, 100 ether, 1, RC, 51);
        GatewayReceipt memory r = slot.receipt;

        uint256 commitment = Poseidon2T4.hash4(DOMAIN_NOTE, r.npk, uint256(r.outputTokenId), uint256(uint96(100 ether)));
        uint256 commitmentsHash = LibDigest.computeCommitmentsHashStep(0, commitment);
        uint256 depositRequestId = LibDigest.computeDepositRequestId(
            block.chainid, address(pool), address(externalGateway), idVault4626, uint96(100 ether), 0, commitmentsHash
        );
        bytes32 receiptHash = keccak256(abi.encode(r));

        vm.expectEmit(true, true, false, true, address(pool));
        emit IPrivacyBoost.GatewayOriginDepositRecorded(
            depositRequestId, receiptHash, GatewayAction.ExternalCall, GatewaySettlementOutcome.Executed, RC, 0
        );
        _submitOneWithdrawal(w, _slotArr1(slot));
    }

    function test_gatewayOriginEmitsCompanionForExternalRedeem() public {
        uint256 shares = _fundPoolWithVaultShares(100 ether, user);
        Withdrawal memory w = Withdrawal({to: address(externalGateway), tokenId: idVault4626, amount: uint96(shares)});
        GatewaySlot memory slot = _erc4626RedeemSlot(0, uint96(shares), 1, RC, 52);
        GatewayReceipt memory r = slot.receipt;

        uint256 commitment = Poseidon2T4.hash4(DOMAIN_NOTE, r.npk, uint256(r.outputTokenId), uint256(uint96(100 ether)));
        uint256 commitmentsHash = LibDigest.computeCommitmentsHashStep(0, commitment);
        uint256 depositRequestId = LibDigest.computeDepositRequestId(
            block.chainid, address(pool), address(externalGateway), idUsdc, uint96(100 ether), 0, commitmentsHash
        );
        bytes32 receiptHash = keccak256(abi.encode(r));

        vm.expectEmit(true, true, false, true, address(pool));
        emit IPrivacyBoost.GatewayOriginDepositRecorded(
            depositRequestId, receiptHash, GatewayAction.ExternalCall, GatewaySettlementOutcome.Executed, RC, 0
        );
        _submitOneWithdrawal(w, _slotArr1(slot));
    }

    function test_policy_removed_between_sign_and_submit_fallsBack() public {
        Withdrawal memory w = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot = _erc4626DepositSlot(0, 100 ether, 1, RC, 53);
        SubmitArgs memory args = _prepareSingleWithdrawal(w);

        externalGateway.removeCallPolicy(address(vault4626), bytes4(slot.callData));
        uint256 poolInputBefore = usdc.balanceOf(address(pool));
        uint256 poolShareBefore = vault4626.balanceOf(address(pool));

        _callSubmit(args, _slotArr1(slot));

        assertEq(usdc.balanceOf(address(pool)), poolInputBefore, "input preserved for fallback");
        assertEq(vault4626.balanceOf(address(pool)), poolShareBefore, "primary output not credited");
    }
}
