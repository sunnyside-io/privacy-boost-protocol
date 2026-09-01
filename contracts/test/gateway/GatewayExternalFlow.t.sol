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
import {GatewayAction, GatewayReceipt, GatewaySlot, Withdrawal} from "src/interfaces/IStructs.sol";
import {IPrivacyBoost} from "src/interfaces/IPrivacyBoost.sol";
import {DOMAIN_NOTE} from "src/interfaces/Constants.sol";
import {Poseidon2T4} from "src/hash/Poseidon2T4.sol";
import {LibDigest} from "src/lib/LibDigest.sol";
import {MockERC4626} from "test/helpers/GatewayMocks.sol";

contract GatewayExternalFlowTest is GatewayBaseTest {
    bytes32 constant RC = keccak256("rc-sync");

    function test_erc4626_depositViaExternalCall_happyPath() public {
        Withdrawal memory w = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot = _erc4626DepositSlot(0, 100 ether, 1, RC, 1);

        uint256 vaultBalBefore = vault4626.balanceOf(address(pool));
        _submitOneWithdrawal(w, _slotArr1(slot));

        // Pool received vault shares 1:1 (empty vault).
        assertEq(vault4626.balanceOf(address(pool)) - vaultBalBefore, 100 ether);
        assertEq(usdc.balanceOf(address(externalGateway)), 0);
        assertEq(vault4626.balanceOf(address(externalGateway)), 0);
    }

    function test_erc4626_redeemViaExternalCall_happyPath() public {
        // Pool holds vault shares from a prior deposit by `user`.
        _fundPoolWithVaultShares(100 ether, user);
        uint256 usdcBefore = usdc.balanceOf(address(pool));

        Withdrawal memory w = Withdrawal({to: address(externalGateway), tokenId: idVault4626, amount: 100 ether});
        GatewaySlot memory slot = _erc4626RedeemSlot(0, 100 ether, 1, RC, 2);
        _submitOneWithdrawal(w, _slotArr1(slot));

        assertEq(usdc.balanceOf(address(pool)) - usdcBefore, 100 ether);
        assertEq(vault4626.balanceOf(address(externalGateway)), 0);
        assertEq(vault4626.allowance(address(pool), address(externalGateway)), 0, "pool allowance cleared");
        assertEq(vault4626.allowance(address(externalGateway), address(vault4626)), 0, "vault allowance cleared");
    }

    function test_erc4626_depositViaExternalCall_ignoresPreExistingDust() public {
        usdc.mint(address(externalGateway), 7777); // dust

        Withdrawal memory w = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot = _erc4626DepositSlot(0, 100 ether, 1, RC, 3);
        _submitOneWithdrawal(w, _slotArr1(slot));

        assertEq(usdc.balanceOf(address(externalGateway)), 7777, "dust untouched");
        assertEq(vault4626.balanceOf(address(pool)), 100 ether);
    }

    function test_erc4626_depositViaExternalCall_belowMinOutputFallsBack() public {
        Withdrawal memory w = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot = _erc4626DepositSlot(0, 100 ether, 200 ether, RC, 4); // unreachable min
        SubmitArgs memory args = _prepareSingleWithdrawal(w);
        _callSubmit(args, _slotArr1(slot));
        assertEq(usdc.balanceOf(address(pool)), 10_000 ether, "input fallback preserved");
    }

    function test_erc4626_depositViaExternalCall_targetExhaustsForwardedGasFallsBack() public {
        Withdrawal memory w = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot = _erc4626DepositSlot(0, 100 ether, 1, RC, 40);
        SubmitArgs memory args = _prepareSingleWithdrawal(w);

        vault4626.setDepositMode(MockERC4626.DepositMode.BurnGas);
        _callSubmitWithGas(args, _slotArr1(slot), 5_000_000);

        assertEq(usdc.balanceOf(address(pool)), 10_000 ether, "input fallback preserved");
        assertEq(usdc.allowance(address(pool), address(externalGateway)), 0, "pool allowance cleared");
    }

    function test_erc4626_revertsWithSettlementGasError_beforeUnderfundedGatewayCall() public {
        // Arrange
        Withdrawal memory w = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot = _erc4626DepositSlot(0, 100 ether, 1, RC, 49);
        SubmitArgs memory args = _prepareSingleWithdrawal(w);
        vault4626.setDepositMode(MockERC4626.DepositMode.BurnGas);

        // Act and assert
        vm.expectPartialRevert(IPrivacyBoost.InsufficientGatewaySettlementGas.selector);
        _callSubmitWithGas(args, _slotArr1(slot), 1_100_000);
    }

    function test_plainOnlyEpoch_settlesBelowGatewaySettlementFloor() public {
        // Arrange. A plain recipient with no Gateway slot makes no untrusted call, so the epoch must
        // not inherit the Gateway settlement-gas floor. The relay does not preflight this path.
        Withdrawal memory w = Withdrawal({to: user, tokenId: idUsdc, amount: 100 ether});
        SubmitArgs memory args = _prepareSingleWithdrawal(w);
        uint256 recipientBefore = usdc.balanceOf(user);

        // Act. At this cap settlement entry sits near 465k, below the 500k Gateway floor.
        _callSubmitWithGas(args, new GatewaySlot[](0), 700_000);

        // Assert
        assertEq(usdc.balanceOf(user) - recipientBefore, 100 ether, "plain withdrawal paid out");
        _assertEpochSettled(args);
    }

    function test_erc4626_locallyStarvedSlot_rollsBackAndFallsBack() public {
        // Arrange
        Withdrawal memory w = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot = _erc4626DepositSlot(0, 100 ether, 1, RC, 50);
        SubmitArgs memory args = _prepareSingleWithdrawal(w);
        vault4626.setDepositMode(MockERC4626.DepositMode.BurnGas);

        // Act. This cap reaches settlement but leaves the isolated child below its 500k record reserve.
        _callSubmitWithGas(args, _slotArr1(slot), 1_500_000);

        // Assert
        assertEq(usdc.balanceOf(address(pool)), 10_000 ether, "child-frame balance changes rolled back");
        assertEq(usdc.allowance(address(pool), address(externalGateway)), 0, "child-frame approval rolled back");
        assertEq(vault4626.balanceOf(address(pool)), 0);
        assertEq(pool.depositNonces(address(externalGateway)), 1);
        _assertGatewayPending(slot.fallbackReceipt, w.amount, 0);
        _assertEpochSettled(args);
    }

    function test_erc4626_twoGasExhaustingTargets_settleThroughFallbacks() public {
        // Arrange
        Withdrawal memory w0 = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        Withdrawal memory w1 = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 200 ether});
        GatewaySlot memory slot0 = _erc4626DepositSlot(0, 100 ether, 1, RC, 41);
        GatewaySlot memory slot1 = _erc4626DepositSlot(1, 200 ether, 1, RC, 42);
        SubmitArgs memory args = _prepareTwoWithdrawals(w0, w1);
        vault4626.setDepositMode(MockERC4626.DepositMode.BurnGas);

        // Act
        _callSubmitWithGas(args, _slotArr2(slot0, slot1), 5_000_000);

        // Assert
        assertEq(usdc.balanceOf(address(pool)), 10_000 ether, "both inputs preserved");
        assertEq(usdc.allowance(address(pool), address(externalGateway)), 0, "pool allowance rolled back");
        assertEq(pool.depositNonces(address(externalGateway)), 2, "one fallback deposit per slot");
        _assertGatewayPending(slot0.fallbackReceipt, w0.amount, 0);
        _assertGatewayPending(slot1.fallbackReceipt, w1.amount, 1);
        _assertEpochSettled(args);
    }

    function test_erc4626_gasExhaustingTargetBeforeHealthyTarget_keepsBatchProgress() public {
        // Arrange
        MockERC4626 healthyVault = new MockERC4626(usdc);
        uint16 healthyVaultId = _registerDepositVault(healthyVault);
        Withdrawal memory w0 = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        Withdrawal memory w1 = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 200 ether});
        GatewaySlot memory slot0 = _erc4626DepositSlot(0, 100 ether, 1, RC, 43);
        GatewaySlot memory slot1 = _erc4626DepositSlotFor(healthyVault, healthyVaultId, 1, 200 ether, 1, RC, 44);
        SubmitArgs memory args = _prepareTwoWithdrawals(w0, w1);
        vault4626.setDepositMode(MockERC4626.DepositMode.BurnGas);

        // Act
        _callSubmitWithGas(args, _slotArr2(slot0, slot1), 5_000_000);

        // Assert
        assertEq(usdc.balanceOf(address(pool)), 9_800 ether, "only healthy input spent");
        assertEq(healthyVault.balanceOf(address(pool)), 200 ether, "later healthy slot executed");
        assertEq(pool.depositNonces(address(externalGateway)), 2);
        _assertGatewayPending(slot0.fallbackReceipt, w0.amount, 0);
        _assertGatewayPending(slot1.receipt, w1.amount, 1);
        _assertEpochSettled(args);
    }

    function test_erc4626_healthyTargetBeforeGasExhaustingTarget_keepsBatchProgress() public {
        // Arrange
        MockERC4626 healthyVault = new MockERC4626(usdc);
        uint16 healthyVaultId = _registerDepositVault(healthyVault);
        Withdrawal memory w0 = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        Withdrawal memory w1 = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 200 ether});
        GatewaySlot memory slot0 = _erc4626DepositSlotFor(healthyVault, healthyVaultId, 0, 100 ether, 1, RC, 45);
        GatewaySlot memory slot1 = _erc4626DepositSlot(1, 200 ether, 1, RC, 46);
        SubmitArgs memory args = _prepareTwoWithdrawals(w0, w1);
        vault4626.setDepositMode(MockERC4626.DepositMode.BurnGas);

        // Act
        _callSubmitWithGas(args, _slotArr2(slot0, slot1), 5_000_000);

        // Assert
        assertEq(usdc.balanceOf(address(pool)), 9_900 ether, "only healthy input spent");
        assertEq(healthyVault.balanceOf(address(pool)), 100 ether, "earlier healthy slot executed");
        assertEq(pool.depositNonces(address(externalGateway)), 2);
        _assertGatewayPending(slot0.receipt, w0.amount, 0);
        _assertGatewayPending(slot1.fallbackReceipt, w1.amount, 1);
        _assertEpochSettled(args);
    }

    function test_erc4626_gasExhaustingTargetBeforePlainWithdrawal_keepsBatchProgress() public {
        // Arrange
        Withdrawal memory gateway = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        Withdrawal memory plain = Withdrawal({to: user, tokenId: idUsdc, amount: 50 ether});
        GatewaySlot memory slot = _erc4626DepositSlot(0, 100 ether, 1, RC, 47);
        SubmitArgs memory args = _prepareTwoWithdrawals(gateway, plain);
        vault4626.setDepositMode(MockERC4626.DepositMode.BurnGas);

        // Act
        _callSubmitWithGas(args, _slotArr1(slot), 5_000_000);

        // Assert
        assertEq(user.balance, 0);
        assertEq(usdc.balanceOf(user), 50 ether, "later plain withdrawal settled");
        assertEq(usdc.balanceOf(address(pool)), 9_950 ether);
        _assertGatewayPending(slot.fallbackReceipt, gateway.amount, 0);
        _assertEpochSettled(args);
    }

    function test_erc4626_plainWithdrawalBeforeGasExhaustingTarget_keepsBatchProgress() public {
        // Arrange
        Withdrawal memory plain = Withdrawal({to: user, tokenId: idUsdc, amount: 50 ether});
        Withdrawal memory gateway = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot = _erc4626DepositSlot(1, 100 ether, 1, RC, 48);
        SubmitArgs memory args = _prepareTwoWithdrawals(plain, gateway);
        vault4626.setDepositMode(MockERC4626.DepositMode.BurnGas);

        // Act
        _callSubmitWithGas(args, _slotArr1(slot), 5_000_000);

        // Assert
        assertEq(usdc.balanceOf(user), 50 ether, "earlier plain withdrawal settled");
        assertEq(usdc.balanceOf(address(pool)), 9_950 ether);
        _assertGatewayPending(slot.fallbackReceipt, gateway.amount, 0);
        _assertEpochSettled(args);
    }

    function test_pending_deposit_cancel_rejectsGatewayOrigin() public {
        // Trigger an ERC-4626 external call that creates a gateway-origin pending deposit.
        Withdrawal memory w = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot = _erc4626DepositSlot(0, 100 ether, 1, RC, 5);
        _submitOneWithdrawal(w, _slotArr1(slot));
        GatewayReceipt memory r = slot.receipt;

        uint256 commitment = Poseidon2T4.hash4(DOMAIN_NOTE, r.npk, uint256(r.outputTokenId), uint256(uint96(100 ether)));
        uint256 commitmentsHash = LibDigest.computeCommitmentsHashStep(0, commitment);
        uint256 depositRequestId = LibDigest.computeDepositRequestId(
            block.chainid,
            address(pool),
            address(externalGateway),
            r.outputTokenId,
            uint96(100 ether),
            0,
            commitmentsHash
        );

        vm.roll(block.number + 11);
        vm.prank(address(externalGateway));
        vm.expectRevert(IPrivacyBoost.GatewayOriginCannotCancel.selector);
        pool.cancelDeposit(depositRequestId);
    }

    function test_external_invalidActionReverts() public {
        Withdrawal memory w = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        GatewayReceipt memory receipt = _makeReceipt(idVault4626, 1, RC, 6);
        GatewaySlot memory slot = GatewaySlot({
            withdrawalIndex: 0,
            action: GatewayAction.Invalid,
            expiryBlock: uint64(block.number + 100),
            target: address(vault4626),
            callData: bytes("invalid"),
            receipt: receipt,
            fallbackReceipt: _makeFallbackReceipt(idUsdc, RC, 16_006)
        });
        SubmitArgs memory args = _prepareSingleWithdrawal(w);
        vm.expectRevert(IPrivacyBoost.RouteMismatch.selector);
        _callSubmit(args, _slotArr1(slot));
    }

    function test_external_missingGatewaySlotReverts() public {
        Withdrawal memory w = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        SubmitArgs memory args = _prepareSingleWithdrawal(w);
        GatewaySlot[] memory empty = new GatewaySlot[](0);
        vm.expectRevert(IPrivacyBoost.MissingGatewaySlot.selector);
        _callSubmit(args, empty);
    }

    function test_external_plainTargetWithSlotReverts() public {
        Withdrawal memory w = Withdrawal({to: user, tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot = _erc4626DepositSlot(0, 100 ether, 1, RC, 7);
        SubmitArgs memory args = _prepareSingleWithdrawal(w);
        vm.expectRevert(IPrivacyBoost.UnexpectedGatewaySlot.selector);
        _callSubmit(args, _slotArr1(slot));
    }

    function _assertEpochSettled(SubmitArgs memory args) internal view {
        assertEq(pool.treeRoot(args.tree.activeTreeNumber), args.tree.rootNew, "tree root finalized");
        assertTrue(pool.nullifierSpent(args.nullifiers[0][0]), "first nullifier spent");
        assertTrue(pool.nullifierSpent(args.nullifiers[1][0]), "second nullifier spent");
    }

    function _assertGatewayPending(GatewayReceipt memory receipt, uint96 amount, uint32 nonce) internal view {
        uint256 commitment =
            Poseidon2T4.hash4(DOMAIN_NOTE, receipt.npk, uint256(receipt.outputTokenId), uint256(amount));
        uint256 commitmentsHash = LibDigest.computeCommitmentsHashStep(0, commitment);
        uint256 depositRequestId = LibDigest.computeDepositRequestId(
            block.chainid,
            address(pool),
            address(externalGateway),
            receipt.outputTokenId,
            amount,
            nonce,
            commitmentsHash
        );
        (
            address depositor,
            uint16 tokenId,
            uint96 totalAmount,
            uint64 requestBlock,
            uint32 storedNonce,
            uint16 commitmentCount,
            uint256 storedCommitmentsHash,
            bytes32 rescueCommitment
        ) = pool.pendingDeposits(depositRequestId);

        assertEq(depositor, address(externalGateway));
        assertEq(tokenId, receipt.outputTokenId);
        assertEq(totalAmount, amount);
        assertEq(requestBlock, block.number);
        assertEq(storedNonce, nonce);
        assertEq(commitmentCount, 1);
        assertEq(storedCommitmentsHash, commitmentsHash);
        assertEq(rescueCommitment, receipt.rescueCommitment);
    }
}
