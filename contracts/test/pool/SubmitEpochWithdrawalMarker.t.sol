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

import {Test} from "forge-std/Test.sol";

import {PrivacyBoost} from "src/PrivacyBoost.sol";
import {IPrivacyBoost} from "src/interfaces/IPrivacyBoost.sol";
import {TokenRegistry} from "src/TokenRegistry.sol";
import {Poseidon2T4} from "src/hash/Poseidon2T4.sol";
import {Output, Transfer, Withdrawal, TreeRootPair, GatewaySlot} from "src/interfaces/IStructs.sol";
import {TOKEN_TYPE_ERC20, DOMAIN_NOTE, WITHDRAWAL_MASK_BITS_PER_WORD} from "src/interfaces/Constants.sol";

import {MockERC20, MockAuthRegistry} from "test/helpers/Mocks.sol";
import {PoolDeployer, DeployConfig} from "test/helpers/PoolDeployer.sol";
import {EpochHelpers, SubmitArgs} from "test/helpers/EpochHelpers.sol";

/// @notice Checks the trailing withdrawal-mask word of the public-input vector the pool builds.
///
/// The verifier interface is `view`, so a recording mock cannot write what it saw. Asserting inside
/// the call instead keeps the check on the real vector: a submission that reaches the end proves the
/// mask matched, and the mismatch test below proves the check is live rather than vacuous.
contract MaskAssertingVerifier {
    uint256 public expectedMask;

    error MaskMismatch(uint256 actual, uint256 expected);

    function setExpectedMask(uint256 mask) external {
        expectedMask = mask;
    }

    function verifyEpoch(uint32, uint32, uint32, uint256[8] calldata, uint256[] calldata publicInputs)
        external
        view
        returns (bool)
    {
        uint256 actual = publicInputs[publicInputs.length - 1];
        if (actual != expectedMask) revert MaskMismatch(actual, expectedMask);
        return true;
    }

    function hasVerifyingKey(uint32) external pure returns (bool) {
        return true;
    }
}

/// @notice Withdrawal markers are paid out publicly and must never enter the note tree. These tests
///         cover the two contract-side consequences: the leaf count drops by one per withdrawal,
///         and the circuit learns which slots are withdrawals through a public mask.
contract SubmitEpochWithdrawalMarkerTest is Test {
    PrivacyBoost pool;
    TokenRegistry tokenRegistry;
    MockAuthRegistry authRegistry;
    MaskAssertingVerifier verifier;
    MockERC20 token;

    address owner = address(this);
    address proxyAdmin = address(0xAD);
    address relayer = makeAddr("relayer");
    address operator = makeAddr("operator");
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    uint16 tokenId;

    uint32 constant BATCH_SIZE = 2;
    uint32 constant MAX_OUTPUTS = 2;
    uint32 constant MAX_FEE_TOKENS = 1;
    uint96 constant WITHDRAW_AMOUNT = 100 ether;

    function setUp() public {
        verifier = new MaskAssertingVerifier();
        authRegistry = new MockAuthRegistry();

        DeployConfig memory cfg = PoolDeployer.defaultConfig(owner, proxyAdmin, address(verifier));
        cfg.batchSize = BATCH_SIZE;
        cfg.maxOutputsPerTransfer = MAX_OUTPUTS;
        cfg.maxFeeTokens = MAX_FEE_TOKENS;
        (pool, tokenRegistry) = PoolDeployer.deployWithMockAuth(cfg, address(authRegistry));

        token = new MockERC20();
        tokenId = tokenRegistry.register(TOKEN_TYPE_ERC20, address(token), 0);
        token.mint(address(pool), 10_000 ether);

        pool.setOperator(operator);
        address[] memory relayers = new address[](1);
        relayers[0] = relayer;
        vm.prank(operator);
        pool.setAllowedRelays(relayers, true);
    }

    // ─────────────── Fixture builders ───────────────

    function _marker(address to) internal view returns (uint256) {
        return Poseidon2T4.hash4(DOMAIN_NOTE, uint256(uint160(to)), uint256(tokenId), uint256(WITHDRAW_AMOUNT));
    }

    /// @dev Builds a two-slot batch. `withdrawTo[t]` non-zero makes slot t a withdrawal whose output
    ///      zero is that recipient's marker; `outputCounts[t]` decides whether a change note follows.
    function _args(address[2] memory withdrawTo, uint32[2] memory outputCounts, uint32 countNew)
        internal
        view
        returns (SubmitArgs memory a)
    {
        uint256 rootOld = pool.treeRoot(pool.currentTreeNumber());
        uint32 countOld = pool.treeCount(pool.currentTreeNumber());

        Transfer[] memory transfers = new Transfer[](BATCH_SIZE);
        uint256[][] memory nullifiers = new uint256[][](BATCH_SIZE);
        uint256 withdrawalCount = 0;
        for (uint256 t = 0; t < BATCH_SIZE; ++t) {
            Output[] memory outputs = new Output[](MAX_OUTPUTS);
            for (uint256 j = 0; j < MAX_OUTPUTS; ++j) {
                // Zero-pad every slot past this transfer's declared output count.
                outputs[j] = EpochHelpers.makeOutput(j < outputCounts[t] ? 0x9000 + t * 16 + j : 0);
            }
            if (withdrawTo[t] != address(0)) {
                outputs[0] = EpochHelpers.makeOutput(_marker(withdrawTo[t]));
                ++withdrawalCount;
            }
            transfers[t] = Transfer({viewingKey: bytes32(0), teeWrapKey: bytes32(0), outputs: outputs});

            nullifiers[t] = new uint256[](1);
            nullifiers[t][0] = 0x1000 + t;
        }

        Withdrawal[] memory withdrawals = new Withdrawal[](withdrawalCount);
        uint32[] memory withdrawalSlots = new uint32[](withdrawalCount);
        uint256 cursor = 0;
        for (uint32 t = 0; t < BATCH_SIZE; ++t) {
            if (withdrawTo[t] == address(0)) continue;
            withdrawals[cursor] = Withdrawal({to: withdrawTo[t], tokenId: tokenId, amount: WITHDRAW_AMOUNT});
            withdrawalSlots[cursor] = t;
            ++cursor;
        }

        Output[] memory feeOutputs = new Output[](MAX_FEE_TOKENS);
        feeOutputs[0] = EpochHelpers.makeOutput(0x7777);

        a.treeState =
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, rootOld), 0, countOld, 0x1234, countNew, false);
        a.usedAuthRoots = EpochHelpers.buildAuthRoots(0, 1);
        a.nTransfers = BATCH_SIZE;
        a.feeTokenCount = MAX_FEE_TOKENS;
        a.feeNPK = 1;
        a.inputsPerTransfer = new uint32[](BATCH_SIZE);
        a.outputsPerTransfer = new uint32[](BATCH_SIZE);
        for (uint256 t = 0; t < BATCH_SIZE; ++t) {
            a.inputsPerTransfer[t] = 1;
            a.outputsPerTransfer[t] = outputCounts[t];
        }
        a.nullifiers = nullifiers;
        a.transfers = transfers;
        a.feeTransfer = EpochHelpers.buildFeeTransfer(feeOutputs);
        a.withdrawals = withdrawals;
        a.withdrawalSlots = withdrawalSlots;
        a.provingTimestamp = uint64(block.timestamp);
        a.proof = EpochHelpers.dummyProof();
        a.gatewaySlots = new GatewaySlot[](0);
    }

    function _countOld() internal view returns (uint32) {
        return pool.treeCount(pool.currentTreeNumber());
    }

    // ─────────────── Leaf accounting ───────────────

    /// @notice One exact withdrawal beside one ordinary transfer: three output commitments and one
    ///         fee note, but only two new leaves because the marker is not one.
    function test_submitEpoch_exactWithdrawalDeductsOneLeaf() public {
        uint32 countOld = _countOld();
        verifier.setExpectedMask(1 << 0);
        SubmitArgs memory a = _args([bob, address(0)], [uint32(1), uint32(1)], countOld + 2);

        vm.prank(relayer);
        EpochHelpers.doSubmitEpoch(pool, a);

        assertEq(pool.treeCount(0), countOld + 2, "tree must grow by transfer output plus fee note");
        assertEq(token.balanceOf(bob), WITHDRAW_AMOUNT, "recipient must still be paid");
    }

    /// @notice The same batch counted the old way must be rejected, so the deduction is enforced
    ///         rather than merely produced by a cooperative submitter.
    function test_submitEpoch_markerCountedAsLeaf_reverts() public {
        uint32 countOld = _countOld();
        verifier.setExpectedMask(1 << 0);
        SubmitArgs memory a = _args([bob, address(0)], [uint32(1), uint32(1)], countOld + 3);

        vm.prank(relayer);
        vm.expectRevert(IPrivacyBoost.InvalidEpochState.selector);
        EpochHelpers.doSubmitEpoch(pool, a);
    }

    /// @notice A withdrawal with change contributes its change note but still not its marker.
    function test_submitEpoch_withdrawalWithChangeAppendsChangeOnly() public {
        uint32 countOld = _countOld();
        verifier.setExpectedMask(1 << 0);
        SubmitArgs memory a = _args([bob, address(0)], [uint32(2), uint32(1)], countOld + 3);

        vm.prank(relayer);
        EpochHelpers.doSubmitEpoch(pool, a);

        assertEq(pool.treeCount(0), countOld + 3, "change note, ordinary output, and fee note");
    }

    /// @notice Every slot paying out publicly deducts its own marker.
    function test_submitEpoch_twoWithdrawalsDeductBothMarkers() public {
        uint32 countOld = _countOld();
        verifier.setExpectedMask((1 << 0) | (1 << 1));
        SubmitArgs memory a = _args([alice, bob], [uint32(1), uint32(1)], countOld + 1);

        vm.prank(relayer);
        EpochHelpers.doSubmitEpoch(pool, a);

        assertEq(pool.treeCount(0), countOld + 1, "only the fee note remains a leaf");
        assertEq(token.balanceOf(alice), WITHDRAW_AMOUNT, "first recipient must be paid");
        assertEq(token.balanceOf(bob), WITHDRAW_AMOUNT, "second recipient must be paid");
    }

    // ─────────────── Mask packing ───────────────

    /// @notice The mask word trails the public-input vector and carries one bit per withdrawal slot.
    ///         Without it the circuit would have no authenticated way to know which output zero to
    ///         skip, and a wrong bit order would go undetected.
    function test_submitEpoch_maskWordCarriesWithdrawalSlots() public {
        uint32 countOld = _countOld();
        // Slot one is the withdrawal, so bit one and nothing else.
        verifier.setExpectedMask(1 << 1);
        SubmitArgs memory a = _args([address(0), bob], [uint32(1), uint32(1)], countOld + 2);

        vm.prank(relayer);
        EpochHelpers.doSubmitEpoch(pool, a);
    }

    function test_submitEpoch_maskWordIsZeroWithoutWithdrawals() public {
        uint32 countOld = _countOld();
        verifier.setExpectedMask(0);
        SubmitArgs memory a = _args([address(0), address(0)], [uint32(1), uint32(1)], countOld + 3);

        vm.prank(relayer);
        EpochHelpers.doSubmitEpoch(pool, a);
    }

    /// @notice Proves the assertion above is live: the same batch fails when the verifier expects a
    ///         different mask, so a passing run really did compare the packed word.
    function test_submitEpoch_maskAssertionIsNotVacuous() public {
        uint32 countOld = _countOld();
        verifier.setExpectedMask(1 << 0);
        SubmitArgs memory a = _args([address(0), bob], [uint32(1), uint32(1)], countOld + 2);

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(MaskAssertingVerifier.MaskMismatch.selector, 1 << 1, 1 << 0));
        EpochHelpers.doSubmitEpoch(pool, a);
    }

    /// @notice The batch capacity here needs one mask word, and the packing width is what decides
    ///         that. Pinning it keeps the contract's word count and the circuit's declaration from
    ///         drifting apart silently.
    function test_maskWordCountMatchesBatchCapacity() public pure {
        assertEq((BATCH_SIZE + WITHDRAWAL_MASK_BITS_PER_WORD - 1) / WITHDRAWAL_MASK_BITS_PER_WORD, 1);
    }
}
