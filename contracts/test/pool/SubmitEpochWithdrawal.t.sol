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

import {AuthRegistry} from "src/AuthRegistry.sol";
import {PrivacyBoost} from "src/PrivacyBoost.sol";
import {IPrivacyBoost} from "src/interfaces/IPrivacyBoost.sol";
import {TokenRegistry} from "src/TokenRegistry.sol";
import {Poseidon2T4} from "src/hash/Poseidon2T4.sol";
import {Output, Transfer, Withdrawal, TreeRootPair, GatewaySlot} from "src/interfaces/IStructs.sol";
import {TOKEN_TYPE_ERC20, DOMAIN_NOTE, MAX_PROOF_AGE} from "src/interfaces/Constants.sol";

import {MockERC20, MockVerifier, MockAuthRegistry, MockRecentAuthRegistry} from "test/helpers/Mocks.sol";
import {PoolDeployer, DeployConfig} from "test/helpers/PoolDeployer.sol";
import {EpochHelpers, SubmitArgs} from "test/helpers/EpochHelpers.sol";

/// @notice Tests for submitEpoch with Withdrawal[] (V1-style withdrawal via EpochCircuit)
contract SubmitEpochWithdrawalTest is Test {
    PrivacyBoost pool;
    TokenRegistry tokenRegistry;
    MockAuthRegistry authRegistry;
    MockVerifier verifier;
    MockERC20 token;

    address owner = address(this);
    address proxyAdmin = address(0xAD); // Separate proxy admin to avoid TransparentProxy routing issue
    address relayer = makeAddr("relayer");
    address bob = makeAddr("bob");
    address operator = makeAddr("operator");

    uint16 tokenId;
    uint8 constant BATCH_SIZE = 2;
    uint8 constant MAX_FEE_TOKENS = 1;

    function setUp() public {
        verifier = new MockVerifier();
        authRegistry = new MockAuthRegistry();

        DeployConfig memory cfg = PoolDeployer.defaultConfig(owner, proxyAdmin, address(verifier));
        cfg.batchSize = BATCH_SIZE;
        cfg.maxFeeTokens = MAX_FEE_TOKENS;

        (pool, tokenRegistry) = PoolDeployer.deployWithMockAuth(cfg, address(authRegistry));

        token = new MockERC20();
        tokenId = tokenRegistry.register(TOKEN_TYPE_ERC20, address(token), 0);

        // Fund the pool (simulating prior deposits)
        token.mint(address(pool), 10000 ether);

        // Set operator
        pool.setOperator(operator);

        // Set relayer as allowed
        address[] memory relayers = new address[](1);
        relayers[0] = relayer;
        vm.prank(operator);
        pool.setAllowedRelays(relayers, true);
    }

    function _wrapUint32Array(uint32 val, uint32 count) internal pure returns (uint32[] memory arr) {
        arr = new uint32[](count);
        for (uint32 i = 0; i < count; i++) {
            arr[i] = val;
        }
    }

    function _wrap2DNullifiers(uint256[] memory nullifiers, uint32 nTransfers)
        internal
        pure
        returns (uint256[][] memory result)
    {
        result = new uint256[][](nTransfers);
        uint256 perTransfer = nullifiers.length / nTransfers;
        for (uint32 i = 0; i < nTransfers; i++) {
            result[i] = new uint256[](perTransfer);
            for (uint256 j = 0; j < perTransfer; j++) {
                result[i][j] = nullifiers[i * perTransfer + j];
            }
        }
    }

    function _buildTransfersN(Output[] memory outputs, uint32 nTransfers)
        internal
        pure
        returns (Transfer[] memory result)
    {
        result = new Transfer[](nTransfers);
        uint256 perTransfer = outputs.length / nTransfers;
        for (uint32 i = 0; i < nTransfers; i++) {
            Output[] memory transferOutputs = new Output[](perTransfer);
            for (uint256 j = 0; j < perTransfer; j++) {
                transferOutputs[j] = outputs[i * perTransfer + j];
            }
            result[i] = Transfer({viewingKey: bytes32(0), teeWrapKey: bytes32(0), outputs: transferOutputs});
        }
    }

    function _deployPoolWithRecentAuth(uint64 maxStalenessBlocks)
        internal
        returns (PrivacyBoost recentPool, TokenRegistry recentTokenRegistry, MockRecentAuthRegistry recentAuth)
    {
        recentAuth = new MockRecentAuthRegistry();
        DeployConfig memory cfg = PoolDeployer.defaultConfig(owner, proxyAdmin, address(verifier));
        cfg.batchSize = BATCH_SIZE;
        cfg.maxFeeTokens = MAX_FEE_TOKENS;
        cfg.maxEpochAuthStalenessBlocks = maxStalenessBlocks;
        cfg.maxForcedWithdrawalAuthStalenessBlocks = maxStalenessBlocks;
        (recentPool, recentTokenRegistry) = PoolDeployer.deployWithMockAuth(cfg, address(recentAuth));
        recentPool.setOperator(operator);
        address[] memory relayers = new address[](1);
        relayers[0] = relayer;
        vm.prank(operator);
        recentPool.setAllowedRelays(relayers, true);
    }

    function _submitBasicEpochWithAuthRoot(
        PrivacyBoost targetPool,
        uint256 authRoot,
        uint256 nullifierSeed,
        bool expectRootNotKnown
    ) internal {
        uint256 rootOld = targetPool.treeRoot(targetPool.currentTreeNumber());
        uint32 countOld = targetPool.treeCount(targetPool.currentTreeNumber());
        TreeRootPair[] memory usedRoots = EpochHelpers.buildUsedRoots(0, rootOld);

        uint256[] memory nullifiers = new uint256[](BATCH_SIZE);
        Output[] memory outputs = new Output[](BATCH_SIZE);
        for (uint256 i = 0; i < BATCH_SIZE; ++i) {
            nullifiers[i] = nullifierSeed + i;
            outputs[i] = EpochHelpers.makeOutput(nullifierSeed + 100 + i);
        }

        Output[] memory feeOutputs = new Output[](MAX_FEE_TOKENS);
        feeOutputs[0] = EpochHelpers.makeOutput(nullifierSeed + 200);

        SubmitArgs memory a;
        a.treeState = EpochHelpers.buildTreeState(usedRoots, 0, countOld, 1, countOld + 3, false);
        a.usedAuthRoots = EpochHelpers.buildAuthRoots(0, authRoot);
        a.nTransfers = 2;
        a.feeTokenCount = 1;
        a.feeNPK = 1;
        a.inputsPerTransfer = _wrapUint32Array(1, 2);
        a.outputsPerTransfer = _wrapUint32Array(1, 2);
        a.nullifiers = _wrap2DNullifiers(nullifiers, 2);
        a.transfers = _buildTransfersN(outputs, 2);
        a.feeTransfer = EpochHelpers.buildFeeTransfer(feeOutputs);
        a.withdrawals = new Withdrawal[](0);
        a.withdrawalSlots = new uint32[](0);
        a.provingTimestamp = uint64(block.timestamp);
        a.proof = EpochHelpers.dummyProof();
        a.gatewaySlots = new GatewaySlot[](0);

        vm.prank(relayer);
        if (expectRootNotKnown) vm.expectRevert(IPrivacyBoost.RootNotKnown.selector);
        EpochHelpers.doSubmitEpoch(targetPool, a);
    }

    function test_submitEpoch_accepts_recent_auth_root_within_configured_window() public {
        // Arrange
        (PrivacyBoost recentPool,, MockRecentAuthRegistry recentAuth) = _deployPoolWithRecentAuth(4);
        uint256 oldAuthRoot = 11;
        recentAuth.setCurrentRoot(22);
        recentAuth.setRecentRoot(oldAuthRoot, uint64(block.number));

        // Act
        _submitBasicEpochWithAuthRoot(recentPool, oldAuthRoot, 1000, false);

        // Assert
        assertEq(recentPool.maxEpochAuthStalenessBlocks(), 4);
        assertEq(recentPool.treeCount(0), 3, "epoch should be accepted with recent auth root");
    }

    function test_submitEpoch_reverts_when_recent_auth_root_exceeds_configured_window() public {
        // Arrange
        (PrivacyBoost recentPool,, MockRecentAuthRegistry recentAuth) = _deployPoolWithRecentAuth(4);
        uint256 oldAuthRoot = 11;
        recentAuth.setCurrentRoot(22);
        recentAuth.setRecentRoot(oldAuthRoot, uint64(block.number));
        vm.roll(block.number + 5);

        // Act / Assert
        _submitBasicEpochWithAuthRoot(recentPool, oldAuthRoot, 2000, true);
    }

    function test_submitEpoch_reverts_for_revoked_approval_after_auth_root_window() public {
        DeployConfig memory cfg = PoolDeployer.defaultConfig(owner, proxyAdmin, address(verifier));
        cfg.batchSize = BATCH_SIZE;
        cfg.maxFeeTokens = MAX_FEE_TOKENS;
        cfg.maxEpochAuthStalenessBlocks = 4;
        (PrivacyBoost approvalPool,, AuthRegistry realAuth) = PoolDeployer.deployFullStack(cfg);
        approvalPool.setOperator(operator);
        address[] memory relayers = new address[](1);
        relayers[0] = relayer;
        vm.prank(operator);
        approvalPool.setAllowedRelays(relayers, true);

        address safe = makeAddr("safe");
        vm.prank(safe);
        uint256 accountId = realAuth.createAccount(123);
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = 12345;
        vm.prank(safe);
        realAuth.approveSpendBatch(accountId, uint64(block.timestamp + 1 days), commitments);

        uint256 approvedRoot = realAuth.authTreeRoot(0);
        uint256 batchRoot = realAuth.computeSpendApprovalBatchRoot(commitments);
        vm.prank(safe);
        realAuth.revokeSpendApprovalBatch(accountId, batchRoot);

        assertTrue(realAuth.isRecentAuthTreeRoot(0, approvedRoot, 4));
        vm.roll(block.number + 5);
        assertFalse(realAuth.isRecentAuthTreeRoot(0, approvedRoot, 4));

        _submitBasicEpochWithAuthRoot(approvalPool, approvedRoot, 3000, true);
    }

    function _toSingleArrays(uint256 nullifier, uint256 commitment)
        internal
        pure
        returns (uint256[] memory nullifiers, uint256[] memory commitments)
    {
        nullifiers = new uint256[](1);
        nullifiers[0] = nullifier;
        commitments = new uint256[](1);
        commitments[0] = commitment;
    }

    /// @notice Test submitEpoch with a single withdrawal (happy path)
    function test_submitEpoch_singleWithdrawal_success() public {
        uint256 withdrawAmount = 100 ether;

        // Compute withdrawal commitment: Poseidon(DOMAIN_NOTE, withdrawalAddress, tokenId, amount)
        uint256 withdrawCommitment =
            Poseidon2T4.hash4(DOMAIN_NOTE, uint256(uint160(bob)), uint256(tokenId), withdrawAmount);

        // Build outputs (slot 0 = withdrawal, slot 1 = dummy transfer)
        Output[] memory outputs = new Output[](BATCH_SIZE);
        outputs[0] = EpochHelpers.makeOutput(withdrawCommitment);
        outputs[1] = EpochHelpers.makeOutput(12345); // dummy

        // Build nullifiers
        uint256[] memory nullifiers = new uint256[](BATCH_SIZE);
        nullifiers[0] = 111;
        nullifiers[1] = 222;

        // Build fee outputs
        Output[] memory feeOutputs = new Output[](MAX_FEE_TOKENS);
        feeOutputs[0] = EpochHelpers.makeOutput(999);

        // Build withdrawals array (slot 0 is a withdrawal)
        Withdrawal[] memory withdrawals = new Withdrawal[](1);
        withdrawals[0] = Withdrawal({to: bob, tokenId: tokenId, amount: uint96(withdrawAmount)});
        uint32[] memory withdrawalSlots = new uint32[](1);
        withdrawalSlots[0] = 0; // transfer slot index

        uint256 bobBalBefore = token.balanceOf(bob);
        uint256 poolBalBefore = token.balanceOf(address(pool));

        // Get current pool state
        uint256 rootOld = pool.treeRoot(pool.currentTreeNumber());
        uint32 countOld = pool.treeCount(pool.currentTreeNumber());
        TreeRootPair[] memory usedRoots = EpochHelpers.buildUsedRoots(0, rootOld);

        // Submit epoch with withdrawal. Two transfer outputs plus one fee note would be three new
        // leaves, but the withdrawal's marker is not appended, so the tree grows by two.
        vm.prank(relayer);
        pool.submitEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 1, countOld + 2, false),
            EpochHelpers.buildAuthRoots(0, 1),
            2, // nTransfers (BATCH_SIZE)
            1, // feeTokenCount
            1, // feeNPK
            _wrapUint32Array(1, 2), // inputsPerTransfer
            _wrapUint32Array(1, 2), // outputsPerTransfer
            _wrap2DNullifiers(nullifiers, 2),
            _buildTransfersN(outputs, 2),
            EpochHelpers.buildFeeTransfer(feeOutputs),
            withdrawals,
            withdrawalSlots,
            uint64(block.timestamp),
            EpochHelpers.dummyProof(),
            new GatewaySlot[](0)
        );

        // Verify bob received the withdrawal
        assertEq(token.balanceOf(bob), bobBalBefore + withdrawAmount, "Bob should receive withdrawal");
        assertEq(token.balanceOf(address(pool)), poolBalBefore - withdrawAmount, "Pool balance should decrease");
    }

    /// @notice Test that invalid withdrawal commitment reverts
    function test_submitEpoch_invalidWithdrawalCommitment_reverts() public {
        uint256 withdrawAmount = 100 ether;

        // Wrong commitment (doesn't match withdrawal params)
        uint256 wrongCommitment = 99999;

        Output[] memory outputs = new Output[](BATCH_SIZE);
        outputs[0] = EpochHelpers.makeOutput(wrongCommitment); // WRONG
        outputs[1] = EpochHelpers.makeOutput(12345);

        uint256[] memory nullifiers = new uint256[](BATCH_SIZE);
        nullifiers[0] = 111;
        nullifiers[1] = 222;

        Output[] memory feeOutputs = new Output[](MAX_FEE_TOKENS);
        feeOutputs[0] = EpochHelpers.makeOutput(999);

        Withdrawal[] memory withdrawals = new Withdrawal[](1);
        withdrawals[0] = Withdrawal({to: bob, tokenId: tokenId, amount: uint96(withdrawAmount)});
        uint32[] memory withdrawalSlots = new uint32[](1);
        withdrawalSlots[0] = 0;

        uint256 rootOld = pool.treeRoot(pool.currentTreeNumber());
        uint32 countOld = pool.treeCount(pool.currentTreeNumber());
        TreeRootPair[] memory usedRoots = EpochHelpers.buildUsedRoots(0, rootOld);

        vm.prank(relayer);
        vm.expectRevert(IPrivacyBoost.InvalidWithdrawal.selector);
        pool.submitEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 1, countOld + 2, false),
            EpochHelpers.buildAuthRoots(0, 1),
            2,
            1,
            1,
            _wrapUint32Array(1, 2),
            _wrapUint32Array(1, 2),
            _wrap2DNullifiers(nullifiers, 2),
            _buildTransfersN(outputs, 2),
            EpochHelpers.buildFeeTransfer(feeOutputs),
            withdrawals,
            withdrawalSlots,
            uint64(block.timestamp),
            EpochHelpers.dummyProof(),
            new GatewaySlot[](0)
        );
    }

    /// @notice Test that zero-amount withdrawal reverts
    function test_submitEpoch_zeroAmountWithdrawal_reverts() public {
        uint256 withdrawCommitment = Poseidon2T4.hash4(
            DOMAIN_NOTE,
            uint256(uint160(bob)),
            uint256(tokenId),
            0 // zero amount
        );

        Output[] memory outputs = new Output[](BATCH_SIZE);
        outputs[0] = EpochHelpers.makeOutput(withdrawCommitment);
        outputs[1] = EpochHelpers.makeOutput(12345);

        uint256[] memory nullifiers = new uint256[](BATCH_SIZE);
        nullifiers[0] = 111;
        nullifiers[1] = 222;

        Output[] memory feeOutputs = new Output[](MAX_FEE_TOKENS);
        feeOutputs[0] = EpochHelpers.makeOutput(999);

        Withdrawal[] memory withdrawals = new Withdrawal[](1);
        withdrawals[0] = Withdrawal({
            to: bob,
            tokenId: tokenId,
            amount: 0 // zero
        });
        uint32[] memory withdrawalSlots = new uint32[](1);
        withdrawalSlots[0] = 0;

        uint256 rootOld = pool.treeRoot(pool.currentTreeNumber());
        uint32 countOld = pool.treeCount(pool.currentTreeNumber());
        TreeRootPair[] memory usedRoots = EpochHelpers.buildUsedRoots(0, rootOld);

        vm.prank(relayer);
        vm.expectRevert(IPrivacyBoost.InvalidWithdrawal.selector);
        pool.submitEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 1, countOld + 2, false),
            EpochHelpers.buildAuthRoots(0, 1),
            2,
            1,
            1,
            _wrapUint32Array(1, 2),
            _wrapUint32Array(1, 2),
            _wrap2DNullifiers(nullifiers, 2),
            _buildTransfersN(outputs, 2),
            EpochHelpers.buildFeeTransfer(feeOutputs),
            withdrawals,
            withdrawalSlots,
            uint64(block.timestamp),
            EpochHelpers.dummyProof(),
            new GatewaySlot[](0)
        );
    }

    /// @notice Test that withdrawal with slot >= nTransfers reverts
    function test_submitEpoch_withdrawalOutOfRange_reverts() public {
        uint256 withdrawAmount = 100 ether;

        // With nTransfers=1, we only have 1 transfer slot (index 0)
        // Create arrays with proper length for nTransfers=1
        Output[] memory outputs = new Output[](1);
        outputs[0] = EpochHelpers.makeOutput(12345); // slot 0: regular transfer

        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = 111;

        Output[] memory feeOutputs = new Output[](MAX_FEE_TOKENS);
        feeOutputs[0] = EpochHelpers.makeOutput(999);

        // Withdrawal references slot 1, but nTransfers=1 means only slot 0 is active
        Withdrawal[] memory withdrawals = new Withdrawal[](1);
        withdrawals[0] = Withdrawal({to: bob, tokenId: tokenId, amount: uint96(withdrawAmount)});
        uint32[] memory withdrawalSlots = new uint32[](1);
        withdrawalSlots[0] = 1; // slot 1, but nTransfers=1 means only slot 0 is active

        uint256 rootOld = pool.treeRoot(pool.currentTreeNumber());
        uint32 countOld = pool.treeCount(pool.currentTreeNumber());
        TreeRootPair[] memory usedRoots = EpochHelpers.buildUsedRoots(0, rootOld);

        vm.prank(relayer);
        vm.expectRevert(IPrivacyBoost.InvalidWithdrawal.selector);
        pool.submitEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 1, countOld + 2, false),
            EpochHelpers.buildAuthRoots(0, 1),
            1, // nTransfers = 1 (only slot 0 is active)
            1,
            1,
            EpochHelpers.singletonUint32Array(1),
            EpochHelpers.singletonUint32Array(1),
            EpochHelpers.wrap2D(nullifiers),
            EpochHelpers.buildTransfers(outputs),
            EpochHelpers.buildFeeTransfer(feeOutputs),
            withdrawals,
            withdrawalSlots,
            uint64(block.timestamp),
            EpochHelpers.dummyProof(),
            new GatewaySlot[](0)
        );
    }

    /// @notice Test that unsorted withdrawalSlots revert with a dedicated reason
    function test_submitEpoch_withdrawalSlotsNotSorted_reverts() public {
        uint256 rootOld = pool.treeRoot(pool.currentTreeNumber());
        uint32 countOld = pool.treeCount(pool.currentTreeNumber());
        TreeRootPair[] memory usedRoots = EpochHelpers.buildUsedRoots(0, rootOld);

        uint256[] memory nullifiers = new uint256[](BATCH_SIZE);
        nullifiers[0] = 111;
        nullifiers[1] = 222;

        Output[] memory outputs = new Output[](BATCH_SIZE);
        outputs[0] = EpochHelpers.makeOutput(12345);
        outputs[1] = EpochHelpers.makeOutput(12346);

        Output[] memory feeOutputs = new Output[](MAX_FEE_TOKENS);
        feeOutputs[0] = EpochHelpers.makeOutput(999);

        Withdrawal[] memory withdrawals = new Withdrawal[](2);
        withdrawals[0] = Withdrawal({to: bob, tokenId: tokenId, amount: 1});
        withdrawals[1] = Withdrawal({to: bob, tokenId: tokenId, amount: 2});

        // Not strictly increasing: [1, 0]
        uint32[] memory withdrawalSlots = new uint32[](2);
        withdrawalSlots[0] = 1;
        withdrawalSlots[1] = 0;

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(IPrivacyBoost.WithdrawalSlotsNotStrictAscending.selector, 1, uint32(1), uint32(0))
        );
        pool.submitEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 1, countOld + 3, false),
            EpochHelpers.buildAuthRoots(0, 1),
            2,
            1,
            1,
            _wrapUint32Array(1, 2),
            _wrapUint32Array(1, 2),
            _wrap2DNullifiers(nullifiers, 2),
            _buildTransfersN(outputs, 2),
            EpochHelpers.buildFeeTransfer(feeOutputs),
            withdrawals,
            withdrawalSlots,
            uint64(block.timestamp),
            EpochHelpers.dummyProof(),
            new GatewaySlot[](0)
        );
    }

    /// @notice Test that duplicate withdrawalSlots revert with a dedicated reason
    function test_submitEpoch_withdrawalSlotsDuplicate_reverts() public {
        uint256 rootOld = pool.treeRoot(pool.currentTreeNumber());
        uint32 countOld = pool.treeCount(pool.currentTreeNumber());
        TreeRootPair[] memory usedRoots = EpochHelpers.buildUsedRoots(0, rootOld);

        uint256[] memory nullifiers = new uint256[](BATCH_SIZE);
        nullifiers[0] = 111;
        nullifiers[1] = 222;

        Output[] memory outputs = new Output[](BATCH_SIZE);
        outputs[0] = EpochHelpers.makeOutput(12345);
        outputs[1] = EpochHelpers.makeOutput(12346);

        Output[] memory feeOutputs = new Output[](MAX_FEE_TOKENS);
        feeOutputs[0] = EpochHelpers.makeOutput(999);

        Withdrawal[] memory withdrawals = new Withdrawal[](2);
        withdrawals[0] = Withdrawal({to: bob, tokenId: tokenId, amount: 1});
        withdrawals[1] = Withdrawal({to: bob, tokenId: tokenId, amount: 2});

        // Not strictly increasing: [0, 0]
        uint32[] memory withdrawalSlots = new uint32[](2);
        withdrawalSlots[0] = 0;
        withdrawalSlots[1] = 0;

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(IPrivacyBoost.WithdrawalSlotsNotStrictAscending.selector, 1, uint32(0), uint32(0))
        );
        pool.submitEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 1, countOld + 3, false),
            EpochHelpers.buildAuthRoots(0, 1),
            2,
            1,
            1,
            _wrapUint32Array(1, 2),
            _wrapUint32Array(1, 2),
            _wrap2DNullifiers(nullifiers, 2),
            _buildTransfersN(outputs, 2),
            EpochHelpers.buildFeeTransfer(feeOutputs),
            withdrawals,
            withdrawalSlots,
            uint64(block.timestamp),
            EpochHelpers.dummyProof(),
            new GatewaySlot[](0)
        );
    }

    // ========== Coverage Tests: Array Length Validation (Lines 243-244) ==========

    /// @notice Test InvalidArrayLengths when outputs.length != batchSize (Lines 243-244)
    function test_revertWhen_outputsLengthMismatch() public {
        uint256 rootOld = pool.treeRoot(pool.currentTreeNumber());
        uint32 countOld = pool.treeCount(pool.currentTreeNumber());
        TreeRootPair[] memory usedRoots = EpochHelpers.buildUsedRoots(0, rootOld);

        // BATCH_SIZE is 2, but we provide only 1 output (mismatch)
        uint256[] memory nullifiers = new uint256[](BATCH_SIZE);
        nullifiers[0] = 111;
        nullifiers[1] = 222;

        Output[] memory outputs = new Output[](1); // Wrong length! Should be BATCH_SIZE
        outputs[0] = EpochHelpers.makeOutput(12345);

        Output[] memory feeOutputs = new Output[](MAX_FEE_TOKENS);
        feeOutputs[0] = EpochHelpers.makeOutput(999);

        vm.prank(relayer);
        vm.expectRevert(IPrivacyBoost.InvalidEpochConfig.selector);
        pool.submitEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 1, countOld + 3, false),
            EpochHelpers.buildAuthRoots(0, 1),
            2,
            1,
            1,
            _wrapUint32Array(1, 2),
            _wrapUint32Array(1, 2),
            _wrap2DNullifiers(nullifiers, 2),
            _buildTransfersN(outputs, 2),
            EpochHelpers.buildFeeTransfer(feeOutputs),
            new Withdrawal[](0),
            new uint32[](0),
            uint64(block.timestamp),
            EpochHelpers.dummyProof(),
            new GatewaySlot[](0)
        );
    }

    /// @notice Test InvalidArrayLengths when feeOutputs.length != maxFeeTokens (Lines 243-244)
    function test_revertWhen_feeOutputsLengthMismatch() public {
        uint256 rootOld = pool.treeRoot(pool.currentTreeNumber());
        uint32 countOld = pool.treeCount(pool.currentTreeNumber());
        TreeRootPair[] memory usedRoots = EpochHelpers.buildUsedRoots(0, rootOld);

        uint256[] memory nullifiers = new uint256[](BATCH_SIZE);
        nullifiers[0] = 111;
        nullifiers[1] = 222;

        Output[] memory outputs = new Output[](BATCH_SIZE);
        outputs[0] = EpochHelpers.makeOutput(12345);
        outputs[1] = EpochHelpers.makeOutput(12346);

        // MAX_FEE_TOKENS is 1, but we provide 2 (mismatch)
        Output[] memory feeOutputs = new Output[](2); // Wrong length!
        feeOutputs[0] = EpochHelpers.makeOutput(999);
        feeOutputs[1] = EpochHelpers.makeOutput(998);

        vm.prank(relayer);
        vm.expectRevert(IPrivacyBoost.InvalidArrayLengths.selector);
        pool.submitEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 1, countOld + 3, false),
            EpochHelpers.buildAuthRoots(0, 1),
            2,
            1,
            1,
            _wrapUint32Array(1, 2),
            _wrapUint32Array(1, 2),
            _wrap2DNullifiers(nullifiers, 2),
            _buildTransfersN(outputs, 2),
            EpochHelpers.buildFeeTransfer(feeOutputs),
            new Withdrawal[](0),
            new uint32[](0),
            uint64(block.timestamp),
            EpochHelpers.dummyProof(),
            new GatewaySlot[](0)
        );
    }

    // ========== Coverage Tests: Duplicate Nullifier (Line 811) ==========

    /// @notice Test InvalidNullifierSet when duplicate nullifier in batch (Line 811)
    function test_revertWhen_duplicateNullifierInBatch() public {
        uint256 rootOld = pool.treeRoot(pool.currentTreeNumber());
        uint32 countOld = pool.treeCount(pool.currentTreeNumber());
        TreeRootPair[] memory usedRoots = EpochHelpers.buildUsedRoots(0, rootOld);

        // Duplicate nullifier in the batch
        uint256[] memory nullifiers = new uint256[](BATCH_SIZE);
        nullifiers[0] = 1001;
        nullifiers[1] = 1001; // Duplicate!

        Output[] memory outputs = new Output[](BATCH_SIZE);
        outputs[0] = EpochHelpers.makeOutput(2001);
        outputs[1] = EpochHelpers.makeOutput(2002);

        Output[] memory feeOutputs = new Output[](MAX_FEE_TOKENS);
        feeOutputs[0] = EpochHelpers.makeOutput(3001);

        vm.prank(relayer);
        vm.expectRevert(IPrivacyBoost.InvalidNullifierSet.selector);
        pool.submitEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0x1234, countOld + 3, false),
            EpochHelpers.buildAuthRoots(0, 1),
            2,
            1,
            1,
            _wrapUint32Array(1, 2),
            _wrapUint32Array(1, 2),
            _wrap2DNullifiers(nullifiers, 2),
            _buildTransfersN(outputs, 2),
            EpochHelpers.buildFeeTransfer(feeOutputs),
            new Withdrawal[](0),
            new uint32[](0),
            uint64(block.timestamp),
            EpochHelpers.dummyProof(),
            new GatewaySlot[](0)
        );
    }

    // ========== Coverage Tests: Zero Nullifier Rejection (L-2) ==========

    /// @notice Zero nullifier must be rejected
    function test_revertWhen_zeroNullifier() public {
        uint256 rootOld = pool.treeRoot(pool.currentTreeNumber());
        uint32 countOld = pool.treeCount(pool.currentTreeNumber());
        TreeRootPair[] memory usedRoots = EpochHelpers.buildUsedRoots(0, rootOld);

        uint256[] memory nullifiers = new uint256[](BATCH_SIZE);
        nullifiers[0] = 0; // Zero nullifier!
        nullifiers[1] = 222;

        Output[] memory outputs = new Output[](BATCH_SIZE);
        outputs[0] = EpochHelpers.makeOutput(2001);
        outputs[1] = EpochHelpers.makeOutput(2002);

        Output[] memory feeOutputs = new Output[](MAX_FEE_TOKENS);
        feeOutputs[0] = EpochHelpers.makeOutput(3001);

        vm.prank(relayer);
        // Zero nullifier in active slot is now caught by _validateSlotPadding before _spendNullifiers
        vm.expectRevert(IPrivacyBoost.InvalidSlotPadding.selector);
        pool.submitEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0x1234, countOld + 3, false),
            EpochHelpers.buildAuthRoots(0, 1),
            2,
            1,
            1,
            _wrapUint32Array(1, 2),
            _wrapUint32Array(1, 2),
            _wrap2DNullifiers(nullifiers, 2),
            _buildTransfersN(outputs, 2),
            EpochHelpers.buildFeeTransfer(feeOutputs),
            new Withdrawal[](0),
            new uint32[](0),
            uint64(block.timestamp),
            EpochHelpers.dummyProof(),
            new GatewaySlot[](0)
        );
    }

    // ========== Coverage Tests: Bounds Validation on inputsPerTransfer/outputsPerTransfer (H-1) ==========

    /// @notice inputsPerTransfer exceeds maxInputsPerTransfer
    function test_revertWhen_inputsPerTransferExceedsMax() public {
        uint256 rootOld = pool.treeRoot(pool.currentTreeNumber());
        uint32 countOld = pool.treeCount(pool.currentTreeNumber());
        TreeRootPair[] memory usedRoots = EpochHelpers.buildUsedRoots(0, rootOld);

        Output[] memory outputs = new Output[](BATCH_SIZE);
        outputs[0] = EpochHelpers.makeOutput(2001);
        outputs[1] = EpochHelpers.makeOutput(2002);

        Output[] memory feeOutputs = new Output[](MAX_FEE_TOKENS);
        feeOutputs[0] = EpochHelpers.makeOutput(3001);

        // inputsPerTransfer[0] = 2 but maxInputsPerTransfer = 1
        uint32[] memory badInputs = new uint32[](BATCH_SIZE);
        badInputs[0] = 2;
        badInputs[1] = 1;

        uint256[] memory nullifiers = new uint256[](BATCH_SIZE);
        nullifiers[0] = 111;
        nullifiers[1] = 222;

        vm.prank(relayer);
        vm.expectRevert(IPrivacyBoost.InvalidEpochConfig.selector);
        pool.submitEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0x1234, countOld + 3, false),
            EpochHelpers.buildAuthRoots(0, 1),
            2,
            1,
            1,
            badInputs,
            _wrapUint32Array(1, 2),
            _wrap2DNullifiers(nullifiers, 2),
            _buildTransfersN(outputs, 2),
            EpochHelpers.buildFeeTransfer(feeOutputs),
            new Withdrawal[](0),
            new uint32[](0),
            uint64(block.timestamp),
            EpochHelpers.dummyProof(),
            new GatewaySlot[](0)
        );
    }

    /// @notice inputsPerTransfer = 0 for active slot
    function test_revertWhen_inputsPerTransferZeroForActiveSlot() public {
        uint256 rootOld = pool.treeRoot(pool.currentTreeNumber());
        uint32 countOld = pool.treeCount(pool.currentTreeNumber());
        TreeRootPair[] memory usedRoots = EpochHelpers.buildUsedRoots(0, rootOld);

        Output[] memory outputs = new Output[](BATCH_SIZE);
        outputs[0] = EpochHelpers.makeOutput(2001);
        outputs[1] = EpochHelpers.makeOutput(2002);

        Output[] memory feeOutputs = new Output[](MAX_FEE_TOKENS);
        feeOutputs[0] = EpochHelpers.makeOutput(3001);

        // inputsPerTransfer[0] = 0 for active slot
        uint32[] memory badInputs = new uint32[](BATCH_SIZE);
        badInputs[0] = 0;
        badInputs[1] = 1;

        uint256[] memory nullifiers = new uint256[](BATCH_SIZE);
        nullifiers[0] = 111;
        nullifiers[1] = 222;

        vm.prank(relayer);
        vm.expectRevert(IPrivacyBoost.InvalidEpochConfig.selector);
        pool.submitEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0x1234, countOld + 3, false),
            EpochHelpers.buildAuthRoots(0, 1),
            2,
            1,
            1,
            badInputs,
            _wrapUint32Array(1, 2),
            _wrap2DNullifiers(nullifiers, 2),
            _buildTransfersN(outputs, 2),
            EpochHelpers.buildFeeTransfer(feeOutputs),
            new Withdrawal[](0),
            new uint32[](0),
            uint64(block.timestamp),
            EpochHelpers.dummyProof(),
            new GatewaySlot[](0)
        );
    }

    /// @notice Inactive slot with non-zero inputsPerTransfer must revert
    function test_revertWhen_inactiveSlotHasNonZeroCounts() public {
        uint256 rootOld = pool.treeRoot(pool.currentTreeNumber());
        uint32 countOld = pool.treeCount(pool.currentTreeNumber());
        TreeRootPair[] memory usedRoots = EpochHelpers.buildUsedRoots(0, rootOld);

        // Use nTransfers=1 with circuitMaxTransfers=2 (partial batch)
        // Slot 1 is inactive but has non-zero inputsPerTransfer
        uint32[] memory badInputs = new uint32[](BATCH_SIZE);
        badInputs[0] = 1; // active: ok
        badInputs[1] = 1; // inactive (t >= nTransfers): should be 0

        uint32[] memory badOutputs = new uint32[](BATCH_SIZE);
        badOutputs[0] = 1; // active: ok
        badOutputs[1] = 0; // inactive: ok (but inputsPerTransfer[1] != 0)

        Output[] memory outputs = new Output[](BATCH_SIZE);
        outputs[0] = EpochHelpers.makeOutput(2001);
        outputs[1] = EpochHelpers.makeOutput(2002);

        Output[] memory feeOutputs = new Output[](MAX_FEE_TOKENS);
        feeOutputs[0] = EpochHelpers.makeOutput(3001);

        uint256[] memory nullifiers = new uint256[](BATCH_SIZE);
        nullifiers[0] = 111;
        nullifiers[1] = 222;

        vm.prank(relayer);
        vm.expectRevert(IPrivacyBoost.InvalidEpochConfig.selector);
        pool.submitEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0x1234, countOld + 2, false),
            EpochHelpers.buildAuthRoots(0, 1),
            1, // nTransfers = 1 (partial batch, slot 1 is inactive)
            1,
            1,
            badInputs,
            badOutputs,
            _wrap2DNullifiers(nullifiers, 2),
            _buildTransfersN(outputs, 2),
            EpochHelpers.buildFeeTransfer(feeOutputs),
            new Withdrawal[](0),
            new uint32[](0),
            uint64(block.timestamp),
            EpochHelpers.dummyProof(),
            new GatewaySlot[](0)
        );
    }

    // ========== Coverage Tests: Partial Batch Digest (C-2) ==========

    /// @notice Partial batch (nTransfers < circuitMaxTransfers) should succeed
    ///         when inactive slots are properly zeroed. Verifies the fix for C-2
    ///         where inactive slot digests must be (0, 0) matching the prover.
    function test_submitEpoch_partialBatch_success() public {
        uint256 rootOld = pool.treeRoot(pool.currentTreeNumber());
        uint32 countOld = pool.treeCount(pool.currentTreeNumber());
        TreeRootPair[] memory usedRoots = EpochHelpers.buildUsedRoots(0, rootOld);

        // circuitMaxTransfers = 2 (from nullifiers.length), nTransfers = 1
        Output[] memory outputs = new Output[](BATCH_SIZE);
        outputs[0] = EpochHelpers.makeOutput(2001);
        outputs[1] = EpochHelpers.makeOutput(0); // inactive slot: zero commitment

        Output[] memory feeOutputs = new Output[](MAX_FEE_TOKENS);
        feeOutputs[0] = EpochHelpers.makeOutput(3001);

        // Active slot has real nullifier, inactive has zero-padded
        uint256[][] memory nullifiers2D = new uint256[][](BATCH_SIZE);
        nullifiers2D[0] = new uint256[](1);
        nullifiers2D[0][0] = 111;
        nullifiers2D[1] = new uint256[](1);
        nullifiers2D[1][0] = 0; // inactive slot: zero-padded

        // inputsPerTransfer/outputsPerTransfer: active=1, inactive=0
        uint32[] memory inputs = new uint32[](BATCH_SIZE);
        inputs[0] = 1;
        inputs[1] = 0;
        uint32[] memory outputCounts = new uint32[](BATCH_SIZE);
        outputCounts[0] = 1;
        outputCounts[1] = 0;

        vm.prank(relayer);
        pool.submitEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0x1234, countOld + 2, false),
            EpochHelpers.buildAuthRoots(0, 1),
            1, // nTransfers = 1 (partial batch)
            1,
            1,
            inputs,
            outputCounts,
            nullifiers2D,
            _buildTransfersN(outputs, 2),
            EpochHelpers.buildFeeTransfer(feeOutputs),
            new Withdrawal[](0),
            new uint32[](0),
            uint64(block.timestamp),
            EpochHelpers.dummyProof(),
            new GatewaySlot[](0)
        );

        // Verify tree state was updated
        assertEq(pool.treeCount(0), countOld + 2);
    }

    // ========== Slot Padding Invariant Tests ==========

    /// @notice Non-zero nullifier in inactive transfer must revert
    function test_revertWhen_nonZeroNullifierInInactiveTransfer() public {
        uint256 rootOld = pool.treeRoot(pool.currentTreeNumber());
        uint32 countOld = pool.treeCount(pool.currentTreeNumber());
        TreeRootPair[] memory usedRoots = EpochHelpers.buildUsedRoots(0, rootOld);

        Output[] memory outputs = new Output[](BATCH_SIZE);
        outputs[0] = EpochHelpers.makeOutput(2001);
        outputs[1] = EpochHelpers.makeOutput(0); // inactive transfer

        Output[] memory feeOutputs = new Output[](MAX_FEE_TOKENS);
        feeOutputs[0] = EpochHelpers.makeOutput(3001);

        uint256[][] memory nullifiers2D = new uint256[][](BATCH_SIZE);
        nullifiers2D[0] = new uint256[](1);
        nullifiers2D[0][0] = 111; // active: non-zero
        nullifiers2D[1] = new uint256[](1);
        nullifiers2D[1][0] = 999; // inactive transfer: non-zero (INVALID)

        uint32[] memory inputs = new uint32[](BATCH_SIZE);
        inputs[0] = 1;
        inputs[1] = 0; // inactive
        uint32[] memory outputCounts = new uint32[](BATCH_SIZE);
        outputCounts[0] = 1;
        outputCounts[1] = 0; // inactive

        vm.prank(relayer);
        vm.expectRevert(IPrivacyBoost.InvalidSlotPadding.selector);
        pool.submitEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0x1234, countOld + 2, false),
            EpochHelpers.buildAuthRoots(0, 1),
            1,
            1,
            1,
            inputs,
            outputCounts,
            nullifiers2D,
            _buildTransfersN(outputs, 2),
            EpochHelpers.buildFeeTransfer(feeOutputs),
            new Withdrawal[](0),
            new uint32[](0),
            uint64(block.timestamp),
            EpochHelpers.dummyProof(),
            new GatewaySlot[](0)
        );
    }

    /// @notice Non-zero commitment in inactive output slot of active transfer must revert.
    ///         Inactive *transfer* commitments are zero-initialized by _computeTransferDigests
    ///         and only enforced by the circuit; this tests the contract-observable case.
    function test_revertWhen_nonZeroCommitmentInInactiveOutputSlot() public {
        // Deploy a pool with maxOutputsPerTransfer=2 so we can have inactive output slots
        MockVerifier v2 = new MockVerifier();
        DeployConfig memory cfg = PoolDeployer.defaultConfig(owner, proxyAdmin, address(v2));
        cfg.batchSize = 1;
        cfg.maxFeeTokens = MAX_FEE_TOKENS;
        cfg.maxOutputsPerTransfer = 2;
        (PrivacyBoost pool2,) = PoolDeployer.deployWithMockAuth(cfg, address(authRegistry));
        pool2.setOperator(operator);
        address[] memory relayers = new address[](1);
        relayers[0] = relayer;
        vm.prank(operator);
        pool2.setAllowedRelays(relayers, true);

        uint256 rootOld = pool2.treeRoot(pool2.currentTreeNumber());
        uint32 countOld = pool2.treeCount(pool2.currentTreeNumber());
        TreeRootPair[] memory usedRoots = EpochHelpers.buildUsedRoots(0, rootOld);

        // 1 transfer with outputsPerTransfer=1, but maxOutputsPerTransfer=2
        // Output slot 0 is active, slot 1 is inactive
        Output[] memory outputs = new Output[](2);
        outputs[0] = EpochHelpers.makeOutput(2001); // active: non-zero
        outputs[1] = EpochHelpers.makeOutput(9999); // inactive slot: non-zero (INVALID)

        Output[] memory feeOutputs = new Output[](MAX_FEE_TOKENS);
        feeOutputs[0] = EpochHelpers.makeOutput(3001);

        uint256[][] memory nullifiers2D = new uint256[][](1);
        nullifiers2D[0] = new uint256[](1);
        nullifiers2D[0][0] = 111;

        vm.prank(relayer);
        vm.expectRevert(IPrivacyBoost.InvalidSlotPadding.selector);
        pool2.submitEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0x1234, countOld + 2, false),
            EpochHelpers.buildAuthRoots(0, 1),
            1,
            1,
            1,
            EpochHelpers.singletonUint32Array(1), // inputsPerTransfer
            EpochHelpers.singletonUint32Array(1), // outputsPerTransfer = 1 (slot 1 inactive)
            nullifiers2D,
            EpochHelpers.buildTransfers(outputs),
            EpochHelpers.buildFeeTransfer(feeOutputs),
            new Withdrawal[](0),
            new uint32[](0),
            uint64(block.timestamp),
            EpochHelpers.dummyProof(),
            new GatewaySlot[](0)
        );
    }

    /// @notice Zero commitment in active transfer must revert
    function test_revertWhen_zeroCommitmentInActiveTransfer() public {
        uint256 rootOld = pool.treeRoot(pool.currentTreeNumber());
        uint32 countOld = pool.treeCount(pool.currentTreeNumber());
        TreeRootPair[] memory usedRoots = EpochHelpers.buildUsedRoots(0, rootOld);

        Output[] memory outputs = new Output[](BATCH_SIZE);
        outputs[0] = EpochHelpers.makeOutput(0); // active: zero commitment (INVALID)
        outputs[1] = EpochHelpers.makeOutput(2002); // active

        Output[] memory feeOutputs = new Output[](MAX_FEE_TOKENS);
        feeOutputs[0] = EpochHelpers.makeOutput(3001);

        uint256[] memory nullifiers = new uint256[](BATCH_SIZE);
        nullifiers[0] = 111;
        nullifiers[1] = 222;

        vm.prank(relayer);
        vm.expectRevert(IPrivacyBoost.InvalidSlotPadding.selector);
        pool.submitEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0x1234, countOld + 3, false),
            EpochHelpers.buildAuthRoots(0, 1),
            2,
            1,
            1,
            _wrapUint32Array(1, 2),
            _wrapUint32Array(1, 2),
            _wrap2DNullifiers(nullifiers, 2),
            _buildTransfersN(outputs, 2),
            EpochHelpers.buildFeeTransfer(feeOutputs),
            new Withdrawal[](0),
            new uint32[](0),
            uint64(block.timestamp),
            EpochHelpers.dummyProof(),
            new GatewaySlot[](0)
        );
    }

    /// @notice Zero nullifier in active transfer must revert (caught by slot padding before _spendNullifiers)
    function test_revertWhen_zeroNullifierInActiveTransfer_slotPadding() public {
        uint256 rootOld = pool.treeRoot(pool.currentTreeNumber());
        uint32 countOld = pool.treeCount(pool.currentTreeNumber());
        TreeRootPair[] memory usedRoots = EpochHelpers.buildUsedRoots(0, rootOld);

        Output[] memory outputs = new Output[](BATCH_SIZE);
        outputs[0] = EpochHelpers.makeOutput(2001);
        outputs[1] = EpochHelpers.makeOutput(2002);

        Output[] memory feeOutputs = new Output[](MAX_FEE_TOKENS);
        feeOutputs[0] = EpochHelpers.makeOutput(3001);

        uint256[] memory nullifiers = new uint256[](BATCH_SIZE);
        nullifiers[0] = 0; // active: zero nullifier (INVALID)
        nullifiers[1] = 222;

        vm.prank(relayer);
        vm.expectRevert(IPrivacyBoost.InvalidSlotPadding.selector);
        pool.submitEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0x1234, countOld + 3, false),
            EpochHelpers.buildAuthRoots(0, 1),
            2,
            1,
            1,
            _wrapUint32Array(1, 2),
            _wrapUint32Array(1, 2),
            _wrap2DNullifiers(nullifiers, 2),
            _buildTransfersN(outputs, 2),
            EpochHelpers.buildFeeTransfer(feeOutputs),
            new Withdrawal[](0),
            new uint32[](0),
            uint64(block.timestamp),
            EpochHelpers.dummyProof(),
            new GatewaySlot[](0)
        );
    }

    /// @dev Timestamp check fires before all other epoch validation, so
    /// minimal calldata suffices; other args never get inspected.
    function _submitEpochWithTimestamp(uint64 provingTimestamp) internal {
        Output[] memory feeOutputs = new Output[](MAX_FEE_TOKENS);
        feeOutputs[0] = EpochHelpers.makeOutput(999);
        vm.prank(relayer);
        pool.submitEpoch(
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, 1), 0, 0, 1, 0, false),
            EpochHelpers.buildAuthRoots(0, 1),
            0,
            0,
            0,
            new uint32[](0),
            new uint32[](0),
            new uint256[][](0),
            new Transfer[](0),
            EpochHelpers.buildFeeTransfer(feeOutputs),
            new Withdrawal[](0),
            new uint32[](0),
            provingTimestamp,
            EpochHelpers.dummyProof(),
            new GatewaySlot[](0)
        );
    }

    /// @notice A proving timestamp ahead of block time must revert.
    function test_revertWhen_provingTimestampInFuture() public {
        vm.expectRevert(IPrivacyBoost.InvalidProvingTimestamp.selector);
        _submitEpochWithTimestamp(uint64(block.timestamp + 1));
    }

    /// @notice A proving timestamp older than MAX_PROOF_AGE must revert.
    function test_revertWhen_provingTimestampStale() public {
        vm.warp(block.timestamp + MAX_PROOF_AGE + 2);
        vm.expectRevert(IPrivacyBoost.InvalidProvingTimestamp.selector);
        _submitEpochWithTimestamp(uint64(block.timestamp - MAX_PROOF_AGE - 1));
    }

    /// @notice Exactly MAX_PROOF_AGE old passes the timestamp gate: the call
    /// proceeds to config validation, pinning the comparison direction.
    function test_provingTimestampAtMaxAgePassesGate() public {
        vm.warp(block.timestamp + MAX_PROOF_AGE + 2);
        vm.expectRevert(IPrivacyBoost.InvalidEpochConfig.selector);
        _submitEpochWithTimestamp(uint64(block.timestamp - MAX_PROOF_AGE));
    }
}
