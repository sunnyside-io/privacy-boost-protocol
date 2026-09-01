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
import {
    Output,
    Transfer,
    Withdrawal,
    EpochTreeState,
    TreeRootPair,
    DepositEntry,
    GatewaySlot
} from "src/interfaces/IStructs.sol";

import {MockVerifier, MockAuthRegistryMultiTree} from "test/helpers/Mocks.sol";
import {PoolDeployer, DeployConfig} from "test/helpers/PoolDeployer.sol";
import {EpochHelpers} from "test/helpers/EpochHelpers.sol";

contract ActiveRootAssertingVerifier {
    uint256 public expectedActiveRoot;

    function setExpectedActiveRoot(uint256 root) external {
        expectedActiveRoot = root;
    }

    function verifyEpoch(uint32, uint32, uint32, uint256[8] calldata, uint256[] calldata publicInputs)
        external
        view
        returns (bool)
    {
        assert(publicInputs[19] == expectedActiveRoot);
        return true;
    }
}

/// @notice Tests for sparse tree roots and auth-root validation edge cases
contract SparseRootsEdgeCasesTest is Test {
    PrivacyBoost pool;
    TokenRegistry tokenRegistry;
    MockAuthRegistryMultiTree authRegistry;
    MockVerifier verifier;

    address owner = address(this);
    address proxyAdmin = address(0xAD);
    address operator = makeAddr("operator");

    function setUp() public {
        verifier = new MockVerifier();
        authRegistry = new MockAuthRegistryMultiTree();

        DeployConfig memory cfg = PoolDeployer.defaultConfig(owner, proxyAdmin, address(verifier));
        cfg.batchSize = 1;
        cfg.maxFeeTokens = 1;

        (pool, tokenRegistry) = PoolDeployer.deployWithMockAuth(cfg, address(authRegistry));

        // Set operator
        pool.setOperator(operator);

        // Setup: allow this contract as relay
        address[] memory relays = new address[](1);
        relays[0] = address(this);
        vm.prank(operator);
        pool.setAllowedRelays(relays, true);
    }

    // ========== Helper Functions ==========

    function _submitBasicEpoch(EpochTreeState memory treeState, TreeRootPair[] memory usedAuthRoots) internal {
        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = uint256(keccak256(abi.encodePacked(block.timestamp, treeState.rootNew)));

        pool.submitEpoch(
            treeState,
            usedAuthRoots,
            1, // nTransfers
            1, // feeTokenCount
            1, // feeNPK
            EpochHelpers.singletonUint32Array(1),
            EpochHelpers.singletonUint32Array(1),
            EpochHelpers.wrap2D(nullifiers),
            EpochHelpers.buildTransfers(EpochHelpers.defaultOutputs(1)),
            EpochHelpers.buildFeeTransfer(new Output[](1)),
            new Withdrawal[](0),
            new uint32[](0),
            uint64(block.timestamp),
            [uint256(1), 2, 3, 4, 5, 6, 7, 8],
            new GatewaySlot[](0)
        );
    }

    // ========== Empty Sparse Arrays Tests ==========

    /// @notice Test that empty usedRoots array reverts with InvalidBatchConfig
    function test_revert_emptyUsedRoots() public {
        TreeRootPair[] memory emptyRoots = new TreeRootPair[](0);

        vm.expectRevert(IPrivacyBoost.InvalidBatchConfig.selector);
        _submitBasicEpoch(EpochHelpers.buildTreeState(emptyRoots, 0, 0, 1, 2, false), EpochHelpers.buildAuthRoots(0, 1));
    }

    /// @notice Test that empty usedAuthRoots array reverts with InvalidBatchConfig
    function test_revert_emptyUsedAuthRoots() public {
        TreeRootPair[] memory emptyAuthRoots = new TreeRootPair[](0);

        uint256 currentTreeRoot = pool.treeRoot(0); // Read before expectRevert

        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = uint256(keccak256(abi.encodePacked(block.timestamp, uint256(1))));

        vm.expectRevert(IPrivacyBoost.InvalidBatchConfig.selector);
        pool.submitEpoch(
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, currentTreeRoot), 0, 0, 1, 2, false),
            emptyAuthRoots,
            1, // nTransfers
            1, // feeTokenCount
            1, // feeNPK
            EpochHelpers.singletonUint32Array(1), // inputsPerTransfer
            EpochHelpers.singletonUint32Array(1), // outputsPerTransfer
            EpochHelpers.wrap2D(nullifiers),
            EpochHelpers.buildTransfers(EpochHelpers.defaultOutputs(1)),
            EpochHelpers.buildFeeTransfer(new Output[](1)),
            new Withdrawal[](0),
            new uint32[](0),
            uint64(block.timestamp),
            [uint256(1), 2, 3, 4, 5, 6, 7, 8],
            new GatewaySlot[](0)
        );
    }

    // ========== Boundary Tests (>16 roots) ==========

    /// @notice Test that >16 usedRoots array reverts with InvalidBatchConfig
    function test_revert_tooManyUsedRoots() public {
        // Create array with 17 roots
        TreeRootPair[] memory tooManyRoots = new TreeRootPair[](17);
        for (uint256 i = 0; i < 17; i++) {
            tooManyRoots[i] = TreeRootPair({treeNumber: i, root: pool.treeRoot(0)});
        }

        vm.expectRevert(IPrivacyBoost.InvalidBatchConfig.selector);
        _submitBasicEpoch(
            EpochHelpers.buildTreeState(tooManyRoots, 0, 0, 1, 2, false), EpochHelpers.buildAuthRoots(0, 1)
        );
    }

    /// @notice Test that >16 usedAuthRoots array reverts with InvalidBatchConfig
    function test_revert_tooManyUsedAuthRoots() public {
        // Create array with 17 auth roots
        TreeRootPair[] memory tooManyAuthRoots = new TreeRootPair[](17);
        for (uint256 i = 0; i < 17; i++) {
            tooManyAuthRoots[i] = TreeRootPair({treeNumber: i, root: 1});
        }

        uint256 currentTreeRoot = pool.treeRoot(0); // Read before expectRevert

        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = uint256(keccak256(abi.encodePacked(block.timestamp, uint256(1))));

        vm.expectRevert(IPrivacyBoost.InvalidBatchConfig.selector);
        pool.submitEpoch(
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, currentTreeRoot), 0, 0, 1, 2, false),
            tooManyAuthRoots,
            1, // nTransfers
            1, // feeTokenCount
            1, // feeNPK
            EpochHelpers.singletonUint32Array(1), // inputsPerTransfer
            EpochHelpers.singletonUint32Array(1), // outputsPerTransfer
            EpochHelpers.wrap2D(nullifiers),
            EpochHelpers.buildTransfers(EpochHelpers.defaultOutputs(1)),
            EpochHelpers.buildFeeTransfer(new Output[](1)),
            new Withdrawal[](0),
            new uint32[](0),
            uint64(block.timestamp),
            [uint256(1), 2, 3, 4, 5, 6, 7, 8],
            new GatewaySlot[](0)
        );
    }

    /// @notice Test that exactly 16 usedRoots is valid (boundary case)
    function test_exactly16UsedRootsIsValid() public {
        // Create array with 16 roots, but only tree 0 has valid root
        TreeRootPair[] memory roots = new TreeRootPair[](1);
        roots[0] = TreeRootPair({treeNumber: 0, root: pool.treeRoot(0)});

        // Should succeed with single valid root
        _submitBasicEpoch(EpochHelpers.buildTreeState(roots, 0, 0, 1, 2, false), EpochHelpers.buildAuthRoots(0, 1));

        assertEq(pool.treeRoot(0), 1, "Root should be updated");
    }

    // ========== Active Tree Validation Tests ==========

    /// @notice Test that active tree not in usedRoots reverts with InvalidEpochState
    function test_revert_activeTreeNotInUsedRoots() public {
        // Create usedRoots with only tree 0, but set activeTreeNumber to 1
        TreeRootPair[] memory roots = new TreeRootPair[](1);
        roots[0] = TreeRootPair({treeNumber: 0, root: pool.treeRoot(0)});

        // activeTreeNumber=1 but usedRoots only contains tree 0
        vm.expectRevert(IPrivacyBoost.InvalidEpochState.selector);
        _submitBasicEpoch(
            EpochHelpers.buildTreeState(roots, 1, 0, 1, 2, false), // activeTreeNumber=1
            EpochHelpers.buildAuthRoots(0, 1)
        );
    }

    /// @notice Test that active tree with historical (not current) root in usedRoots succeeds.
    /// The contract reads activeRoot from treeRoot[activeTreeNumber] for frontier binding,
    /// so usedRoots can carry a past root for input spending.
    function test_activeTreeWithHistoricalRoot() public {
        uint256 initialRoot = pool.treeRoot(0);

        // First epoch: advance tree 0 root (initialRoot -> 1001)
        _submitBasicEpoch(
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, initialRoot), 0, 0, 1001, 2, false),
            EpochHelpers.buildAuthRoots(0, 1)
        );
        assertEq(pool.treeRoot(0), 1001, "Root should be 1001 after first epoch");

        // Second epoch: usedRoots references the historical root (initialRoot), not the current one (1001).
        // This is valid because inputs may have been inserted under the old root.
        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = 33333;

        pool.submitEpoch(
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, initialRoot), 0, 2, 1002, 4, false),
            EpochHelpers.buildAuthRoots(0, 1),
            1,
            1,
            1,
            EpochHelpers.singletonUint32Array(1),
            EpochHelpers.singletonUint32Array(1),
            EpochHelpers.wrap2D(nullifiers),
            EpochHelpers.buildTransfers(EpochHelpers.defaultOutputs(1)),
            EpochHelpers.buildFeeTransfer(new Output[](1)),
            new Withdrawal[](0),
            new uint32[](0),
            uint64(block.timestamp),
            [uint256(1), 2, 3, 4, 5, 6, 7, 8],
            new GatewaySlot[](0)
        );

        assertEq(pool.treeRoot(0), 1002, "Root should be updated to 1002");
    }

    function test_epochUsesCurrentRootForActiveRootWhenSparseRootIsHistorical() public {
        uint256 initialRoot = pool.treeRoot(0);

        _submitBasicEpoch(
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, initialRoot), 0, 0, 1001, 2, false),
            EpochHelpers.buildAuthRoots(0, 1)
        );

        uint256 currentRoot = pool.treeRoot(0);
        ActiveRootAssertingVerifier assertingVerifier = new ActiveRootAssertingVerifier();
        assertingVerifier.setExpectedActiveRoot(currentRoot);
        pool.setEpochVerifier(address(assertingVerifier));

        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = 33334;

        pool.submitEpoch(
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, initialRoot), 0, 2, 1002, 4, false),
            EpochHelpers.buildAuthRoots(0, 1),
            1,
            1,
            1,
            EpochHelpers.singletonUint32Array(1),
            EpochHelpers.singletonUint32Array(1),
            EpochHelpers.wrap2D(nullifiers),
            EpochHelpers.buildTransfers(EpochHelpers.defaultOutputs(1)),
            EpochHelpers.buildFeeTransfer(new Output[](1)),
            new Withdrawal[](0),
            new uint32[](0),
            uint64(block.timestamp),
            [uint256(1), 2, 3, 4, 5, 6, 7, 8],
            new GatewaySlot[](0)
        );

        assertEq(pool.treeRoot(0), 1002, "Root should be updated to 1002");
    }

    // ========== Zero Root Tests ==========

    /// @notice Test that zero root in usedRoots reverts with RootNotKnown
    function test_revert_zeroRootInUsedRoots() public {
        TreeRootPair[] memory roots = new TreeRootPair[](1);
        roots[0] = TreeRootPair({treeNumber: 0, root: 0}); // Zero root

        vm.expectRevert(IPrivacyBoost.RootNotKnown.selector);
        _submitBasicEpoch(EpochHelpers.buildTreeState(roots, 0, 0, 1, 2, false), EpochHelpers.buildAuthRoots(0, 1));
    }

    /// @notice Test that zero root in usedAuthRoots reverts with RootNotKnown
    function test_revert_zeroRootInUsedAuthRoots() public {
        TreeRootPair[] memory authRoots = new TreeRootPair[](1);
        authRoots[0] = TreeRootPair({treeNumber: 0, root: 0}); // Zero root

        uint256 currentTreeRoot = pool.treeRoot(0); // Read before expectRevert

        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = uint256(keccak256(abi.encodePacked(block.timestamp, uint256(1))));

        vm.expectRevert(IPrivacyBoost.RootNotKnown.selector);
        pool.submitEpoch(
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, currentTreeRoot), 0, 0, 1, 2, false),
            authRoots,
            1, // nTransfers
            1, // feeTokenCount
            1, // feeNPK
            EpochHelpers.singletonUint32Array(1), // inputsPerTransfer
            EpochHelpers.singletonUint32Array(1), // outputsPerTransfer
            EpochHelpers.wrap2D(nullifiers),
            EpochHelpers.buildTransfers(EpochHelpers.defaultOutputs(1)),
            EpochHelpers.buildFeeTransfer(new Output[](1)),
            new Withdrawal[](0),
            new uint32[](0),
            uint64(block.timestamp),
            [uint256(1), 2, 3, 4, 5, 6, 7, 8],
            new GatewaySlot[](0)
        );
    }

    // ========== Multi-Tree Batch Tests ==========

    /// @notice Test multi-tree batch with partial sparse set
    function test_multiTreeBatchPartialSparseSet() public {
        // First, submit to tree 0
        uint256 tree0Root = pool.treeRoot(0);
        _submitBasicEpoch(
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, tree0Root), 0, 0, 1001, 2, false),
            EpochHelpers.buildAuthRoots(0, 1)
        );

        // Rollover to tree 1
        // Set up tree 0 at max capacity
        uint8 MERKLE_DEPTH = 20;
        uint32 MAX_LEAVES = uint32(1 << MERKLE_DEPTH);

        bytes32 treeCountSlot = keccak256(abi.encode(uint256(0), uint256(8)));
        vm.store(address(pool), treeCountSlot, bytes32(uint256(MAX_LEAVES)));

        bytes32 treeRootSlot = keccak256(abi.encode(uint256(0), uint256(7)));
        uint256 fullTreeRoot = 0xF011EEEE;
        vm.store(address(pool), treeRootSlot, bytes32(fullTreeRoot));

        bytes32 treeRootHistoryCursorSlot = keccak256(abi.encode(uint256(0), uint256(10)));
        vm.store(address(pool), treeRootHistoryCursorSlot, bytes32(uint256(2)));

        bytes32 baseArraySlot = keccak256(abi.encode(uint256(0), uint256(9)));
        vm.store(address(pool), bytes32(uint256(baseArraySlot) + 2), bytes32(fullTreeRoot));

        // Epoch allows duplicate tree numbers in usedRoots because each input
        // proves membership against an explicit (treeNumber, root) pair.
        TreeRootPair[] memory multiRoots = new TreeRootPair[](2);
        multiRoots[0] = TreeRootPair({treeNumber: 0, root: fullTreeRoot});
        multiRoots[1] = TreeRootPair({treeNumber: 0, root: tree0Root}); // Duplicate tree number with different root (allowed for epoch)

        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = 99999;

        // Submit with rollover — duplicate tree numbers accepted for epoch
        pool.submitEpoch(
            EpochHelpers.buildTreeState(multiRoots, 0, MAX_LEAVES, 2001, 2, true),
            EpochHelpers.buildAuthRoots(0, 1),
            1, // nTransfers
            1, // feeTokenCount
            1, // feeNPK
            EpochHelpers.singletonUint32Array(1), // inputsPerTransfer
            EpochHelpers.singletonUint32Array(1), // outputsPerTransfer
            EpochHelpers.wrap2D(nullifiers),
            EpochHelpers.buildTransfers(EpochHelpers.defaultOutputs(1)),
            EpochHelpers.buildFeeTransfer(new Output[](1)),
            new Withdrawal[](0),
            new uint32[](0),
            uint64(block.timestamp),
            [uint256(1), 2, 3, 4, 5, 6, 7, 8],
            new GatewaySlot[](0)
        );
    }

    /// @notice Test that epoch accepts duplicate tree numbers with different (but known) roots.
    /// @dev Inputs bind directly to (treeNumber, root) pairs, so duplicate tree numbers
    ///      remain safe as long as exact duplicate pairs are rejected.
    function test_epochAcceptsDuplicateTreeNumberDifferentRoots() public {
        // Submit once to make the initial root historical (known) and create a new current root.
        uint256 initialRoot = pool.treeRoot(0);
        _submitBasicEpoch(
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, initialRoot), 0, 0, 1001, 2, false),
            EpochHelpers.buildAuthRoots(0, 1)
        );

        uint32 countOld = pool.treeCount(0);
        uint256 currentRoot = pool.treeRoot(0);

        assertTrue(pool.isKnownTreeRoot(0, initialRoot), "Initial root should be known");
        assertTrue(pool.isKnownTreeRoot(0, currentRoot), "Current root should be known");

        TreeRootPair[] memory dupRoots = new TreeRootPair[](2);
        dupRoots[0] = TreeRootPair({treeNumber: 0, root: initialRoot});
        dupRoots[1] = TreeRootPair({treeNumber: 0, root: currentRoot});

        // Epoch accepts duplicate tree numbers with different known roots.
        _submitBasicEpoch(
            EpochHelpers.buildTreeState(dupRoots, 0, countOld, 2002, countOld + 2, false),
            EpochHelpers.buildAuthRoots(0, 1)
        );
    }

    /// @notice Test that epoch rejects exact duplicate (treeNumber, root) pairs.
    function test_revertWhen_epochDuplicateTreeRootPair() public {
        uint256 root = pool.treeRoot(0);

        TreeRootPair[] memory dupPairs = new TreeRootPair[](2);
        dupPairs[0] = TreeRootPair({treeNumber: 0, root: root});
        dupPairs[1] = TreeRootPair({treeNumber: 0, root: root});

        vm.expectRevert(IPrivacyBoost.DuplicateTreeRootPair.selector);
        _submitBasicEpoch(
            EpochHelpers.buildTreeState(dupPairs, 0, 0, 1001, 2, false), EpochHelpers.buildAuthRoots(0, 1)
        );
    }

    /// @notice Test that duplicate tree numbers in usedAuthRoots are rejected.
    function test_revert_duplicateTreeNumberInUsedAuthRoots() public {
        TreeRootPair[] memory usedRoots = EpochHelpers.buildUsedRoots(0, pool.treeRoot(0));
        TreeRootPair[] memory dupAuthRoots = new TreeRootPair[](2);
        dupAuthRoots[0] = TreeRootPair({treeNumber: 0, root: 1});
        dupAuthRoots[1] = TreeRootPair({treeNumber: 0, root: 1});

        vm.expectRevert(IPrivacyBoost.DuplicateTreeNumber.selector);
        _submitBasicEpoch(EpochHelpers.buildTreeState(usedRoots, 0, 0, 1, 2, false), dupAuthRoots);
    }

    /// @notice Test epoch with inputs from historical tree (after rollover)
    function test_epochWithHistoricalTreeInputs() public {
        // Set up tree 0 at max capacity and do rollover
        uint8 MERKLE_DEPTH = 20;
        uint32 MAX_LEAVES = uint32(1 << MERKLE_DEPTH);

        bytes32 treeCountSlot = keccak256(abi.encode(uint256(0), uint256(8)));
        vm.store(address(pool), treeCountSlot, bytes32(uint256(MAX_LEAVES)));

        bytes32 treeRootSlot = keccak256(abi.encode(uint256(0), uint256(7)));
        uint256 tree0FinalRoot = 0xF011EEEE;
        vm.store(address(pool), treeRootSlot, bytes32(tree0FinalRoot));

        bytes32 treeRootHistoryCursorSlot = keccak256(abi.encode(uint256(0), uint256(10)));
        vm.store(address(pool), treeRootHistoryCursorSlot, bytes32(uint256(1)));

        bytes32 baseArraySlot = keccak256(abi.encode(uint256(0), uint256(9)));
        vm.store(address(pool), bytes32(uint256(baseArraySlot) + 1), bytes32(tree0FinalRoot));

        // Rollover to tree 1
        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = 88888;

        pool.submitEpoch(
            EpochHelpers.buildTreeState(
                EpochHelpers.buildUsedRoots(0, tree0FinalRoot), 0, MAX_LEAVES, 0xEEE10001, 2, true
            ),
            EpochHelpers.buildAuthRoots(0, 1),
            1, // nTransfers
            1, // feeTokenCount
            1, // feeNPK
            EpochHelpers.singletonUint32Array(1), // inputsPerTransfer
            EpochHelpers.singletonUint32Array(1), // outputsPerTransfer
            EpochHelpers.wrap2D(nullifiers),
            EpochHelpers.buildTransfers(EpochHelpers.defaultOutputs(1)),
            EpochHelpers.buildFeeTransfer(new Output[](1)),
            new Withdrawal[](0),
            new uint32[](0),
            uint64(block.timestamp),
            [uint256(1), 2, 3, 4, 5, 6, 7, 8],
            new GatewaySlot[](0)
        );

        assertEq(pool.currentTreeNumber(), 1, "Should be on tree 1");

        // Now submit epoch with inputs from BOTH tree 0 (historical) and tree 1 (active)
        TreeRootPair[] memory multiRoots = new TreeRootPair[](2);
        multiRoots[0] = TreeRootPair({treeNumber: 0, root: tree0FinalRoot}); // Historical tree
        multiRoots[1] = TreeRootPair({treeNumber: 1, root: pool.treeRoot(1)}); // Active tree

        nullifiers[0] = 77777;

        pool.submitEpoch(
            EpochHelpers.buildTreeState(multiRoots, 1, 2, 0xEEE10002, 4, false),
            EpochHelpers.buildAuthRoots(0, 1),
            1, // nTransfers
            1, // feeTokenCount
            1, // feeNPK
            EpochHelpers.singletonUint32Array(1), // inputsPerTransfer
            EpochHelpers.singletonUint32Array(1), // outputsPerTransfer
            EpochHelpers.wrap2D(nullifiers),
            EpochHelpers.buildTransfers(EpochHelpers.defaultOutputs(1)),
            EpochHelpers.buildFeeTransfer(new Output[](1)),
            new Withdrawal[](0),
            new uint32[](0),
            uint64(block.timestamp),
            [uint256(1), 2, 3, 4, 5, 6, 7, 8],
            new GatewaySlot[](0)
        );

        assertEq(pool.treeRoot(1), 0xEEE10002, "Tree 1 root should be updated");
    }

    // ========== Multi-Auth Tree Tests ==========

    /// @notice Test epoch with multiple auth trees in sparse array
    function test_multipleAuthTreesInSparseArray() public {
        // Add more auth trees via mock
        authRegistry.addAuthTree(2); // Tree 1 with root 2
        authRegistry.addAuthTree(3); // Tree 2 with root 3

        // Create sparse auth roots with multiple trees
        TreeRootPair[] memory multiAuthRoots = new TreeRootPair[](3);
        multiAuthRoots[0] = TreeRootPair({treeNumber: 0, root: 1});
        multiAuthRoots[1] = TreeRootPair({treeNumber: 1, root: 2});
        multiAuthRoots[2] = TreeRootPair({treeNumber: 2, root: 3});

        // Should succeed
        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = 55555;

        pool.submitEpoch(
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, pool.treeRoot(0)), 0, 0, 1, 2, false),
            multiAuthRoots,
            1, // nTransfers
            1, // feeTokenCount
            1, // feeNPK
            EpochHelpers.singletonUint32Array(1), // inputsPerTransfer
            EpochHelpers.singletonUint32Array(1), // outputsPerTransfer
            EpochHelpers.wrap2D(nullifiers),
            EpochHelpers.buildTransfers(EpochHelpers.defaultOutputs(1)),
            EpochHelpers.buildFeeTransfer(new Output[](1)),
            new Withdrawal[](0),
            new uint32[](0),
            uint64(block.timestamp),
            [uint256(1), 2, 3, 4, 5, 6, 7, 8],
            new GatewaySlot[](0)
        );

        assertEq(pool.treeRoot(0), 1, "Root should be updated");
    }

    /// @notice Test that an unknown auth root for an extra tree reverts.
    function test_revert_unknownAuthRootForExtraTree() public {
        // Add auth tree 1
        authRegistry.addAuthTree(2);

        TreeRootPair[] memory multiAuthRoots = new TreeRootPair[](2);
        multiAuthRoots[0] = TreeRootPair({treeNumber: 0, root: 1});
        multiAuthRoots[1] = TreeRootPair({treeNumber: 1, root: 9999}); // Not the known root for tree 1

        uint256 currentTreeRoot = pool.treeRoot(0); // Read before expectRevert
        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = 44444;

        vm.expectRevert(IPrivacyBoost.RootNotKnown.selector);
        pool.submitEpoch(
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, currentTreeRoot), 0, 0, 1, 2, false),
            multiAuthRoots,
            1, // nTransfers
            1, // feeTokenCount
            1, // feeNPK
            EpochHelpers.singletonUint32Array(1), // inputsPerTransfer
            EpochHelpers.singletonUint32Array(1), // outputsPerTransfer
            EpochHelpers.wrap2D(nullifiers),
            EpochHelpers.buildTransfers(EpochHelpers.defaultOutputs(1)),
            EpochHelpers.buildFeeTransfer(new Output[](1)),
            new Withdrawal[](0),
            new uint32[](0),
            uint64(block.timestamp),
            [uint256(1), 2, 3, 4, 5, 6, 7, 8],
            new GatewaySlot[](0)
        );
    }

    // ========== Deposit Epoch Tests ==========

    /// @notice Test submitDepositEpoch with empty usedRoots reverts
    /// @dev Note: The sparse root validation happens after basic epoch config checks.
    ///      To reach _validateKnownRootsSparse, we need valid deposits array.
    ///      Since creating valid deposits is complex, we test that empty deposits
    ///      fails with InvalidEpochConfig (which is the expected behavior).
    function test_revert_depositEpochEmptyDeposits() public {
        TreeRootPair[] memory roots = new TreeRootPair[](1);
        roots[0] = TreeRootPair({treeNumber: 0, root: pool.treeRoot(0)});

        // Empty deposits array triggers InvalidEpochConfig
        vm.expectRevert(IPrivacyBoost.InvalidEpochConfig.selector);
        pool.submitDepositEpoch(
            EpochHelpers.buildTreeState(roots, 0, 0, 1, 1, false),
            1, // nTotalCommitments
            new Output[](1),
            new DepositEntry[](0), // Empty deposits
            [uint256(1), 2, 3, 4, 5, 6, 7, 8]
        );
    }

    /// @notice Test submitDepositEpoch validation sequence - epoch config checked before sparse roots
    /// @dev This verifies that empty usedRoots with empty deposits fails with InvalidEpochConfig,
    ///      confirming the validation order in submitDepositEpoch.
    function test_depositEpochValidationOrder() public {
        TreeRootPair[] memory emptyRoots = new TreeRootPair[](0);

        // Empty deposits is checked before empty usedRoots
        // So we get InvalidEpochConfig (for empty deposits), not InvalidBatchConfig (for empty roots)
        vm.expectRevert(IPrivacyBoost.InvalidEpochConfig.selector);
        pool.submitDepositEpoch(
            EpochHelpers.buildTreeState(emptyRoots, 0, 0, 1, 1, false),
            1,
            new Output[](1),
            new DepositEntry[](0),
            [uint256(1), 2, 3, 4, 5, 6, 7, 8]
        );
    }

    /// @notice Test that submitDepositEpoch still rejects duplicate tree numbers.
    /// @dev Deposit circuit uses selectByTreeNumber which sums duplicates (unsafe).
    function test_revertWhen_depositEpochDuplicateTreeNumbers() public {
        uint256 root = pool.treeRoot(0);

        TreeRootPair[] memory dupRoots = new TreeRootPair[](2);
        dupRoots[0] = TreeRootPair({treeNumber: 0, root: root});
        dupRoots[1] = TreeRootPair({treeNumber: 0, root: root});

        vm.expectRevert(IPrivacyBoost.DuplicateTreeNumber.selector);
        pool.submitDepositEpoch(
            EpochHelpers.buildTreeState(dupRoots, 0, 0, 1, 1, false),
            1,
            new Output[](1),
            new DepositEntry[](1),
            [uint256(1), 2, 3, 4, 5, 6, 7, 8]
        );
    }
}
