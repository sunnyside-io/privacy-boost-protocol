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
import {Output, Transfer, Withdrawal, EpochTreeState, TreeRootPair, GatewaySlot} from "src/interfaces/IStructs.sol";
import {MockVerifier, MockAuthRegistry} from "test/helpers/Mocks.sol";
import {PoolDeployer, DeployConfig} from "test/helpers/PoolDeployer.sol";
import {EpochHelpers} from "test/helpers/EpochHelpers.sol";

/// @notice Tests for PrivacyBoost multi-tree state management
contract MultiTreeRootsTest is Test {
    PrivacyBoost pool;
    TokenRegistry tokenRegistry;
    MockAuthRegistry authRegistry;
    MockVerifier verifier;

    address owner = address(this);
    address proxyAdmin = address(0xAD); // Separate proxy admin to avoid TransparentProxy routing issue
    address operator = makeAddr("operator");

    function setUp() public {
        verifier = new MockVerifier();
        authRegistry = new MockAuthRegistry();
        DeployConfig memory cfg = PoolDeployer.defaultConfig(owner, proxyAdmin, address(verifier));
        cfg.batchSize = 1;
        cfg.maxFeeTokens = 1;
        cfg.maxForcedInputs = 1;
        (pool, tokenRegistry) = PoolDeployer.deployWithMockAuth(cfg, address(authRegistry));
        pool.setOperator(operator);
    }

    /// @dev Submit a basic single-transfer epoch with auth root (treeNumber 0, root 1) known to MockAuthRegistry.
    function _submitBasicEpoch(EpochTreeState memory treeState, uint256[] memory nullifiers) internal {
        pool.submitEpoch(
            treeState,
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

    /// @notice Test initial multi-tree state
    function test_initialMultiTreeState() public view {
        // currentTreeNumber starts at 0
        assertEq(pool.currentTreeNumber(), 0, "Should start at tree 0");

        // Tree 0 has initial empty tree root (Poseidon hash of empty tree)
        uint256 tree0Root = pool.treeRoot(0);
        assertGt(tree0Root, 0, "Tree 0 should have non-zero initial root (empty tree hash)");
        assertEq(pool.treeCount(0), 0, "Tree 0 count should be 0");

        // Tree 1 not used yet
        assertEq(pool.treeRoot(1), 0, "Tree 1 root should be 0 (unused)");
        assertEq(pool.treeCount(1), 0, "Tree 1 count should be 0");
    }

    /// @notice Test isKnownTreeRoot validates initial empty tree root
    function test_isKnownTreeRoot_initialRoot() public view {
        uint256 emptyTreeRoot = pool.treeRoot(0);

        // Initial root should be known in tree 0
        assertTrue(pool.isKnownTreeRoot(0, emptyTreeRoot), "Empty tree root should be known in tree 0");

        // But NOT known in tree 1 (different tree)
        assertFalse(pool.isKnownTreeRoot(1, emptyTreeRoot), "Tree 0 root should NOT be known in tree 1");
    }

    /// @notice Test isKnownTreeRoot returns false for random roots
    function test_isKnownTreeRoot_unknownRoot() public view {
        uint256 randomRoot = 12345;
        assertFalse(pool.isKnownTreeRoot(0, randomRoot), "Random root should not be known in tree 0");
        assertFalse(pool.isKnownTreeRoot(1, randomRoot), "Random root should not be known in tree 1");
    }

    /// @notice Test that different trees have independent state
    function test_treesAreIndependent() public view {
        uint256 root0 = pool.treeRoot(0);
        uint256 root1 = pool.treeRoot(1);

        // Tree 0 has empty tree root, tree 1 is unused (0)
        assertGt(root0, 0, "Tree 0 has initial root");
        assertEq(root1, 0, "Tree 1 is unused");
        assertTrue(root0 != root1, "Different trees have different roots");
    }

    /// @notice Test that unused trees with non-zero root in usedRoots are rejected
    function test_unusedTreesMustHaveZeroRoot() public {
        // Setup: allow this contract as relay
        address[] memory relays = new address[](1);
        relays[0] = address(this);
        vm.prank(operator);
        pool.setAllowedRelays(relays, true);

        // Include an invalid tree 1 with fake root
        TreeRootPair[] memory usedRoots = new TreeRootPair[](2);
        usedRoots[0] = TreeRootPair({treeNumber: 0, root: pool.treeRoot(0)});
        usedRoots[1] = TreeRootPair({treeNumber: 1, root: 12345}); // INVALID: unused tree

        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = 1;

        // This should revert because tree 1 root is not known
        vm.expectRevert(IPrivacyBoost.RootNotKnown.selector);
        _submitBasicEpoch(EpochHelpers.buildTreeState(usedRoots, 0, 0, 1, 2, false), nullifiers);
    }

    /// @notice Test that valid usedRoots with only active tree passes the root validation
    /// @dev With MockVerifier always returning true, the entire tx succeeds if root validation passes
    function test_validKnownRootsWithZeroUnusedTrees() public {
        // Setup: allow this contract as relay
        address[] memory relays = new address[](1);
        relays[0] = address(this);
        vm.prank(operator);
        pool.setAllowedRelays(relays, true);

        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = 1;

        // With MockVerifier returning true, this should succeed entirely
        _submitBasicEpoch(
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, pool.treeRoot(0)), 0, 0, 1, 2, false), nullifiers
        );

        // Verify state was updated (proof that tx succeeded)
        assertEq(pool.treeRoot(0), 1, "Root should be updated to new value");
        assertEq(pool.treeCount(0), 2, "Count should be updated");
    }

    /// @notice Test EpochSubmitted event includes treeNumber
    function test_epochSubmittedEventIncludesTreeNumber() public {
        // Setup
        address[] memory relays = new address[](1);
        relays[0] = address(this);
        vm.prank(operator);
        pool.setAllowedRelays(relays, true);

        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = 1;

        // Expect EpochSubmitted event with treeNum=0, rootNew=1, countOld=0, countNew=2
        vm.expectEmit(true, true, true, true);
        emit IPrivacyBoost.EpochSubmitted(0, 1, 0, 2);

        _submitBasicEpoch(
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, pool.treeRoot(0)), 0, 0, 1, 2, false), nullifiers
        );
    }

    // ========== Coverage Tests: Rollover Logic (Lines 307-308, 858-869) ==========

    /// @notice Test submitEpoch with rollover=true (Lines 307-308, 858-869)
    function test_submitEpoch_withRollover() public {
        // Setup relay
        address[] memory relays = new address[](1);
        relays[0] = address(this);
        vm.prank(operator);
        pool.setAllowedRelays(relays, true);

        // Set up tree at max capacity using vm.store
        // Storage layout: treeRoot=slot7, treeCount=slot8, treeRootHistory=slot9, treeRootHistoryCursor=slot10
        // (slots shifted by 1 after operator was added; giftClaimVerifier is appended at the end so it does not shift these)
        uint8 MERKLE_DEPTH = 20;
        uint32 MAX_LEAVES = uint32(1 << MERKLE_DEPTH);

        // Set treeCount[0] = MAX_LEAVES
        bytes32 treeCountSlot = keccak256(abi.encode(uint256(0), uint256(8)));
        vm.store(address(pool), treeCountSlot, bytes32(uint256(MAX_LEAVES)));

        // Set treeRoot[0] to a valid root for the full tree
        bytes32 treeRootSlot = keccak256(abi.encode(uint256(0), uint256(7)));
        uint256 fullTreeRoot = 0xF011EEEE;
        vm.store(address(pool), treeRootSlot, bytes32(fullTreeRoot));

        // Set treeRootHistoryCursor[0] = 1
        bytes32 treeRootHistoryCursorSlot = keccak256(abi.encode(uint256(0), uint256(10)));
        vm.store(address(pool), treeRootHistoryCursorSlot, bytes32(uint256(1)));

        // Set treeRootHistory[0][1] = fullTreeRoot
        bytes32 baseArraySlot = keccak256(abi.encode(uint256(0), uint256(9)));
        vm.store(address(pool), bytes32(uint256(baseArraySlot) + 1), bytes32(fullTreeRoot));

        // Verify setup
        assertEq(pool.treeCount(0), MAX_LEAVES);
        assertEq(pool.treeRoot(0), fullTreeRoot);
        assertEq(pool.currentTreeNumber(), 0);

        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = 1001;

        uint256 newRoot = 0x1234ABCD;
        uint32 newCount = 2; // 1 output + 1 fee

        // Expect TreeAdvanced event (Line 869)
        vm.expectEmit(true, true, false, true);
        emit IPrivacyBoost.TreeAdvanced(0, 1);

        // Expect EpochSubmitted event with new tree number (Lines 307-308)
        vm.expectEmit(true, true, true, true);
        emit IPrivacyBoost.EpochSubmitted(1, newRoot, 0, newCount);

        _submitBasicEpoch(
            EpochHelpers.buildTreeState(
                EpochHelpers.buildUsedRoots(0, fullTreeRoot), 0, MAX_LEAVES, newRoot, newCount, true
            ),
            nullifiers
        );

        // Verify tree advanced
        assertEq(pool.currentTreeNumber(), 1, "Tree should advance to 1");
        assertEq(pool.treeRoot(1), newRoot, "New tree should have new root");
        assertEq(pool.treeCount(1), newCount, "New tree should have correct count");
    }

    /// @notice Test isKnownTreeRoot for finalized (past) tree (Line 689)
    function test_isKnownTreeRoot_finalizedTree() public {
        // Setup relay
        address[] memory relays = new address[](1);
        relays[0] = address(this);
        vm.prank(operator);
        pool.setAllowedRelays(relays, true);

        // Set up tree 0 at max capacity
        // Storage layout: treeRoot=slot7, treeCount=slot8, treeRootHistory=slot9, treeRootHistoryCursor=slot10
        uint8 MERKLE_DEPTH = 20;
        uint32 MAX_LEAVES = uint32(1 << MERKLE_DEPTH);

        bytes32 treeCountSlot = keccak256(abi.encode(uint256(0), uint256(8)));
        vm.store(address(pool), treeCountSlot, bytes32(uint256(MAX_LEAVES)));

        bytes32 treeRootSlot = keccak256(abi.encode(uint256(0), uint256(7)));
        uint256 tree0FinalRoot = 0xEEE0F1A1;
        vm.store(address(pool), treeRootSlot, bytes32(tree0FinalRoot));

        bytes32 treeRootHistoryCursorSlot = keccak256(abi.encode(uint256(0), uint256(10)));
        vm.store(address(pool), treeRootHistoryCursorSlot, bytes32(uint256(1)));

        bytes32 baseArraySlot = keccak256(abi.encode(uint256(0), uint256(9)));
        vm.store(address(pool), bytes32(uint256(baseArraySlot) + 1), bytes32(tree0FinalRoot));

        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = 6001;

        // Do rollover to advance to tree 1
        _submitBasicEpoch(
            EpochHelpers.buildTreeState(
                EpochHelpers.buildUsedRoots(0, tree0FinalRoot), 0, MAX_LEAVES, 0xEEE10001, 2, true
            ),
            nullifiers
        );

        // Now tree 0 is finalized
        assertEq(pool.currentTreeNumber(), 1, "Current tree should be 1");

        // Check isKnownTreeRoot for finalized tree (Line 689)
        // For finalized trees, only the final root is valid
        assertTrue(pool.isKnownTreeRoot(0, tree0FinalRoot), "Final root of tree 0 should be known");

        // Random root should not be known
        assertFalse(pool.isKnownTreeRoot(0, 0xAABBCCDD), "Random root should not be known in finalized tree");
    }

    /// @notice Test isKnownTreeRoot returns false after history exhaustion (Line 701)
    function test_isKnownTreeRoot_exhaustsHistoryReturnsFalse() public {
        // Setup relay
        address[] memory relays = new address[](1);
        relays[0] = address(this);
        vm.prank(operator);
        pool.setAllowedRelays(relays, true);

        // Submit 129 epochs to fill history (ROOT_HISTORY_SIZE = 128)
        // First root will be evicted after the 129th submission
        for (uint256 i = 0; i < 129; i++) {
            uint256[] memory nullifiers = new uint256[](1);
            nullifiers[0] = 10000 + i;

            uint256 newRoot = 0x1000000 + i;
            uint32 countOld = pool.treeCount(0);

            _submitBasicEpoch(
                EpochHelpers.buildTreeState(
                    EpochHelpers.buildUsedRoots(0, pool.treeRoot(0)), 0, countOld, newRoot, countOld + 2, false
                ),
                nullifiers
            );
        }

        // First root (0x1000000) should be evicted from history
        uint256 evictedRoot = 0x1000000;
        assertFalse(pool.isKnownTreeRoot(0, evictedRoot), "Evicted root should not be known");

        // Recent roots should still be known
        uint256 recentRoot = 0x1000000 + 128;
        assertTrue(pool.isKnownTreeRoot(0, recentRoot), "Recent root should be known");
    }
}
