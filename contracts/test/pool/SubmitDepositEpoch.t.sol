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
import {MockERC20, MockVerifier} from "test/helpers/Mocks.sol";
import {PoolDeployer, DeployConfig} from "test/helpers/PoolDeployer.sol";
import {EpochHelpers} from "test/helpers/EpochHelpers.sol";

import {PrivacyBoost} from "src/PrivacyBoost.sol";
import {IPrivacyBoost} from "src/interfaces/IPrivacyBoost.sol";
import {TokenRegistry} from "src/TokenRegistry.sol";
import {AuthRegistry} from "src/AuthRegistry.sol";
import {LibDigest} from "src/lib/LibDigest.sol";
import {Output, DepositEntry, DepositCiphertext, EpochTreeState, TreeRootPair} from "src/interfaces/IStructs.sol";
import {TOKEN_TYPE_ERC20} from "src/interfaces/Constants.sol";

contract SubmitDepositEpochTest is Test {
    PrivacyBoost pool;
    TokenRegistry tokenRegistry;
    AuthRegistry authRegistry;
    MockVerifier verifier;
    MockERC20 token;

    address owner = address(this);
    address proxyAdmin = address(0xAD);
    address relay = makeAddr("relay");
    address alice = makeAddr("alice");
    address operator = makeAddr("operator");

    uint16 tokenId;
    uint256[8] dummyProof;

    function setUp() public {
        verifier = new MockVerifier();
        DeployConfig memory cfg = PoolDeployer.defaultConfig(owner, proxyAdmin, address(verifier));
        (pool, tokenRegistry, authRegistry) = PoolDeployer.deployFullStack(cfg);
        token = new MockERC20();
        tokenId = tokenRegistry.register(TOKEN_TYPE_ERC20, address(token), 0);
        pool.setOperator(operator);
        address[] memory relays = new address[](1);
        relays[0] = relay;
        vm.prank(operator);
        pool.setAllowedRelays(relays, true);
        token.mint(alice, 100_000 ether);
        vm.prank(alice);
        token.approve(address(pool), type(uint256).max);
    }

    function _dummyCiphertext() internal pure returns (DepositCiphertext memory) {
        return DepositCiphertext({
            viewingKey: bytes32(uint256(1)),
            teeWrapKey: bytes32(uint256(2)),
            receiverWrapKey: bytes32(uint256(3)),
            ct0: bytes32(uint256(4)),
            ct1: bytes32(uint256(5)),
            ct2: bytes16(uint128(6))
        });
    }

    function _dummyOutput(uint256 commitment) internal pure returns (Output memory) {
        return Output({
            commitment: commitment,
            receiverWrapKey: bytes32(uint256(3)),
            ct0: bytes32(uint256(4)),
            ct1: bytes32(uint256(5)),
            ct2: bytes32(uint256(6)),
            ct3: bytes16(uint128(7))
        });
    }

    function _getUsedRoots(uint256 treeNum) internal view returns (TreeRootPair[] memory) {
        TreeRootPair[] memory roots = new TreeRootPair[](1);
        roots[0] = TreeRootPair({treeNumber: treeNum, root: pool.treeRoot(treeNum)});
        return roots;
    }

    // ========== Happy Path ==========

    function test_submitDepositEpoch_singleRequest_singleCommitment() public {
        // Request deposit
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = 12345;
        DepositCiphertext[] memory cts = new DepositCiphertext[](1);
        cts[0] = _dummyCiphertext();

        vm.prank(alice);
        uint256 reqId = pool.requestDeposit(tokenId, 1000 ether, commitments, cts);

        // Submit deposit epoch
        TreeRootPair[] memory usedRoots = _getUsedRoots(0);
        uint32 countOld = pool.treeCount(0);

        Output[] memory outputs = new Output[](1);
        outputs[0] = _dummyOutput(commitments[0]);

        DepositEntry[] memory deposits = new DepositEntry[](1);
        deposits[0] = DepositEntry({depositRequestId: reqId});

        vm.prank(relay);
        pool.submitDepositEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0xABCD, countOld + 1, false),
            1, // nTotalCommitments
            outputs,
            deposits,
            dummyProof
        );

        // Verify deposit is processed
        assertTrue(pool.processedDeposits(reqId));
        assertEq(pool.treeCount(0), countOld + 1);
    }

    function test_submitDepositEpoch_singleRequest_multipleCommitments() public {
        // Request deposit with 3 commitments
        uint256[] memory commitments = new uint256[](3);
        commitments[0] = 100;
        commitments[1] = 200;
        commitments[2] = 300;
        DepositCiphertext[] memory cts = new DepositCiphertext[](3);
        for (uint256 i = 0; i < 3; i++) {
            cts[i] = _dummyCiphertext();
        }

        vm.prank(alice);
        uint256 reqId = pool.requestDeposit(tokenId, 3000 ether, commitments, cts);

        // Submit deposit epoch
        TreeRootPair[] memory usedRoots = _getUsedRoots(0);
        uint32 countOld = pool.treeCount(0);

        Output[] memory outputs = new Output[](3);
        outputs[0] = _dummyOutput(commitments[0]);
        outputs[1] = _dummyOutput(commitments[1]);
        outputs[2] = _dummyOutput(commitments[2]);

        DepositEntry[] memory deposits = new DepositEntry[](1);
        deposits[0] = DepositEntry({depositRequestId: reqId});

        vm.prank(relay);
        pool.submitDepositEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0xABCD, countOld + 3, false),
            3, // nTotalCommitments
            outputs,
            deposits,
            dummyProof
        );

        assertTrue(pool.processedDeposits(reqId));
        assertEq(pool.treeCount(0), countOld + 3);
    }

    function test_submitDepositEpoch_multipleRequests() public {
        // Request 1: 2 commitments
        uint256[] memory commitments1 = new uint256[](2);
        commitments1[0] = 100;
        commitments1[1] = 200;
        DepositCiphertext[] memory cts1 = new DepositCiphertext[](2);
        cts1[0] = _dummyCiphertext();
        cts1[1] = _dummyCiphertext();

        vm.prank(alice);
        uint256 reqId1 = pool.requestDeposit(tokenId, 1000 ether, commitments1, cts1);

        // Request 2: 1 commitment
        uint256[] memory commitments2 = new uint256[](1);
        commitments2[0] = 300;
        DepositCiphertext[] memory cts2 = new DepositCiphertext[](1);
        cts2[0] = _dummyCiphertext();

        vm.prank(alice);
        uint256 reqId2 = pool.requestDeposit(tokenId, 500 ether, commitments2, cts2);

        // Submit deposit epoch with both requests
        TreeRootPair[] memory usedRoots = _getUsedRoots(0);
        uint32 countOld = pool.treeCount(0);

        // Outputs ordered: request1's commitments, then request2's commitments
        Output[] memory outputs = new Output[](3);
        outputs[0] = _dummyOutput(commitments1[0]);
        outputs[1] = _dummyOutput(commitments1[1]);
        outputs[2] = _dummyOutput(commitments2[0]);

        DepositEntry[] memory deposits = new DepositEntry[](2);
        deposits[0] = DepositEntry({depositRequestId: reqId1});
        deposits[1] = DepositEntry({depositRequestId: reqId2});

        vm.prank(relay);
        pool.submitDepositEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0xABCD, countOld + 3, false),
            3, // nTotalCommitments = 2 + 1
            outputs,
            deposits,
            dummyProof
        );

        assertTrue(pool.processedDeposits(reqId1));
        assertTrue(pool.processedDeposits(reqId2));
        assertEq(pool.treeCount(0), countOld + 3);
    }

    // ========== Error Cases ==========

    function test_revertWhen_commitmentsHashMismatch() public {
        // Request deposit
        uint256[] memory commitments = new uint256[](2);
        commitments[0] = 100;
        commitments[1] = 200;
        DepositCiphertext[] memory cts = new DepositCiphertext[](2);
        cts[0] = _dummyCiphertext();
        cts[1] = _dummyCiphertext();

        vm.prank(alice);
        uint256 reqId = pool.requestDeposit(tokenId, 1000 ether, commitments, cts);

        // Submit with WRONG commitments order
        TreeRootPair[] memory usedRoots = _getUsedRoots(0);
        uint32 countOld = pool.treeCount(0);

        Output[] memory outputs = new Output[](2);
        outputs[0] = _dummyOutput(200); // Wrong order!
        outputs[1] = _dummyOutput(100);

        DepositEntry[] memory deposits = new DepositEntry[](1);
        deposits[0] = DepositEntry({depositRequestId: reqId});

        vm.prank(relay);
        vm.expectRevert(IPrivacyBoost.InvalidDeposit.selector);
        pool.submitDepositEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0xABCD, countOld + 2, false),
            2,
            outputs,
            deposits,
            dummyProof
        );
    }

    function test_revertWhen_depositAlreadyProcessed() public {
        // Request and process deposit
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = 12345;
        DepositCiphertext[] memory cts = new DepositCiphertext[](1);
        cts[0] = _dummyCiphertext();

        vm.prank(alice);
        uint256 reqId = pool.requestDeposit(tokenId, 1000 ether, commitments, cts);

        TreeRootPair[] memory usedRoots = _getUsedRoots(0);
        uint32 countOld = pool.treeCount(0);

        Output[] memory outputs = new Output[](1);
        outputs[0] = _dummyOutput(commitments[0]);

        DepositEntry[] memory deposits = new DepositEntry[](1);
        deposits[0] = DepositEntry({depositRequestId: reqId});

        vm.prank(relay);
        pool.submitDepositEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0xABCD, countOld + 1, false),
            1,
            outputs,
            deposits,
            dummyProof
        );

        // Try to process again
        usedRoots = _getUsedRoots(0);
        countOld = pool.treeCount(0);

        vm.prank(relay);
        vm.expectRevert(IPrivacyBoost.DepositAlreadyProcessed.selector);
        pool.submitDepositEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0xDEAD, countOld + 1, false),
            1,
            outputs,
            deposits,
            dummyProof
        );
    }

    function test_revertWhen_duplicateRequestIdInSameBatch() public {
        // Request a single deposit
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = 77777;
        DepositCiphertext[] memory cts = new DepositCiphertext[](1);
        cts[0] = _dummyCiphertext();

        vm.prank(alice);
        uint256 reqId = pool.requestDeposit(tokenId, 1000 ether, commitments, cts);

        TreeRootPair[] memory usedRoots = _getUsedRoots(0);
        uint32 countOld = pool.treeCount(0);

        // Duplicate the same commitment in outputs (attacker tries to mint twice)
        Output[] memory outputs = new Output[](2);
        outputs[0] = _dummyOutput(commitments[0]);
        outputs[1] = _dummyOutput(commitments[0]);

        // Include the same requestId TWICE in the batch
        DepositEntry[] memory deposits = new DepositEntry[](2);
        deposits[0] = DepositEntry({depositRequestId: reqId});
        deposits[1] = DepositEntry({depositRequestId: reqId}); // Duplicate!

        // Should revert on second iteration when reqId is already marked processed
        vm.prank(relay);
        vm.expectRevert(IPrivacyBoost.DepositAlreadyProcessed.selector);
        pool.submitDepositEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0xABCD, countOld + 2, false),
            2,
            outputs,
            deposits,
            dummyProof
        );
    }

    function test_revertWhen_depositNotFound() public {
        TreeRootPair[] memory usedRoots = _getUsedRoots(0);
        uint32 countOld = pool.treeCount(0);

        Output[] memory outputs = new Output[](1);
        outputs[0] = _dummyOutput(12345);

        DepositEntry[] memory deposits = new DepositEntry[](1);
        deposits[0] = DepositEntry({depositRequestId: 999999}); // Non-existent

        vm.prank(relay);
        vm.expectRevert(IPrivacyBoost.InvalidDeposit.selector);
        pool.submitDepositEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0xABCD, countOld + 1, false),
            1,
            outputs,
            deposits,
            dummyProof
        );
    }

    function test_revertWhen_notRelay() public {
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = 12345;
        DepositCiphertext[] memory cts = new DepositCiphertext[](1);
        cts[0] = _dummyCiphertext();

        vm.prank(alice);
        uint256 reqId = pool.requestDeposit(tokenId, 1000 ether, commitments, cts);

        TreeRootPair[] memory usedRoots = _getUsedRoots(0);
        uint32 countOld = pool.treeCount(0);

        Output[] memory outputs = new Output[](1);
        outputs[0] = _dummyOutput(commitments[0]);

        DepositEntry[] memory deposits = new DepositEntry[](1);
        deposits[0] = DepositEntry({depositRequestId: reqId});

        vm.prank(alice); // Not a relay
        vm.expectRevert(IPrivacyBoost.NotAllowedRelay.selector);
        pool.submitDepositEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0xABCD, countOld + 1, false),
            1,
            outputs,
            deposits,
            dummyProof
        );
    }

    function test_revertWhen_wrongTreeState() public {
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = 12345;
        DepositCiphertext[] memory cts = new DepositCiphertext[](1);
        cts[0] = _dummyCiphertext();

        vm.prank(alice);
        uint256 reqId = pool.requestDeposit(tokenId, 1000 ether, commitments, cts);

        TreeRootPair[] memory usedRoots = _getUsedRoots(0);

        Output[] memory outputs = new Output[](1);
        outputs[0] = _dummyOutput(commitments[0]);

        DepositEntry[] memory deposits = new DepositEntry[](1);
        deposits[0] = DepositEntry({depositRequestId: reqId});

        vm.prank(relay);
        vm.expectRevert(IPrivacyBoost.InvalidEpochState.selector);
        pool.submitDepositEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, 999, 0xABCD, 1000, false), 1, outputs, deposits, dummyProof
        );
    }

    function test_revertWhen_duplicateTreeNumberInUsedRoots() public {
        // Request deposit
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = 424242;
        DepositCiphertext[] memory cts = new DepositCiphertext[](1);
        cts[0] = _dummyCiphertext();

        vm.prank(alice);
        uint256 reqId = pool.requestDeposit(tokenId, 1000 ether, commitments, cts);

        uint32 countOld = pool.treeCount(0);
        uint256 rootVal = pool.treeRoot(0);

        // Duplicate tree number in sparse usedRoots should be rejected.
        TreeRootPair[] memory usedRoots = new TreeRootPair[](2);
        usedRoots[0] = TreeRootPair({treeNumber: 0, root: rootVal});
        usedRoots[1] = TreeRootPair({treeNumber: 0, root: rootVal});

        Output[] memory outputs = new Output[](1);
        outputs[0] = _dummyOutput(commitments[0]);

        DepositEntry[] memory deposits = new DepositEntry[](1);
        deposits[0] = DepositEntry({depositRequestId: reqId});

        vm.prank(relay);
        vm.expectRevert(IPrivacyBoost.DuplicateTreeNumber.selector);
        pool.submitDepositEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0xABCD, countOld + 1, false),
            1,
            outputs,
            deposits,
            dummyProof
        );
    }

    function test_revertWhen_nTotalCommitmentsMismatch() public {
        // Request deposit with 2 commitments
        uint256[] memory commitments = new uint256[](2);
        commitments[0] = 100;
        commitments[1] = 200;
        DepositCiphertext[] memory cts = new DepositCiphertext[](2);
        cts[0] = _dummyCiphertext();
        cts[1] = _dummyCiphertext();

        vm.prank(alice);
        uint256 reqId = pool.requestDeposit(tokenId, 1000 ether, commitments, cts);

        TreeRootPair[] memory usedRoots = _getUsedRoots(0);
        uint32 countOld = pool.treeCount(0);

        Output[] memory outputs = new Output[](2);
        outputs[0] = _dummyOutput(commitments[0]);
        outputs[1] = _dummyOutput(commitments[1]);

        DepositEntry[] memory deposits = new DepositEntry[](1);
        deposits[0] = DepositEntry({depositRequestId: reqId});

        vm.prank(relay);
        vm.expectRevert(IPrivacyBoost.InvalidArrayLengths.selector);
        pool.submitDepositEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0xABCD, countOld + 1, false),
            1, // Wrong! Should be 2
            outputs,
            deposits,
            dummyProof
        );
    }

    // ========== Tree State Updates ==========

    function test_treeRootUpdated() public {
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = 12345;
        DepositCiphertext[] memory cts = new DepositCiphertext[](1);
        cts[0] = _dummyCiphertext();

        vm.prank(alice);
        uint256 reqId = pool.requestDeposit(tokenId, 1000 ether, commitments, cts);

        TreeRootPair[] memory usedRoots = _getUsedRoots(0);
        uint32 countOld = pool.treeCount(0);
        uint256 newRoot = 0xDEADBEEF;

        Output[] memory outputs = new Output[](1);
        outputs[0] = _dummyOutput(commitments[0]);

        DepositEntry[] memory deposits = new DepositEntry[](1);
        deposits[0] = DepositEntry({depositRequestId: reqId});

        vm.prank(relay);
        pool.submitDepositEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, newRoot, countOld + 1, false),
            1,
            outputs,
            deposits,
            dummyProof
        );

        assertEq(pool.treeRoot(0), newRoot);
    }

    function test_commitmentsHashVerification() public {
        // This test verifies the sequential hash computation matches
        uint256[] memory commitments = new uint256[](3);
        commitments[0] = 111;
        commitments[1] = 222;
        commitments[2] = 333;
        DepositCiphertext[] memory cts = new DepositCiphertext[](3);
        for (uint256 i = 0; i < 3; i++) {
            cts[i] = _dummyCiphertext();
        }

        vm.prank(alice);
        uint256 reqId = pool.requestDeposit(tokenId, 3000 ether, commitments, cts);

        // Verify stored hash
        (,,,,, uint16 commitmentCount, uint256 storedHash,) = pool.pendingDeposits(reqId);
        assertEq(commitmentCount, 3);

        // Compute expected hash
        uint256 expectedHash = LibDigest.computeCommitmentsHash(commitments);
        assertEq(storedHash, expectedHash);

        // Submit should succeed with correct order
        TreeRootPair[] memory usedRoots = _getUsedRoots(0);
        uint32 countOld = pool.treeCount(0);

        Output[] memory outputs = new Output[](3);
        outputs[0] = _dummyOutput(111);
        outputs[1] = _dummyOutput(222);
        outputs[2] = _dummyOutput(333);

        DepositEntry[] memory deposits = new DepositEntry[](1);
        deposits[0] = DepositEntry({depositRequestId: reqId});

        vm.prank(relay);
        pool.submitDepositEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0xABCD, countOld + 3, false),
            3,
            outputs,
            deposits,
            dummyProof
        );

        assertTrue(pool.processedDeposits(reqId));
    }

    // ========== Coverage Tests: View Functions (processedDeposits) ==========

    /// @notice Test processedDeposits returns false for non-existent deposit
    function test_processedDeposits_returnsFalse_whenNotProcessed() public view {
        assertFalse(pool.processedDeposits(12345));
        assertFalse(pool.processedDeposits(0));
        assertFalse(pool.processedDeposits(type(uint256).max));
    }

    /// @notice Test processedDeposits returns true after processing
    function test_processedDeposits_returnsTrue_afterProcessing() public {
        // Request deposit
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = 99999;
        DepositCiphertext[] memory cts = new DepositCiphertext[](1);
        cts[0] = _dummyCiphertext();

        vm.prank(alice);
        uint256 reqId = pool.requestDeposit(tokenId, 1000 ether, commitments, cts);

        // Not processed yet
        assertFalse(pool.processedDeposits(reqId));

        // Process deposit
        TreeRootPair[] memory usedRoots = _getUsedRoots(0);
        uint32 countOld = pool.treeCount(0);

        Output[] memory outputs = new Output[](1);
        outputs[0] = _dummyOutput(commitments[0]);

        DepositEntry[] memory deposits = new DepositEntry[](1);
        deposits[0] = DepositEntry({depositRequestId: reqId});

        vm.prank(relay);
        pool.submitDepositEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0xABCD, countOld + 1, false),
            1,
            outputs,
            deposits,
            dummyProof
        );

        // Now processed
        assertTrue(pool.processedDeposits(reqId));
    }

    // ========== Coverage Tests: Cancel Deposit After Processed (Line 393) ==========

    /// @notice Test DepositAlreadyProcessed in cancelDeposit (Line 393)
    function test_revertWhen_cancelDeposit_afterProcessed() public {
        // Request deposit
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = 55555;
        DepositCiphertext[] memory cts = new DepositCiphertext[](1);
        cts[0] = _dummyCiphertext();

        vm.prank(alice);
        uint256 reqId = pool.requestDeposit(tokenId, 1000 ether, commitments, cts);

        // Process deposit
        TreeRootPair[] memory usedRoots = _getUsedRoots(0);
        uint32 countOld = pool.treeCount(0);

        Output[] memory outputs = new Output[](1);
        outputs[0] = _dummyOutput(commitments[0]);

        DepositEntry[] memory deposits = new DepositEntry[](1);
        deposits[0] = DepositEntry({depositRequestId: reqId});

        vm.prank(relay);
        pool.submitDepositEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0xABCD, countOld + 1, false),
            1,
            outputs,
            deposits,
            dummyProof
        );

        // Wait for cancel delay
        vm.roll(block.number + pool.cancelDelay() + 1);

        // Try to cancel already processed deposit
        vm.prank(alice);
        vm.expectRevert(IPrivacyBoost.DepositAlreadyProcessed.selector);
        pool.cancelDeposit(reqId);
    }

    // ========== Coverage Tests: Deposit Epoch Rollover (Lines 509-510) ==========

    /// @notice Test submitDepositEpoch with rollover=true (Lines 509-510)
    function test_submitDepositEpoch_withRollover() public {
        // Request deposit first
        uint256[] memory commitments = new uint256[](2);
        commitments[0] = 5001;
        commitments[1] = 5002;
        DepositCiphertext[] memory cts = new DepositCiphertext[](2);
        cts[0] = _dummyCiphertext();
        cts[1] = _dummyCiphertext();

        vm.prank(alice);
        uint256 reqId = pool.requestDeposit(tokenId, 2000 ether, commitments, cts);

        // Set up tree at max capacity using vm.store
        // Storage layout: treeRoot=slot7, treeCount=slot8, treeRootHistory=slot9, treeRootHistoryCursor=slot10
        // (slots shifted by 1 after operator was added; giftClaimVerifier is appended at the end so it does not shift these)
        uint8 MERKLE_DEPTH = 20;
        uint32 MAX_LEAVES = uint32(1 << MERKLE_DEPTH);

        // Set treeCount[0] = MAX_LEAVES
        bytes32 treeCountSlot = keccak256(abi.encode(uint256(0), uint256(8)));
        vm.store(address(pool), treeCountSlot, bytes32(uint256(MAX_LEAVES)));

        // Set treeRoot[0] to a valid root
        bytes32 treeRootSlot = keccak256(abi.encode(uint256(0), uint256(7)));
        uint256 fullTreeRoot = 0xF011EEEE2;
        vm.store(address(pool), treeRootSlot, bytes32(fullTreeRoot));

        // Set treeRootHistoryCursor[0] = 1
        bytes32 treeRootHistoryCursorSlot = keccak256(abi.encode(uint256(0), uint256(10)));
        vm.store(address(pool), treeRootHistoryCursorSlot, bytes32(uint256(1)));

        // Set treeRootHistory[0][1] = fullTreeRoot
        bytes32 baseArraySlot = keccak256(abi.encode(uint256(0), uint256(9)));
        vm.store(address(pool), bytes32(uint256(baseArraySlot) + 1), bytes32(fullTreeRoot));

        // Verify setup
        assertEq(pool.treeCount(0), MAX_LEAVES);

        TreeRootPair[] memory usedRoots = new TreeRootPair[](1);
        usedRoots[0] = TreeRootPair({treeNumber: 0, root: fullTreeRoot});

        Output[] memory outputs = new Output[](2);
        outputs[0] = _dummyOutput(commitments[0]);
        outputs[1] = _dummyOutput(commitments[1]);

        DepositEntry[] memory deposits = new DepositEntry[](1);
        deposits[0] = DepositEntry({depositRequestId: reqId});

        uint256 newRoot = 0xDE90510000;

        // Expect TreeAdvanced event
        vm.expectEmit(true, true, false, true);
        emit IPrivacyBoost.TreeAdvanced(0, 1);

        // Expect DepositEpochSubmitted event with new tree number (Lines 509-510)
        vm.expectEmit(true, true, true, true);
        emit IPrivacyBoost.DepositEpochSubmitted(1, newRoot, 0, 2);

        vm.prank(relay);
        pool.submitDepositEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, MAX_LEAVES, newRoot, 2, true), 2, outputs, deposits, dummyProof
        );

        // Verify tree advanced
        assertEq(pool.currentTreeNumber(), 1, "Tree should advance to 1");
        assertEq(pool.treeRoot(1), newRoot, "New tree should have new root");
        assertEq(pool.treeCount(1), 2, "New tree should have correct count");
    }
}
