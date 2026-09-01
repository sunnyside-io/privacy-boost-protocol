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

import {LibPublicInputs} from "src/lib/LibPublicInputs.sol";
import {EpochTreeState, TreeRootPair} from "src/interfaces/IStructs.sol";
import {IPrivacyBoost} from "src/interfaces/IPrivacyBoost.sol";
import {WITHDRAWAL_MASK_BITS_PER_WORD} from "src/interfaces/Constants.sol";

// Test wrapper to expose internal library functions with calldata
contract LibPublicInputsWrapper {
    function sparseToPackedRootsWithTreeNumbers(TreeRootPair[] calldata sparse)
        external
        pure
        returns (uint256[16] memory packedRoots, uint256 packedTreeNumbers)
    {
        return LibPublicInputs.sparseToPackedRootsWithTreeNumbers(sparse);
    }

    function sparseToPackedAuthRootsWithTreeNumbers(TreeRootPair[] calldata sparse)
        external
        pure
        returns (uint256[16] memory packedRoots, uint256 packedTreeNumbers)
    {
        return LibPublicInputs.sparseToPackedAuthRootsWithTreeNumbers(sparse);
    }
}

contract LibPublicInputsTest is Test {
    uint8 constant MAX_TREES = 16;
    uint8 constant MAX_AUTH_TREES = 16;

    LibPublicInputsWrapper wrapper;

    function setUp() public {
        wrapper = new LibPublicInputsWrapper();
    }

    function _buildUsedRoots() internal pure returns (TreeRootPair[] memory) {
        TreeRootPair[] memory roots = new TreeRootPair[](16);
        for (uint256 i = 0; i < 16; i++) {
            roots[i] = TreeRootPair({treeNumber: i, root: i + 1});
        }
        return roots;
    }

    function _buildAuthRoots() internal pure returns (TreeRootPair[] memory) {
        TreeRootPair[] memory roots = new TreeRootPair[](16);
        for (uint256 i = 0; i < 16; i++) {
            roots[i] = TreeRootPair({treeNumber: i, root: 100 + i});
        }
        return roots;
    }

    function _buildTreeState(
        TreeRootPair[] memory usedRoots,
        uint256 activeTreeNumber,
        uint32 countOld,
        uint256 rootNew,
        uint32 countNew,
        bool rollover
    ) internal pure returns (EpochTreeState memory) {
        return EpochTreeState({
            usedRoots: usedRoots,
            activeTreeNumber: activeTreeNumber,
            countOld: countOld,
            rootNew: rootNew,
            countNew: countNew,
            rollover: rollover
        });
    }

    /// @dev A batch with no withdrawals still declares its mask words, so the tests that only care
    ///      about the pre-existing layout pass the single all-zero word an s1..s128 shape uses.
    function _emptyWithdrawalMask() private pure returns (uint256[] memory mask) {
        mask = new uint256[](1);
    }

    // ========== Epoch Inputs ==========

    function test_buildEpochInputs_returnsCorrectLength() public {
        TreeRootPair[] memory usedRoots = _buildUsedRoots();
        TreeRootPair[] memory authRoots = _buildAuthRoots();

        uint256[][] memory nullifiers = new uint256[][](3);
        uint256[][] memory commitmentsOut = new uint256[][](3);
        for (uint256 t = 0; t < 3; t++) {
            nullifiers[t] = new uint256[](1);
            commitmentsOut[t] = new uint256[](1);
        }
        uint256[] memory approveDigestHi = new uint256[](3);
        uint256[] memory approveDigestLo = new uint256[](3);
        uint256[] memory feeCommitmentsOut = new uint256[](4);

        uint256[] memory inputs = LibPublicInputs.buildEpochInputs(
            _buildTreeState(usedRoots, 1, 100, 0xABCD, 103, false),
            authRoots,
            0xACE, // activeTreeRoot
            0, // provingTimestamp
            3, // nTransfers
            nullifiers,
            commitmentsOut,
            approveDigestHi,
            approveDigestLo,
            2, // feeTokenCount
            12345, // feeNPK
            feeCommitmentsOut,
            0xFEE1, // feeTransferDigestHi
            0xFEE2, // feeTransferDigestLo
            1, // maxInputsPerTransfer
            1, // maxOutputsPerTransfer
            4, // maxFeeTokens
            _emptyWithdrawalMask()
        );

        // Expected length: MAX_TREES(16) + 2(packedTreeNumbers + provingTimestamp) + MAX_AUTH_TREES(16) + 1(packedAuthTreeNumbers) +
        //                  4(activeTree + activeTreeRoot + countsPacked + rootNew) +
        //                  nullifiers(3*1) + commitments(3*1) + digestHi(3) + digestLo(3) + 1(feeNPK) +
        //                  maxFeeTokens(4) + feeTransferDigestHi(1) + feeTransferDigestLo(1) +
        //                  withdrawalMask(1) = 59
        assertEq(inputs.length, 59);
        assertEq(inputs[56], 0xFEE1);
        assertEq(inputs[57], 0xFEE2);
        assertEq(inputs[58], 0);
    }

    function test_buildEpochInputs_containsKnownRoots() public {
        TreeRootPair[] memory usedRoots = _buildUsedRoots();
        TreeRootPair[] memory authRoots = _buildAuthRoots();

        uint256[][] memory nullifiers = new uint256[][](1);
        uint256[][] memory commitmentsOut = new uint256[][](1);
        nullifiers[0] = new uint256[](1);
        commitmentsOut[0] = new uint256[](1);
        uint256[] memory approveDigestHi = new uint256[](1);
        uint256[] memory approveDigestLo = new uint256[](1);
        uint256[] memory feeCommitmentsOut = new uint256[](2);

        uint256[] memory inputs = LibPublicInputs.buildEpochInputs(
            _buildTreeState(usedRoots, 0, 0, 0, 0, false),
            authRoots,
            0, // activeTreeRoot
            0, // provingTimestamp
            1,
            nullifiers,
            commitmentsOut,
            approveDigestHi,
            approveDigestLo,
            1,
            0,
            feeCommitmentsOut,
            0,
            0,
            1,
            1,
            2,
            _emptyWithdrawalMask()
        );

        for (uint256 i = 0; i < MAX_TREES; i++) {
            assertEq(inputs[i], usedRoots[i].root);
        }
    }

    function test_buildEpochInputs_containsAuthRoots() public {
        TreeRootPair[] memory usedRoots = _buildUsedRoots();
        TreeRootPair[] memory authRoots = _buildAuthRoots();

        uint256[][] memory nullifiers = new uint256[][](1);
        uint256[][] memory commitmentsOut = new uint256[][](1);
        nullifiers[0] = new uint256[](1);
        commitmentsOut[0] = new uint256[](1);
        uint256[] memory approveDigestHi = new uint256[](1);
        uint256[] memory approveDigestLo = new uint256[](1);
        uint256[] memory feeCommitmentsOut = new uint256[](2);

        uint256[] memory inputs = LibPublicInputs.buildEpochInputs(
            _buildTreeState(usedRoots, 0, 0, 0, 0, false),
            authRoots,
            0, // activeTreeRoot
            0, // provingTimestamp
            1,
            nullifiers,
            commitmentsOut,
            approveDigestHi,
            approveDigestLo,
            1,
            0,
            feeCommitmentsOut,
            0,
            0,
            1,
            1,
            2,
            _emptyWithdrawalMask()
        );

        // authRoots start at index MAX_TREES + 2(packedTreeNumbers + provingTimestamp) + 1(activeTree) + 1(activeTreeRoot) + 1(countsPacked) + 1(rootNew) = 22
        uint256 authStart = MAX_TREES + 2 + 4;
        for (uint256 i = 0; i < MAX_AUTH_TREES; i++) {
            assertEq(inputs[authStart + i], authRoots[i].root);
        }
    }

    function test_buildEpochInputs_containsEpochParams() public {
        TreeRootPair[] memory usedRoots = _buildUsedRoots();
        TreeRootPair[] memory authRoots = _buildAuthRoots();

        uint256[][] memory nullifiers = new uint256[][](1);
        uint256[][] memory commitmentsOut = new uint256[][](1);
        nullifiers[0] = new uint256[](1);
        commitmentsOut[0] = new uint256[](1);
        uint256[] memory approveDigestHi = new uint256[](1);
        uint256[] memory approveDigestLo = new uint256[](1);
        uint256[] memory feeCommitmentsOut = new uint256[](2);

        uint256[] memory inputs = LibPublicInputs.buildEpochInputs(
            _buildTreeState(usedRoots, 5, 100, 0xABCD, 105, true),
            authRoots,
            0xACE, // activeTreeRoot
            0, // provingTimestamp
            1, // nTransfers
            nullifiers,
            commitmentsOut,
            approveDigestHi,
            approveDigestLo,
            1,
            12345,
            feeCommitmentsOut,
            0,
            0,
            1,
            1,
            2,
            _emptyWithdrawalMask()
        );

        // Params start at index MAX_TREES + 2(packedTreeNumbers + provingTimestamp) = 18 (after roots, packed tree numbers, and provingTimestamp)
        assertEq(inputs[17], 0); // provingTimestamp
        assertEq(inputs[18], 5); // activeTreeNumber
        assertEq(inputs[19], 0xACE); // activeTreeRoot

        // countsPacked at index 20: CountOld | (CountNew << 32) | (Rollover << 64) | (NTransfers << 96) | (FeeTokenCount << 128)
        uint256 expectedCountsPacked = 100; // countOld
        expectedCountsPacked |= uint256(105) << 32; // countNew
        expectedCountsPacked |= uint256(1) << 64; // rollover (true = 1)
        expectedCountsPacked |= uint256(1) << 96; // nTransfers
        expectedCountsPacked |= uint256(1) << 128; // feeTokenCount
        assertEq(inputs[20], expectedCountsPacked);

        assertEq(inputs[21], 0xABCD); // rootNew
        // authRoots at 22-37, packedAuthTreeNumbers at 38
    }

    function test_buildEpochInputs_rolloverFalseIsZero() public {
        TreeRootPair[] memory usedRoots = _buildUsedRoots();
        TreeRootPair[] memory authRoots = _buildAuthRoots();

        uint256[][] memory nullifiers = new uint256[][](1);
        uint256[][] memory commitmentsOut = new uint256[][](1);
        nullifiers[0] = new uint256[](1);
        commitmentsOut[0] = new uint256[](1);
        uint256[] memory approveDigestHi = new uint256[](1);
        uint256[] memory approveDigestLo = new uint256[](1);
        uint256[] memory feeCommitmentsOut = new uint256[](2);

        uint256[] memory inputs = LibPublicInputs.buildEpochInputs(
            _buildTreeState(usedRoots, 0, 0, 0, 0, false),
            authRoots,
            0, // activeTreeRoot
            0, // provingTimestamp
            1,
            nullifiers,
            commitmentsOut,
            approveDigestHi,
            approveDigestLo,
            1,
            0,
            feeCommitmentsOut,
            0,
            0,
            1,
            1,
            2,
            _emptyWithdrawalMask()
        );

        // countsPacked at index 20: CountOld | (CountNew << 32) | (Rollover << 64) | (NTransfers << 96) | (FeeTokenCount << 128)
        uint256 expectedCountsPackedNoRollover = 0; // countOld
        expectedCountsPackedNoRollover |= uint256(0) << 32; // countNew
        expectedCountsPackedNoRollover |= uint256(0) << 64; // rollover (false = 0)
        expectedCountsPackedNoRollover |= uint256(1) << 96; // nTransfers
        expectedCountsPackedNoRollover |= uint256(1) << 128; // feeTokenCount
        assertEq(inputs[20], expectedCountsPackedNoRollover);
    }

    /// @dev Every other epoch test uses one input and one output per transfer, where row-major and
    ///      column-major flattening produce identical output and an omitted write is indistinguishable
    ///      from a zero value. This case uses distinct non-zero values and a wider, non-square shape
    ///      (2 inputs against 3 outputs per transfer) so a transposed, shifted, or dropped element moves
    ///      at least one slot and fails.
    function test_buildEpochInputs_flattensTransferMatricesRowMajor() public {
        // Arrange
        uint256 nTransfers = 2;
        uint256 maxIn = 2;
        uint256 maxOut = 3;
        uint256 maxFee = 2;

        uint256[][] memory nullifiers = new uint256[][](nTransfers);
        uint256[][] memory commitmentsOut = new uint256[][](nTransfers);
        for (uint256 t = 0; t < nTransfers; t++) {
            nullifiers[t] = new uint256[](maxIn);
            commitmentsOut[t] = new uint256[](maxOut);
            for (uint256 i = 0; i < maxIn; i++) {
                nullifiers[t][i] = 0x1000 + t * 0x10 + i;
            }
            for (uint256 j = 0; j < maxOut; j++) {
                commitmentsOut[t][j] = 0x2000 + t * 0x10 + j;
            }
        }

        uint256[] memory approveDigestHi = new uint256[](nTransfers);
        uint256[] memory approveDigestLo = new uint256[](nTransfers);
        for (uint256 t = 0; t < nTransfers; t++) {
            approveDigestHi[t] = 0x3000 + t;
            approveDigestLo[t] = 0x4000 + t;
        }

        uint256[] memory feeCommitmentsOut = new uint256[](maxFee);
        for (uint256 k = 0; k < maxFee; k++) {
            feeCommitmentsOut[k] = 0x5000 + k;
        }

        // Act
        uint256[] memory inputs = LibPublicInputs.buildEpochInputs(
            _buildTreeState(_buildUsedRoots(), 0, 0, 0, 0, false),
            _buildAuthRoots(),
            0, // activeTreeRoot
            0, // provingTimestamp
            nTransfers,
            nullifiers,
            commitmentsOut,
            approveDigestHi,
            approveDigestLo,
            uint32(maxFee), // feeTokenCount
            0x6000, // feeNPK
            feeCommitmentsOut,
            0x7001, // feeTransferDigestHi
            0x7002, // feeTransferDigestLo
            uint32(maxIn),
            uint32(maxOut),
            uint32(maxFee),
            _emptyWithdrawalMask()
        );

        // Assert
        // Matrices begin after note roots(16) + packedTreeNumbers + provingTimestamp + activeTree +
        // activeTreeRoot + countsPacked + rootNew + authRoots(16) + packedAuthTreeNumbers.
        uint256 nullifierStart = MAX_TREES + 2 + 4 + MAX_AUTH_TREES + 1;
        assertEq(nullifierStart, 39);

        for (uint256 t = 0; t < nTransfers; t++) {
            for (uint256 i = 0; i < maxIn; i++) {
                assertEq(inputs[nullifierStart + t * maxIn + i], nullifiers[t][i]);
            }
        }

        uint256 commitmentStart = nullifierStart + nTransfers * maxIn;
        for (uint256 t = 0; t < nTransfers; t++) {
            for (uint256 j = 0; j < maxOut; j++) {
                assertEq(inputs[commitmentStart + t * maxOut + j], commitmentsOut[t][j]);
            }
        }

        // The digest, fee, and fee-digest blocks must sit immediately after the matrices, so a helper
        // that writes the wrong number of slots shifts every one of these and fails here.
        uint256 digestHiStart = commitmentStart + nTransfers * maxOut;
        for (uint256 t = 0; t < nTransfers; t++) {
            assertEq(inputs[digestHiStart + t], approveDigestHi[t]);
            assertEq(inputs[digestHiStart + nTransfers + t], approveDigestLo[t]);
        }

        uint256 feeNPKIndex = digestHiStart + nTransfers * 2;
        assertEq(inputs[feeNPKIndex], 0x6000);
        for (uint256 k = 0; k < maxFee; k++) {
            assertEq(inputs[feeNPKIndex + 1 + k], feeCommitmentsOut[k]);
        }
        assertEq(inputs[feeNPKIndex + 1 + maxFee], 0x7001);
        assertEq(inputs[feeNPKIndex + 2 + maxFee], 0x7002);
        // The mask words trail the fee digests, so a helper that writes the wrong number of slots
        // anywhere earlier moves them and fails here.
        assertEq(inputs[feeNPKIndex + 3 + maxFee], 0);
        assertEq(inputs.length, feeNPKIndex + 4 + maxFee);
    }

    // ========== Withdrawal mask ==========

    function test_packWithdrawalMask_emptyBatchIsAllZero() public pure {
        uint32[] memory slots = new uint32[](0);
        uint256[] memory mask = LibPublicInputs.packWithdrawalMask(slots, 8);

        assertEq(mask.length, 1);
        assertEq(mask[0], 0);
    }

    function test_packWithdrawalMask_setsOneBitPerSlot() public pure {
        uint32[] memory slots = new uint32[](3);
        slots[0] = 0;
        slots[1] = 3;
        slots[2] = 7;
        uint256[] memory mask = LibPublicInputs.packWithdrawalMask(slots, 8);

        // Bits 0, 3, and 7 only.
        assertEq(mask.length, 1);
        assertEq(mask[0], (1 << 0) | (1 << 3) | (1 << 7));
    }

    function test_packWithdrawalMask_wordCountFollowsCapacity() public pure {
        uint32[] memory slots = new uint32[](0);

        assertEq(LibPublicInputs.packWithdrawalMask(slots, 1).length, 1);
        assertEq(LibPublicInputs.packWithdrawalMask(slots, WITHDRAWAL_MASK_BITS_PER_WORD).length, 1);
        assertEq(LibPublicInputs.packWithdrawalMask(slots, WITHDRAWAL_MASK_BITS_PER_WORD + 1).length, 2);
        assertEq(LibPublicInputs.packWithdrawalMask(slots, 256).length, 2);
    }

    function test_packWithdrawalMask_splitsAcrossWords() public pure {
        // A slot at the packing boundary must land in the second word's bit zero, not the first
        // word's bit 128, which is where an off-by-one in the divisor would put it.
        uint32[] memory slots = new uint32[](2);
        slots[0] = uint32(WITHDRAWAL_MASK_BITS_PER_WORD - 1);
        slots[1] = uint32(WITHDRAWAL_MASK_BITS_PER_WORD);
        uint256[] memory mask = LibPublicInputs.packWithdrawalMask(slots, 2 * WITHDRAWAL_MASK_BITS_PER_WORD);

        assertEq(mask.length, 2);
        assertEq(mask[0], uint256(1) << (WITHDRAWAL_MASK_BITS_PER_WORD - 1));
        assertEq(mask[1], 1);
    }

    // ========== Deposit Inputs (Simplified for TEE prover) ==========

    function test_buildDepositInputs_returnsCorrectLength() public {
        TreeRootPair[] memory usedRoots = _buildUsedRoots();

        uint256[] memory depositRequestIds = new uint256[](4);
        uint256[] memory totalAmounts = new uint256[](4);
        uint256[] memory commitmentCounts = new uint256[](4);
        uint256[] memory commitmentsOut = new uint256[](4);

        uint256[] memory inputs = LibPublicInputs.buildDepositInputs(
            1, // chainId
            address(0x1234), // pool
            _buildTreeState(usedRoots, 1, 100, 0xABCD, 103, false),
            2, // nRequests
            3, // nTotalCommitments
            depositRequestIds,
            totalAmounts,
            commitmentCounts,
            commitmentsOut
        );

        // Expected: MAX_TREES(16) + 10 + maxSlots*4(16) = 42
        assertEq(inputs.length, 42);
    }

    function test_buildDepositInputs_containsChainIdAndPool() public {
        TreeRootPair[] memory usedRoots = _buildUsedRoots();

        uint256[] memory depositRequestIds = new uint256[](2);
        uint256[] memory totalAmounts = new uint256[](2);
        uint256[] memory commitmentCounts = new uint256[](2);
        uint256[] memory commitmentsOut = new uint256[](2);

        address pool = address(0x1234);

        uint256[] memory inputs = LibPublicInputs.buildDepositInputs(
            31337,
            pool,
            _buildTreeState(usedRoots, 0, 0, 0, 0, false),
            1,
            1,
            depositRequestIds,
            totalAmounts,
            commitmentCounts,
            commitmentsOut
        );

        assertEq(inputs[0], 31337);
        assertEq(inputs[1], uint256(uint160(pool)));
    }

    function test_buildDepositInputs_containsScalarParams() public {
        TreeRootPair[] memory usedRoots = _buildUsedRoots();

        uint256[] memory depositRequestIds = new uint256[](2);
        uint256[] memory totalAmounts = new uint256[](2);
        uint256[] memory commitmentCounts = new uint256[](2);
        uint256[] memory commitmentsOut = new uint256[](2);

        uint256[] memory inputs = LibPublicInputs.buildDepositInputs(
            1,
            address(0x1234),
            _buildTreeState(usedRoots, 5, 100, 0xABCD, 102, true),
            2, // nRequests
            4, // nTotalCommitments
            depositRequestIds,
            totalAmounts,
            commitmentCounts,
            commitmentsOut
        );

        // After chainId(0), pool(1), knownRoots(2-17), packedTreeNumbers(18):
        assertEq(inputs[19], 5); // activeTreeNumber
        assertEq(inputs[20], 100); // countOld
        assertEq(inputs[21], 0xABCD); // rootNew
        assertEq(inputs[22], 102); // countNew
        assertEq(inputs[23], 1); // rollover (true = 1)
        assertEq(inputs[24], 2); // nRequests
        assertEq(inputs[25], 4); // nTotalCommitments
    }

    // ========== Forced Withdrawal Inputs ==========

    function test_buildForcedWithdrawalInputs_returnsCorrectLength() public {
        TreeRootPair[] memory usedRoots = _buildUsedRoots();
        TreeRootPair[] memory forcedAuthData = new TreeRootPair[](1);
        forcedAuthData[0] = TreeRootPair({treeNumber: uint128(1) << 100, root: 777});

        uint256[] memory nullifiersPadded = new uint256[](4);
        uint256[] memory inputCommitmentsPadded = new uint256[](4);

        uint256[] memory inputs = LibPublicInputs.buildForcedWithdrawalInputs(
            usedRoots,
            forcedAuthData,
            2, // inputCount
            12345, // spenderAccountId
            nullifiersPadded,
            inputCommitmentsPadded,
            keccak256("digest"),
            address(0xBEEF),
            1, // tokenId
            1000 ether // amount
        );

        // Expected: note roots(16) + packed tree numbers(1) + scalar fields(9) + arrays(8).
        assertEq(inputs.length, 34);
    }

    function test_buildForcedWithdrawalInputs_containsWithdrawalDetails() public {
        TreeRootPair[] memory usedRoots = _buildUsedRoots();
        TreeRootPair[] memory forcedAuthData = new TreeRootPair[](1);
        forcedAuthData[0] = TreeRootPair({treeNumber: uint128(1) << 100, root: 777});

        uint256[] memory nullifiersPadded = new uint256[](4);
        uint256[] memory inputCommitmentsPadded = new uint256[](4);

        bytes32 digest = keccak256("test digest");
        address withdrawalTo = address(0xBEEF);
        uint16 tokenId = 5;
        uint96 amount = 500 ether;

        uint256[] memory inputs = LibPublicInputs.buildForcedWithdrawalInputs(
            usedRoots,
            forcedAuthData,
            2,
            12345,
            nullifiersPadded,
            inputCommitmentsPadded,
            digest,
            withdrawalTo,
            tokenId,
            amount
        );

        // Check digest split
        uint256 digestHi = uint256(digest) >> 128;
        uint256 digestLo = uint256(digest) & ((uint256(1) << 128) - 1);

        // Position: note roots(16) + packed tree numbers(1) + inputCount/account(2) + arrays(8).
        uint256 digestHiIdx = 27;
        assertEq(inputs[digestHiIdx], digestHi);
        assertEq(inputs[digestHiIdx + 1], digestLo);
        assertEq(inputs[digestHiIdx + 2], uint256(uint160(withdrawalTo)));
        assertEq(inputs[digestHiIdx + 3], uint256(tokenId));
        assertEq(inputs[digestHiIdx + 4], uint256(amount));
        assertEq(inputs[digestHiIdx + 5], 777);
        assertEq(inputs[digestHiIdx + 6], uint256(1) << 100);
    }

    // ========== Tree Number Boundary Tests ==========

    function test_treeNumberPacking_zeroTreeNumber() public view {
        TreeRootPair[] memory roots = new TreeRootPair[](1);
        roots[0] = TreeRootPair({treeNumber: 0, root: 123});

        (uint256[16] memory packedRoots, uint256 packedTreeNumbers) = wrapper.sparseToPackedRootsWithTreeNumbers(roots);

        assertEq(packedRoots[0], 123);
        assertEq(packedTreeNumbers, 0); // treeNumber 0 at slot 0 = 0 << 0 = 0
    }

    function test_treeNumberPacking_maxTreeNumber() public view {
        // Max 15-bit value = 32767 (2^15 - 1)
        TreeRootPair[] memory roots = new TreeRootPair[](1);
        roots[0] = TreeRootPair({treeNumber: 32767, root: 456});

        (uint256[16] memory packedRoots, uint256 packedTreeNumbers) = wrapper.sparseToPackedRootsWithTreeNumbers(roots);

        assertEq(packedRoots[0], 456);
        assertEq(packedTreeNumbers, 32767); // 32767 << 0 = 32767
    }

    function test_treeNumberPacking_overflowReverts() public {
        // Tree number 32768 (2^15) should overflow 15-bit slot
        TreeRootPair[] memory roots = new TreeRootPair[](1);
        roots[0] = TreeRootPair({treeNumber: 32768, root: 789});

        vm.expectRevert(IPrivacyBoost.TreeNumberOverflow.selector);
        wrapper.sparseToPackedRootsWithTreeNumbers(roots);
    }

    function test_treeNumberPacking_all16Slots() public view {
        TreeRootPair[] memory roots = new TreeRootPair[](16);
        for (uint256 i = 0; i < 16; i++) {
            roots[i] = TreeRootPair({treeNumber: i, root: i * 100});
        }

        (uint256[16] memory packedRoots, uint256 packedTreeNumbers) = wrapper.sparseToPackedRootsWithTreeNumbers(roots);

        // Verify each root is at correct position
        for (uint256 i = 0; i < 16; i++) {
            assertEq(packedRoots[i], i * 100);
        }

        // Verify packed tree numbers: 0 | (1 << 15) | (2 << 30) | ... | (15 << 225)
        uint256 expectedPacked = 0;
        for (uint256 i = 0; i < 16; i++) {
            expectedPacked |= (i << (i * 15));
        }
        assertEq(packedTreeNumbers, expectedPacked);
    }

    function test_treeNumberPacking_all16SlotsMaxValues() public view {
        // Test all 16 slots with max tree number (32767) at each slot
        TreeRootPair[] memory roots = new TreeRootPair[](16);
        for (uint256 i = 0; i < 16; i++) {
            roots[i] = TreeRootPair({treeNumber: 32767, root: i + 1});
        }

        (uint256[16] memory packedRoots, uint256 packedTreeNumbers) = wrapper.sparseToPackedRootsWithTreeNumbers(roots);

        // Suppress unused variable warning
        packedRoots;

        // Verify packed tree numbers: 32767 | (32767 << 15) | (32767 << 30) | ... | (32767 << 225)
        uint256 expectedPacked = 0;
        for (uint256 i = 0; i < 16; i++) {
            expectedPacked |= (uint256(32767) << (i * 15));
        }
        assertEq(packedTreeNumbers, expectedPacked);

        // Total bits used: 16 * 15 = 240 bits, which fits in 254-bit BN254 field
        // 240 bits set to 1 = 2^240 - 1, which is well under 2^254
        assertTrue(packedTreeNumbers < (uint256(1) << 254));
    }

    function test_authTreeNumberPacking_overflowReverts() public {
        TreeRootPair[] memory roots = new TreeRootPair[](1);
        roots[0] = TreeRootPair({treeNumber: 32768, root: 789});

        vm.expectRevert(IPrivacyBoost.TreeNumberOverflow.selector);
        wrapper.sparseToPackedAuthRootsWithTreeNumbers(roots);
    }
}
