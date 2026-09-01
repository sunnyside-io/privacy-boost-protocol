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

import {EpochTreeState, TreeRootPair} from "src/interfaces/IStructs.sol";
import {
    MAX_NOTE_ROOTS_PER_PROOF,
    MAX_AUTH_ROOTS_PER_PROOF,
    MAX_NOTE_TREE_NUMBER,
    DIGEST_HALF_BITS,
    WITHDRAWAL_MASK_BITS_PER_WORD
} from "src/interfaces/Constants.sol";
import {IPrivacyBoost} from "src/interfaces/IPrivacyBoost.sol";

/// @title LibPublicInputs
/// @notice Construct public input arrays for ZK verifiers
/// @custom:security-contact contact@sunnyside.io
library LibPublicInputs {
    // ─────────────── Field-packing helpers ───────────────

    /// @notice Pack count-related values into a single field element
    /// @dev Layout: CountOld | (CountNew << 32) | (Rollover << 64) | (NTransfers << 96) | (FeeTokenCount << 128)
    ///      Total: 160 bits (5 slots × 32 bits), fits within BN254's ~254-bit scalar field.
    /// @param countOld Leaf count before the epoch update
    /// @param countNew Leaf count after the epoch update
    /// @param rollover Whether the active tree rolled over to a new tree
    /// @param nTransfers Number of transfers in this epoch
    /// @param feeTokenCount Number of fee tokens used for this epoch
    /// @return packed Packed counts field element
    function packCounts(uint32 countOld, uint32 countNew, bool rollover, uint32 nTransfers, uint32 feeTokenCount)
        internal
        pure
        returns (uint256 packed)
    {
        packed = uint256(countOld);
        packed |= uint256(countNew) << 32;
        packed |= (rollover ? uint256(1) : uint256(0)) << 64;
        packed |= uint256(nTransfers) << 96;
        packed |= uint256(feeTokenCount) << 128;
    }

    /// @notice Pack sparse tree data into roots array and packed tree numbers
    /// @dev Internal helper shared by note tree and auth tree packing functions.
    ///      Tree numbers are packed as 15-bit values: packedTreeNumbers = treeNum[0] | (treeNum[1] << 15) | ...
    ///      Using 15 bits allows 16 slots × 15 bits = 240 bits, fitting in BN254's ~254-bit scalar field.
    /// @param sparse The sparse tree root pairs to pack
    /// @param maxSlots Maximum number of slots allowed (for bounds checking)
    /// @return packedTreeNumbers Packed tree numbers in a single field element
    function _packTreeData(TreeRootPair[] calldata sparse, uint256 maxSlots)
        private
        pure
        returns (uint256 packedTreeNumbers)
    {
        uint256 len = sparse.length;
        if (len > maxSlots) revert IPrivacyBoost.TooManyDistinctTrees();
        for (uint256 i = 0; i < len; ++i) {
            uint256 treeNum = sparse[i].treeNumber;
            if (treeNum > MAX_NOTE_TREE_NUMBER) revert IPrivacyBoost.TreeNumberOverflow();
            // Pack tree number into 15-bit slot
            packedTreeNumbers |= (treeNum << (i * 15));
        }
    }

    /// @notice Convert sparse tree roots to packed arrays for circuit (roots array + single packed tree numbers)
    /// @dev Separate function from auth version due to different return array sizes for type safety.
    /// @param sparse Sparse (treeNumber, root) pairs to pack
    /// @return packedRoots Fixed-size roots array padded with zeros
    /// @return packedTreeNumbers Packed 15-bit tree numbers in a single field element
    function sparseToPackedRootsWithTreeNumbers(TreeRootPair[] calldata sparse)
        internal
        pure
        returns (uint256[MAX_NOTE_ROOTS_PER_PROOF] memory packedRoots, uint256 packedTreeNumbers)
    {
        packedTreeNumbers = _packTreeData(sparse, MAX_NOTE_ROOTS_PER_PROOF);
        for (uint256 i = 0; i < sparse.length; ++i) {
            packedRoots[i] = sparse[i].root;
        }
    }

    /// @notice Convert sparse auth roots to packed arrays for circuit (roots array + single packed tree numbers)
    /// @dev Separate function from note version due to different return array sizes for type safety.
    /// @param sparse Sparse (treeNumber, root) pairs to pack
    /// @return packedRoots Fixed-size auth roots array padded with zeros
    /// @return packedTreeNumbers Packed 15-bit tree numbers in a single field element
    function sparseToPackedAuthRootsWithTreeNumbers(TreeRootPair[] calldata sparse)
        internal
        pure
        returns (uint256[MAX_AUTH_ROOTS_PER_PROOF] memory packedRoots, uint256 packedTreeNumbers)
    {
        packedTreeNumbers = _packTreeData(sparse, MAX_AUTH_ROOTS_PER_PROOF);
        for (uint256 i = 0; i < sparse.length; ++i) {
            packedRoots[i] = sparse[i].root;
        }
    }

    /// @dev Append the 16-slot packed note-root array followed by the packed tree-numbers word to
    ///      `publicInputs` starting at `idx`. Kept as a separate frame so the 16-element scratch array
    ///      does not count against the caller's stack budget. Returns the updated write cursor.
    function _appendNoteRoots(uint256[] memory publicInputs, uint256 idx, TreeRootPair[] calldata sparse)
        private
        pure
        returns (uint256)
    {
        (uint256[MAX_NOTE_ROOTS_PER_PROOF] memory packedRoots, uint256 packedTreeNumbers) =
            sparseToPackedRootsWithTreeNumbers(sparse);
        for (uint256 i = 0; i < MAX_NOTE_ROOTS_PER_PROOF; ++i) {
            publicInputs[idx++] = packedRoots[i];
        }
        publicInputs[idx++] = packedTreeNumbers;
        return idx;
    }

    /// @dev Append the 16-slot packed auth-root array followed by the packed tree-numbers word to
    ///      `publicInputs` starting at `idx`. Separate frame, same rationale as _appendNoteRoots.
    function _appendAuthRoots(uint256[] memory publicInputs, uint256 idx, TreeRootPair[] calldata sparse)
        private
        pure
        returns (uint256)
    {
        (uint256[MAX_AUTH_ROOTS_PER_PROOF] memory packedRoots, uint256 packedTreeNumbers) =
            sparseToPackedAuthRootsWithTreeNumbers(sparse);
        for (uint256 i = 0; i < MAX_AUTH_ROOTS_PER_PROOF; ++i) {
            publicInputs[idx++] = packedRoots[i];
        }
        publicInputs[idx++] = packedTreeNumbers;
        return idx;
    }

    /// @dev Flatten the nullifier and output-commitment matrices row-major into `publicInputs` starting at `idx`.
    ///      Kept as a separate frame so the two nested loops and the two 2D calldata arrays they walk do not
    ///      count against the caller's stack budget, same rationale as the root appenders above. A calldata
    ///      array parameter occupies two stack slots (offset and length) against one for a memory pointer,
    ///      so the epoch builder cannot hold every array in its own frame and still reach its deepest local.
    /// @return The write cursor after both matrices
    function _appendTransferMatrices(
        uint256[] memory publicInputs,
        uint256 idx,
        uint256[][] calldata nullifiers,
        uint256[][] calldata commitmentsOut,
        uint256 maxTransfers,
        uint32 maxInputsPerTransfer,
        uint32 maxOutputsPerTransfer
    ) private pure returns (uint256) {
        // Flatten nullifiers row-major: [t][i] -> idx = t * maxInputs + i
        for (uint256 t = 0; t < maxTransfers; ++t) {
            for (uint256 i = 0; i < maxInputsPerTransfer; ++i) {
                publicInputs[idx++] = nullifiers[t][i];
            }
        }

        // Flatten commitments row-major: [t][j] -> idx = t * maxOutputs + j
        for (uint256 t = 0; t < maxTransfers; ++t) {
            for (uint256 j = 0; j < maxOutputsPerTransfer; ++j) {
                publicInputs[idx++] = commitmentsOut[t][j];
            }
        }

        return idx;
    }

    // ─────────────── Per-circuit public-input builders ───────────────

    /// @notice Build public inputs for epoch verification
    /// @dev Layout: [knownRoots(16), packedTreeNumbers, provingTimestamp, activeTree, activeTreeRoot,
    ///              countsPacked, rootNew,
    ///              authRoots(16), packedAuthTreeNumbers,
    ///              nullifiers(maxTransfers*maxInputs), commitments(maxTransfers*maxOutputs),
    ///              digestHi(maxTransfers), digestLo(maxTransfers),
    ///              feeNPK, feeCommitments(maxFeeTokens)]
    /// @dev 2D arrays are flattened row-major: nullifiers[t][i] -> idx = t * maxInputs + i
    /// @param treeState Note tree state (sparse roots, active tree number, counts, new root)
    /// @param usedAuthRoots Sparse (treeNumber, root) pairs for the auth trees referenced by this proof
    /// @param activeTreeRoot Root of the active note tree (treeState.activeTreeNumber)
    /// @param provingTimestamp Timestamp used by the circuit for auth expiry checks
    /// @param nTransfers Actual number of transfers (must be <= nullifiers.length)
    /// @param nullifiers Padded nullifier matrix [maxTransfers][maxInputsPerTransfer]
    /// @param commitmentsOut Padded output commitments matrix [maxTransfers][maxOutputsPerTransfer]
    /// @param approveDigestHi High halves of per-transfer approval digests (length = maxTransfers)
    /// @param approveDigestLo Low halves of per-transfer approval digests (length = maxTransfers)
    /// @param feeTokenCount Number of fee tokens used (<= maxFeeTokens)
    /// @param feeNPK Fee note public key for the fee receiver (circuit-defined)
    /// @param feeCommitmentsOut Fee output commitments (length = maxFeeTokens)
    /// @param feeTransferDigestHi High 128 bits of the fee-transfer metadata digest
    /// @param feeTransferDigestLo Low 128 bits of the fee-transfer metadata digest
    /// @param maxInputsPerTransfer Circuit parameter: max inputs per transfer
    /// @param maxOutputsPerTransfer Circuit parameter: max outputs per transfer
    /// @param maxFeeTokens Circuit parameter: max fee tokens
    /// @return publicInputs Flattened public input array for epoch verification
    /// @param withdrawalMask Packed bitmask marking which transfer slots are withdrawals, one bit per
    ///        slot, least-significant bit first
    function buildEpochInputs(
        EpochTreeState calldata treeState,
        TreeRootPair[] calldata usedAuthRoots,
        uint256 activeTreeRoot,
        uint64 provingTimestamp,
        uint256 nTransfers,
        uint256[][] calldata nullifiers,
        uint256[][] calldata commitmentsOut,
        uint256[] calldata approveDigestHi,
        uint256[] calldata approveDigestLo,
        uint32 feeTokenCount,
        uint256 feeNPK,
        uint256[] calldata feeCommitmentsOut,
        uint256 feeTransferDigestHi,
        uint256 feeTransferDigestLo,
        uint32 maxInputsPerTransfer,
        uint32 maxOutputsPerTransfer,
        uint32 maxFeeTokens,
        uint256[] memory withdrawalMask
    ) external pure returns (uint256[] memory) {
        uint256 maxTransfers = nullifiers.length;
        // Layout: knownRoots(16) + packedTreeNumbers(1) + provingTimestamp(1) + activeTree(1) + activeTreeRoot(1) +
        //         countsPacked(1) + rootNew(1) +
        //         authRoots(16) + packedAuthTreeNumbers(1) +
        //         nullifiers(maxTransfers * maxInputs) + commitments(maxTransfers * maxOutputs) +
        //         digestHi(maxTransfers) + digestLo(maxTransfers) +
        //         feeNPK(1) + feeCommitments(maxFeeTokens) + feeTransferDigestHi(1) + feeTransferDigestLo(1) +
        //         withdrawalMask(ceil(maxTransfers / WITHDRAWAL_MASK_BITS_PER_WORD))
        // The mask trails every other field because the circuit declares it last, and gnark orders
        // public inputs by declaration. Appending rather than inserting also leaves every existing
        // index untouched, which is what keeps this change reviewable against the old layout.
        uint256 totalNullifiers = maxTransfers * maxInputsPerTransfer;
        uint256 totalCommitments = maxTransfers * maxOutputsPerTransfer;
        uint256[] memory publicInputs = new uint256[](
            MAX_NOTE_ROOTS_PER_PROOF + 2 + MAX_AUTH_ROOTS_PER_PROOF + 1 + 4 + totalNullifiers + totalCommitments
                + maxTransfers * 2 + 1 + maxFeeTokens + 2 + withdrawalMask.length
        );
        uint256 idx;

        idx = _appendNoteRoots(publicInputs, idx, treeState.usedRoots);
        publicInputs[idx++] = provingTimestamp;

        publicInputs[idx++] = treeState.activeTreeNumber;
        publicInputs[idx++] = activeTreeRoot;

        // Pack counts: CountOld | (CountNew << 32) | (Rollover << 64) | (NTransfers << 96) | (FeeTokenCount << 128)
        // nTransfers is validated against PrivacyBoost.maxBatchSize, which is uint16-bounded.
        // forge-lint: disable-next-line(unsafe-typecast)
        uint32 nTransfers32 = uint32(nTransfers);
        publicInputs[idx++] =
            packCounts(treeState.countOld, treeState.countNew, treeState.rollover, nTransfers32, feeTokenCount);
        publicInputs[idx++] = treeState.rootNew;

        idx = _appendAuthRoots(publicInputs, idx, usedAuthRoots);

        idx = _appendTransferMatrices(
            publicInputs, idx, nullifiers, commitmentsOut, maxTransfers, maxInputsPerTransfer, maxOutputsPerTransfer
        );

        // Digests (one per transfer)
        for (uint256 t = 0; t < maxTransfers; ++t) {
            publicInputs[idx++] = approveDigestHi[t];
        }
        for (uint256 t = 0; t < maxTransfers; ++t) {
            publicInputs[idx++] = approveDigestLo[t];
        }

        publicInputs[idx++] = feeNPK;
        for (uint256 i = 0; i < maxFeeTokens; ++i) {
            publicInputs[idx++] = feeCommitmentsOut[i];
        }
        publicInputs[idx++] = feeTransferDigestHi;
        publicInputs[idx++] = feeTransferDigestLo;

        for (uint256 w = 0; w < withdrawalMask.length; ++w) {
            publicInputs[idx++] = withdrawalMask[w];
        }

        return publicInputs;
    }

    /// @notice Pack validated withdrawal slots into the circuit's public withdrawal-mask words.
    /// @dev Caller must have validated that every slot is strictly ascending and below nTransfers,
    ///      which is what makes one pass over the array enough and keeps the mask a faithful
    ///      restatement of the withdrawal list rather than an independently trusted input.
    /// @param withdrawalSlots Ascending transfer-slot indices that pay out publicly
    /// @param maxTransfers Circuit transfer capacity, which fixes the number of mask words
    /// @return mask One word per WITHDRAWAL_MASK_BITS_PER_WORD transfer slots, least-significant
    ///         bit first
    function packWithdrawalMask(uint32[] memory withdrawalSlots, uint256 maxTransfers)
        internal
        pure
        returns (uint256[] memory mask)
    {
        uint256 wordCount = (maxTransfers + WITHDRAWAL_MASK_BITS_PER_WORD - 1) / WITHDRAWAL_MASK_BITS_PER_WORD;
        mask = new uint256[](wordCount);
        for (uint256 i = 0; i < withdrawalSlots.length; ++i) {
            uint256 slot = withdrawalSlots[i];
            mask[slot / WITHDRAWAL_MASK_BITS_PER_WORD] |= uint256(1) << (slot % WITHDRAWAL_MASK_BITS_PER_WORD);
        }
    }

    /// @notice Build public inputs for deposit epoch verification
    /// @dev Layout: [chainId, poolAddress,
    ///              knownRoots(16), packedTreeNumbers,
    ///              activeTree, countOld, rootNew, countNew, rollover,
    ///              nRequests, nTotalCommitments,
    ///              depositRequestIds(maxSlots), totalAmounts(maxSlots),
    ///              commitmentCounts(maxSlots), commitmentsOut(maxSlots)]
    /// @param chainId The chain ID used for domain separation
    /// @param pool The PrivacyBoost pool contract address
    /// @param treeState Note tree state (sparse roots, active tree number, counts, new root)
    /// @param nRequests Number of distinct deposit requests included
    /// @param nTotalCommitments Total number of commitments across all included requests
    /// @param depositRequestIdsPadded Deposit request IDs padded to maxSlots
    /// @param totalAmountsPadded Total amounts (per request) padded to maxSlots
    /// @param commitmentCountsPadded Commitment counts (per request) padded to maxSlots
    /// @param commitmentsOutPadded Output commitments padded to maxSlots
    /// @return publicInputs Flattened public input array for deposit verification
    function buildDepositInputs(
        uint256 chainId,
        address pool,
        EpochTreeState calldata treeState,
        uint256 nRequests,
        uint256 nTotalCommitments,
        uint256[] calldata depositRequestIdsPadded,
        uint256[] calldata totalAmountsPadded,
        uint256[] calldata commitmentCountsPadded,
        uint256[] calldata commitmentsOutPadded
    ) external pure returns (uint256[] memory) {
        uint256 maxSlots = commitmentsOutPadded.length;
        uint256[] memory publicInputs = new uint256[](MAX_NOTE_ROOTS_PER_PROOF + 10 + maxSlots * 4);
        uint256 idx;

        publicInputs[idx++] = chainId;
        publicInputs[idx++] = uint256(uint160(pool));

        (uint256[MAX_NOTE_ROOTS_PER_PROOF] memory packedRoots, uint256 packedTreeNumbers) =
            sparseToPackedRootsWithTreeNumbers(treeState.usedRoots);
        for (uint256 i = 0; i < MAX_NOTE_ROOTS_PER_PROOF; ++i) {
            publicInputs[idx++] = packedRoots[i];
        }
        publicInputs[idx++] = packedTreeNumbers;

        publicInputs[idx++] = treeState.activeTreeNumber;
        publicInputs[idx++] = treeState.countOld;
        publicInputs[idx++] = treeState.rootNew;
        publicInputs[idx++] = treeState.countNew;
        publicInputs[idx++] = treeState.rollover ? 1 : 0;
        publicInputs[idx++] = nRequests;
        publicInputs[idx++] = nTotalCommitments;

        for (uint256 i = 0; i < maxSlots; ++i) {
            publicInputs[idx++] = depositRequestIdsPadded[i];
        }
        for (uint256 i = 0; i < maxSlots; ++i) {
            publicInputs[idx++] = totalAmountsPadded[i];
        }
        for (uint256 i = 0; i < maxSlots; ++i) {
            publicInputs[idx++] = commitmentCountsPadded[i];
        }
        for (uint256 i = 0; i < maxSlots; ++i) {
            publicInputs[idx++] = commitmentsOutPadded[i];
        }

        return publicInputs;
    }

    /// @notice Build public inputs for hidden-recipient portal-deposit epoch verification
    /// @dev Index-for-index mirror of the Go BuildPortalDepositInputs (in deposit_portal_circuit.go),
    ///      which is the source of truth for the layout — the two MUST agree element-for-element or the
    ///      verify call lines up against the wrong public witness. Layout:
    ///        [chainId, pool,
    ///         knownRoots(16), packedTreeNumbers,
    ///         activeTree, countOld, rootNew, countNew, rollover,
    ///         nRequests,
    ///         E(maxSlots), counter(maxSlots), H(maxSlots), tokenId(maxSlots),
    ///         amount(maxSlots), commitment(maxSlots)]
    ///      The scalar prefix (chainId/pool at 0/1, packed roots, then the tree-state block) is identical
    ///      to buildDepositInputs so the shared note tree's CAS lines up (layout parity). The
    ///      tail DIVERGES from buildDepositInputs: it drops nTotalCommitments and the requestId/
    ///      commitmentCount arrays (one note per portal deposit) and instead carries the portal-specific
    ///      per-slot arrays, array-grouped (all E's, then all counters, ...) to match gnark's contiguous
    ///      serialization of each public slice. recipientMPK/blind are witness-only and never appear here
    ///      (recipient hiding). The contract supplies EVERY element from the stored record —
    ///      `amountsNet` is `gross − fee` computed at the call site — so a malicious relay cannot
    ///      substitute a different amount, binding, or counter.
    /// @param chainId The chain ID used for domain separation
    /// @param pool The PrivacyBoost pool contract address
    /// @param treeState Note tree state (sparse roots, active tree number, counts, new root)
    /// @param nRequests Number of active portal deposits in this batch
    /// @param portalsPadded Portal addresses E padded to maxSlots
    /// @param countersPadded Per-portal sweep counters padded to maxSlots
    /// @param recipientBindHsPadded Owner bindings H (from each E's portalBinding()) padded to maxSlots
    /// @param tokenIdsPadded Token IDs padded to maxSlots
    /// @param amountsNetPadded Net credited amounts (gross − fee) padded to maxSlots
    /// @param commitmentsOutPadded Output note commitments padded to maxSlots
    /// @return publicInputs Flattened public input array for portal-deposit verification
    function buildPortalDepositInputs(
        uint256 chainId,
        address pool,
        EpochTreeState calldata treeState,
        uint256 nRequests,
        uint256[] calldata portalsPadded,
        uint256[] calldata countersPadded,
        uint256[] calldata recipientBindHsPadded,
        uint256[] calldata tokenIdsPadded,
        uint256[] calldata amountsNetPadded,
        uint256[] calldata commitmentsOutPadded
    ) external pure returns (uint256[] memory) {
        uint256 maxSlots = commitmentsOutPadded.length;
        // Size = MAX_NOTE_ROOTS_PER_PROOF + 9 + maxSlots*6, equal to the Go builder's
        // `2 + maxNoteRoots + 1 + 6 + maxSlots*6`. The constant 9 = 2 (chainId/pool) + 1
        // (packedTreeNumbers) + 6 scalars (activeTree, countOld, rootNew, countNew, rollover,
        // nRequests). vs buildDepositInputs' "+ 10": the portal vector drops nTotalCommitments
        // (one note per portal deposit) and carries 6 per-slot arrays rather than 4.
        uint256[] memory publicInputs = new uint256[](MAX_NOTE_ROOTS_PER_PROOF + 9 + maxSlots * 6);
        uint256 idx;

        publicInputs[idx++] = chainId;
        publicInputs[idx++] = uint256(uint160(pool));

        (uint256[MAX_NOTE_ROOTS_PER_PROOF] memory packedRoots, uint256 packedTreeNumbers) =
            sparseToPackedRootsWithTreeNumbers(treeState.usedRoots);
        for (uint256 i = 0; i < MAX_NOTE_ROOTS_PER_PROOF; ++i) {
            publicInputs[idx++] = packedRoots[i];
        }
        publicInputs[idx++] = packedTreeNumbers;

        publicInputs[idx++] = treeState.activeTreeNumber;
        publicInputs[idx++] = treeState.countOld;
        publicInputs[idx++] = treeState.rootNew;
        publicInputs[idx++] = treeState.countNew;
        publicInputs[idx++] = treeState.rollover ? 1 : 0;
        publicInputs[idx++] = nRequests;

        // Per-slot tail, array-grouped to match the gnark public-witness serialization order.
        for (uint256 i = 0; i < maxSlots; ++i) {
            publicInputs[idx++] = portalsPadded[i];
        }
        for (uint256 i = 0; i < maxSlots; ++i) {
            publicInputs[idx++] = countersPadded[i];
        }
        for (uint256 i = 0; i < maxSlots; ++i) {
            publicInputs[idx++] = recipientBindHsPadded[i];
        }
        for (uint256 i = 0; i < maxSlots; ++i) {
            publicInputs[idx++] = tokenIdsPadded[i];
        }
        for (uint256 i = 0; i < maxSlots; ++i) {
            publicInputs[idx++] = amountsNetPadded[i];
        }
        for (uint256 i = 0; i < maxSlots; ++i) {
            publicInputs[idx++] = commitmentsOutPadded[i];
        }

        return publicInputs;
    }

    /// @notice Build public inputs for forced withdrawal verification
    /// @dev Layout: [knownRoots(16), packedTreeNumbers, inputCount, spenderAccountId,
    ///              nullifiers(N), inputCommitments(N), digestHi, digestLo,
    ///              withdrawalTo, tokenId, amount, authLeaf, authContext]
    /// @param sparseRoots Sparse (treeNumber, root) pairs to pack for note trees
    /// @param forcedAuthData One pair carrying authContext in treeNumber and authLeaf in root
    /// @param inputCount Number of inputs used (must be <= nullifiersPadded.length)
    /// @param spenderAccountId Account ID used for auth lookup and authorization
    /// @param nullifiersPadded Nullifiers padded to maxInputs
    /// @param inputCommitmentsPadded Input commitments padded to maxInputs
    /// @param digest Forced-withdraw digest (will be split into hi/lo)
    /// @param withdrawalTo Withdrawal recipient
    /// @param tokenId The compact token ID
    /// @param amount The withdrawal amount (gross)
    /// @return publicInputs Flattened public input array for forced withdrawal verification
    function buildForcedWithdrawalInputs(
        TreeRootPair[] calldata sparseRoots,
        TreeRootPair[] calldata forcedAuthData,
        uint256 inputCount,
        uint256 spenderAccountId,
        uint256[] calldata nullifiersPadded,
        uint256[] calldata inputCommitmentsPadded,
        bytes32 digest,
        address withdrawalTo,
        uint16 tokenId,
        uint96 amount
    ) external pure returns (uint256[] memory) {
        uint256 maxInputs = nullifiersPadded.length;
        uint256[] memory publicInputs = new uint256[](MAX_NOTE_ROOTS_PER_PROOF + 1 + 9 + (maxInputs * 2));
        uint256 idx;

        idx = _appendNoteRoots(publicInputs, idx, sparseRoots);

        publicInputs[idx++] = inputCount;
        publicInputs[idx++] = spenderAccountId;

        for (uint256 i = 0; i < maxInputs; ++i) {
            publicInputs[idx++] = nullifiersPadded[i];
        }
        for (uint256 i = 0; i < maxInputs; ++i) {
            publicInputs[idx++] = inputCommitmentsPadded[i];
        }

        publicInputs[idx++] = uint256(digest) >> DIGEST_HALF_BITS;
        publicInputs[idx++] = uint256(digest) & ((uint256(1) << DIGEST_HALF_BITS) - 1);
        publicInputs[idx++] = uint256(uint160(withdrawalTo));
        publicInputs[idx++] = uint256(tokenId);
        publicInputs[idx++] = uint256(amount);
        if (forcedAuthData.length != 1) revert IPrivacyBoost.InvalidForcedAuthContext();
        publicInputs[idx++] = forcedAuthData[0].root;
        publicInputs[idx++] = forcedAuthData[0].treeNumber;

        return publicInputs;
    }

    /// @notice Build public inputs for a private gift-claim epoch (claim/refund batch)
    /// @dev PRIVATE layout: epoch-shaped, modelled on buildEpochInputs. Each slot is a single-input
    ///      single-output re-mint (one gift note consumed, one canonical note minted), so the
    ///      per-slot stride is 1 — unlike the epoch circuit's maxInputs/maxOutputs grid.
    ///      Deliberately carries NO public destination: the private claim and private refund must be
    ///      indistinguishable on chain, so the recipient/sender target is a private witness and only the
    ///      gift nullifier, the minted commitment, and the recomputed approval digest are public.
    ///      `currentBlock` is public in BOTH the claim and refund branches so they keep an
    ///      identical public shape; the contract bounds it to block.number and only the refund
    ///      branch enforces the deadline in-circuit.
    ///      Layout mirrors the circuit's GiftClaimPublicInputs declaration order (gnark public-input
    ///      order == struct field order, the same convention buildEpochInputs follows):
    ///        [knownRoots(16), packedTreeNumbers, authRoots(16), packedAuthTreeNumbers,
    ///         activeTreeNumber, activeTreeRoot, countOld, rootNew, countNew, rollover, nClaims, currentBlock,
    ///         provingTimestamp,
    ///         nullifiers(M), commitments(M), outputTokenIds(M)=0, outputAmounts(M)=0,
    ///         claimDigestHi(M), claimDigestLo(M), branchSelectors(M)]  (M = maxSlots)
    ///      branchSelectors are 1 for the first nClaims slots and 0 for the padded suffix:
    ///      submitGiftClaimEpoch always mints a canonical note in each active slot (append mode);
    ///      public-payout mode (0) is reserved for the gift exit path. The token/amount columns are forced to
    ///      zero in mint mode so a private claim never reveals the gifted value — they are bound only through
    ///      the output commitment here, and revealed only by the public-exit layout (buildGiftExitInputs).
    /// @param treeState Output-tree state (used roots, active tree number, countOld/countNew, rootNew, rollover)
    /// @param usedAuthRoots Sparse (treeNumber, root) pairs for the auth trees referenced by this proof
    /// @param activeTreeRoot Current root of the active output tree (frontier binding; read from storage by the caller)
    /// @param nClaims Number of active claims in the padded fixed-capacity columns
    /// @param giftNullifiers Per-slot gift nullifiers (length = maxSlots)
    /// @param commitmentsOut Per-slot minted output commitments (length = maxSlots)
    /// @param claimDigestHi High halves of per-slot gift-claim approval digests (length = maxSlots)
    /// @param claimDigestLo Low halves of per-slot gift-claim approval digests (length = maxSlots)
    /// @param currentBlock Caller-attested block number bounded by the contract (refund-deadline public input)
    /// @param provingTimestamp Recent UNIX timestamp bounded by the contract (auth-expiry public input)
    /// @return publicInputs Flattened public input array for gift-claim verification
    function buildGiftClaimInputs(
        EpochTreeState calldata treeState,
        TreeRootPair[] calldata usedAuthRoots,
        uint256 activeTreeRoot,
        uint256 nClaims,
        uint256[] calldata giftNullifiers,
        uint256[] calldata commitmentsOut,
        uint256[] calldata claimDigestHi,
        uint256[] calldata claimDigestLo,
        uint256 currentBlock,
        uint64 provingTimestamp
    ) external pure returns (uint256[] memory) {
        uint256 maxSlots = giftNullifiers.length;
        uint256[] memory publicInputs =
            new uint256[](MAX_NOTE_ROOTS_PER_PROOF + 1 + MAX_AUTH_ROOTS_PER_PROOF + 1 + 9 + (maxSlots * 7));
        uint256 idx;

        (uint256[MAX_NOTE_ROOTS_PER_PROOF] memory packedRoots, uint256 packedTreeNumbers) =
            sparseToPackedRootsWithTreeNumbers(treeState.usedRoots);
        for (uint256 i = 0; i < MAX_NOTE_ROOTS_PER_PROOF; ++i) {
            publicInputs[idx++] = packedRoots[i];
        }
        publicInputs[idx++] = packedTreeNumbers;

        (uint256[MAX_AUTH_ROOTS_PER_PROOF] memory packedAuthRoots, uint256 packedAuthTreeNumbers) =
            sparseToPackedAuthRootsWithTreeNumbers(usedAuthRoots);
        for (uint256 i = 0; i < MAX_AUTH_ROOTS_PER_PROOF; ++i) {
            publicInputs[idx++] = packedAuthRoots[i];
        }
        publicInputs[idx++] = packedAuthTreeNumbers;

        // Tree-append state as separate scalars: the gift circuit's GiftClaimPublicInputs exposes
        // individual CountOld/RootNew/CountNew/Rollover fields, not the packed counts word the epoch
        // circuit uses.
        publicInputs[idx++] = treeState.activeTreeNumber;
        publicInputs[idx++] = activeTreeRoot;
        publicInputs[idx++] = treeState.countOld;
        publicInputs[idx++] = treeState.rootNew;
        publicInputs[idx++] = treeState.countNew;
        publicInputs[idx++] = treeState.rollover ? 1 : 0;
        publicInputs[idx++] = nClaims;
        publicInputs[idx++] = currentBlock;
        publicInputs[idx++] = provingTimestamp;

        // Per-slot columns at stride 1, in circuit-declared order.
        for (uint256 s = 0; s < maxSlots; ++s) {
            publicInputs[idx++] = giftNullifiers[s];
        }
        for (uint256 s = 0; s < maxSlots; ++s) {
            publicInputs[idx++] = commitmentsOut[s];
        }
        // Private mint hides token/amount: the circuit forces these public columns to zero in mint mode
        // (BranchSelectors = 1 for every slot here), binding the gifted token/amount only through the output
        // commitment. The public exit (buildGiftExitInputs) is the only path that reveals them.
        for (uint256 s = 0; s < maxSlots; ++s) {
            publicInputs[idx++] = 0;
        }
        for (uint256 s = 0; s < maxSlots; ++s) {
            publicInputs[idx++] = 0;
        }
        for (uint256 s = 0; s < maxSlots; ++s) {
            publicInputs[idx++] = claimDigestHi[s];
        }
        for (uint256 s = 0; s < maxSlots; ++s) {
            publicInputs[idx++] = claimDigestLo[s];
        }
        // Private-mint mode for the active prefix. The padded suffix remains inactive.
        for (uint256 s = 0; s < maxSlots; ++s) {
            publicInputs[idx++] = s < nClaims ? 1 : 0;
        }

        return publicInputs;
    }

    /// @notice Build public inputs for a permissionless public gift exit
    /// @dev The public exit verifies against the SAME gift-claim circuit/VK as the private path, so it uses
    ///      the canonical GiftClaimPublicInputs layout with batchSize 1 in public-payout mode. The destination
    ///      is bound INTO the gift-claim digest (hi/lo) — not as a free public input — so the proof authorizes
    ///      one specific payout target and the contract cannot redirect funds. The exit appends no note, so
    ///      below capacity rootNew == activeTreeRoot and countNew == countOld; a full tree uses the circuit's
    ///      rollover-to-empty representation. Both are proof-only no-ops, and the per-slot
    ///      branchSelector is 0 (payout). The commitmentsOut slot is repurposed as the exact active auth leaf
    ///      for a wallet-recipient or sender-refund exit and is zero only for secret-bearer exits. `currentBlock` is the
    ///      refund-deadline public input; the circuit asserts `currentBlock >= refundAfterBlock`.
    ///      Layout: [knownRoots(16), packedTreeNumbers, authRoots(16), packedAuthTreeNumbers,
    ///               activeTreeNumber, activeTreeRoot, countOld, rootNew, countNew, rollover, nClaims, currentBlock,
    ///               provingTimestamp,
    ///               giftNullifier, exitAuthLeaf, tokenId, amount, digestHi, digestLo, branchSelector]
    /// @param sparseRoots Sparse (treeNumber, root) pairs for the funding note trees
    /// @param usedAuthRoots Sparse (treeNumber, root) pairs for the auth trees referenced by this proof
    /// @param activeTreeNumber Current note tree number (proof-only no-op transition for the exit)
    /// @param activeTreeRoot Current active-tree root
    /// @param treeCount Current active-tree leaf count
    /// @param emptyTreeRoot Canonical empty-tree root used by the circuit's rollover branch
    /// @param fullTreeExit Whether to represent the no-append exit through the circuit's rollover branch
    /// @param giftNullifier The gift nullifier spent by this exit
    /// @param exitAuthLeaf Exact key or Safe-approval leaf, or zero for a secret-bearer exit
    /// @param tokenId The compact token ID
    /// @param amount The gift amount (gross, before fee)
    /// @param digestHi High half of the gift-claim digest (binds the destination)
    /// @param digestLo Low half of the gift-claim digest
    /// @param currentBlock Caller-attested block number bounded by the contract (refund-deadline public input)
    /// @param provingTimestamp Recent UNIX timestamp bounded by the contract (auth-expiry public input)
    /// @return publicInputs Flattened public input array for gift exit verification
    function buildGiftExitInputs(
        TreeRootPair[] calldata sparseRoots,
        TreeRootPair[] calldata usedAuthRoots,
        uint256 activeTreeNumber,
        uint256 activeTreeRoot,
        uint256 treeCount,
        uint256 emptyTreeRoot,
        bool fullTreeExit,
        uint256 giftNullifier,
        uint256 exitAuthLeaf,
        uint256 tokenId,
        uint256 amount,
        uint256 digestHi,
        uint256 digestLo,
        uint256 currentBlock,
        uint64 provingTimestamp
    ) external pure returns (uint256[] memory) {
        uint256[] memory publicInputs =
            new uint256[](MAX_NOTE_ROOTS_PER_PROOF + 1 + MAX_AUTH_ROOTS_PER_PROOF + 1 + 9 + 7);
        uint256 idx;

        (uint256[MAX_NOTE_ROOTS_PER_PROOF] memory packedRoots, uint256 packedTreeNumbers) =
            sparseToPackedRootsWithTreeNumbers(sparseRoots);
        for (uint256 i = 0; i < MAX_NOTE_ROOTS_PER_PROOF; ++i) {
            publicInputs[idx++] = packedRoots[i];
        }
        publicInputs[idx++] = packedTreeNumbers;

        (uint256[MAX_AUTH_ROOTS_PER_PROOF] memory packedAuthRoots, uint256 packedAuthTreeNumbers) =
            sparseToPackedAuthRootsWithTreeNumbers(usedAuthRoots);
        for (uint256 i = 0; i < MAX_AUTH_ROOTS_PER_PROOF; ++i) {
            publicInputs[idx++] = packedAuthRoots[i];
        }
        publicInputs[idx++] = packedAuthTreeNumbers;

        // Tree-append state: a public exit appends nothing. Below capacity this is the ordinary
        // root/count no-op. At capacity the gift-claim circuit rejects a non-rollover CountOld, so use
        // its rollover branch as a proof-only representation: it starts from the empty tree and, with no
        // append, ends at (emptyTreeRoot, 0). publicGiftExit never commits this virtual transition.
        publicInputs[idx++] = activeTreeNumber;
        publicInputs[idx++] = activeTreeRoot;
        publicInputs[idx++] = treeCount; // countOld
        publicInputs[idx++] = fullTreeExit ? emptyTreeRoot : activeTreeRoot; // rootNew
        publicInputs[idx++] = fullTreeExit ? 0 : treeCount; // countNew
        publicInputs[idx++] = fullTreeExit ? 1 : 0; // rollover
        publicInputs[idx++] = 1; // nClaims
        publicInputs[idx++] = currentBlock;
        publicInputs[idx++] = provingTimestamp;

        // Single per-slot column set, in circuit-declared order. branchSelector 0 = public payout: the
        // circuit binds the exact key or Safe-approval leaf, or zero for a secret-bearer exit, without appending a note.
        publicInputs[idx++] = giftNullifier;
        publicInputs[idx++] = exitAuthLeaf;
        publicInputs[idx++] = tokenId;
        publicInputs[idx++] = amount;
        publicInputs[idx++] = digestHi;
        publicInputs[idx++] = digestLo;
        publicInputs[idx++] = 0; // branchSelector: public payout, no append

        return publicInputs;
    }
}
