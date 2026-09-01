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

import {MAX_AUTH_ROOTS_PER_PROOF, MAX_NOTE_ROOTS_PER_PROOF, ROOT_HISTORY_SIZE} from "src/interfaces/Constants.sol";
import {Transfer, Withdrawal, EpochTreeState, TreeRootPair, GatewaySlot} from "src/interfaces/IStructs.sol";
import {IAuthRegistry} from "src/interfaces/IAuthRegistry.sol";
import {IPrivacyBoost, IEpochVerifier} from "src/interfaces/IPrivacyBoost.sol";
import {LibDigest} from "src/lib/LibDigest.sol";
import {LibPublicInputs} from "src/lib/LibPublicInputs.sol";

/// @title LibEpoch
/// @notice Epoch validation, proof verification, and nullifier-spend logic extracted from PrivacyBoost
///         to keep the implementation bytecode under the EIP-170 limit.
/// @dev Deployed as an external delegatecall library. Submission runs against the pool's storage via
///      explicit storage references, so `address(this)` is the pool and `msg.sender` is preserved.
/// @custom:security-contact contact@sunnyside.io
library LibEpoch {
    struct EpochSubmitConfig {
        uint32 maxBatchSize;
        uint32 maxInputsPerTransfer;
        uint32 maxOutputsPerTransfer;
        uint32 maxFeeTokens;
        uint64 maxEpochAuthStalenessBlocks;
        uint8 merkleDepth;
    }

    struct CircuitBounds {
        uint32 maxTransfers;
        uint32 maxInputs;
        uint32 maxOutputs;
    }

    struct TransferDigestResult {
        uint256[][] commitmentsOut;
        uint256[] approveDigestHi;
        uint256[] approveDigestLo;
    }

    // ─────────────── Epoch verify and spend ───────────────

    /// @notice Verify the epoch proof and spend nullifiers. Reverts on invalid calldata or proof.
    /// @param treeRoot Per-tree current root map
    /// @param treeCount Per-tree leaf-count map
    /// @param treeRootHistory Per-tree ring buffer of recent roots
    /// @param treeRootHistoryCursor Per-tree write cursor into that ring buffer
    /// @param nullifierSpent Global spent-nullifier map, written by this call
    /// @param authRegistry Registry consulted for auth-root recency
    /// @param epochVerifier The epoch Groth16 verifier
    /// @param currentTreeNumber The pool's active tree number at entry
    /// @param config Circuit bounds and staleness limits for this epoch
    /// @param treeState The epoch's note-tree state (sparse roots, active tree, counts, new root)
    /// @param usedAuthRoots Sparse (treeNumber, root) pairs for the auth trees this proof references
    /// @param nTransfers Number of active transfers in the epoch
    /// @param feeTokenCount Number of active fee tokens
    /// @param feeNpk Note public key receiving the fee outputs
    /// @param inputsPerTransfer Declared input count per transfer
    /// @param outputsPerTransfer Declared output count per transfer
    /// @param nullifiers Per-transfer nullifiers to spend
    /// @param transfers The epoch's transfers and their outputs
    /// @param feeTransfer The fee transfer and its outputs
    /// @param withdrawals The withdrawals this epoch settles
    /// @param withdrawalSlots Ascending transfer indices the withdrawals attach to
    /// @param provingTimestamp Timestamp the circuit used for auth expiry checks
    /// @param proof The Groth16 proof over the built public inputs
    /// @param gatewaySlots Gateway settlement slots, index-aligned with the routed withdrawals
    function verifyAndSpend(
        mapping(uint256 => uint256) storage treeRoot,
        mapping(uint256 => uint32) storage treeCount,
        mapping(uint256 => uint256[ROOT_HISTORY_SIZE]) storage treeRootHistory,
        mapping(uint256 => uint256) storage treeRootHistoryCursor,
        mapping(uint256 => bool) storage nullifierSpent,
        IAuthRegistry authRegistry,
        IEpochVerifier epochVerifier,
        uint256 currentTreeNumber,
        EpochSubmitConfig calldata config,
        EpochTreeState calldata treeState,
        TreeRootPair[] calldata usedAuthRoots,
        uint32 nTransfers,
        uint32 feeTokenCount,
        uint256 feeNpk,
        uint32[] calldata inputsPerTransfer,
        uint32[] calldata outputsPerTransfer,
        uint256[][] calldata nullifiers,
        Transfer[] calldata transfers,
        Transfer calldata feeTransfer,
        Withdrawal[] calldata withdrawals,
        uint32[] calldata withdrawalSlots,
        uint64 provingTimestamp,
        uint256[8] calldata proof,
        GatewaySlot[] calldata gatewaySlots
    ) external {
        CircuitBounds memory bounds = _validateCircuitShape(
            config, nTransfers, inputsPerTransfer, outputsPerTransfer, nullifiers, transfers, feeTransfer
        );

        uint256 activeRoot = _validateStateAndRoots(
            treeRoot,
            treeCount,
            treeRootHistory,
            treeRootHistoryCursor,
            authRegistry,
            currentTreeNumber,
            config,
            treeState,
            usedAuthRoots
        );

        _validateFeeTokenCount(config, feeTokenCount);
        // Validated before capacity because the marker deduction below trusts that every slot is
        // distinct and inside the active range.
        _validateWithdrawalSlots(withdrawalSlots, withdrawals.length, nTransfers);
        _validateTreeCapacity(config, treeState, outputsPerTransfer, nTransfers, feeTokenCount, withdrawals.length);

        TransferDigestResult memory digestResult = _computeTransferDigests(
            inputsPerTransfer,
            outputsPerTransfer,
            nullifiers,
            transfers,
            withdrawals,
            withdrawalSlots,
            bounds,
            nTransfers,
            gatewaySlots
        );

        _validateSlotPadding(
            nullifiers,
            digestResult.commitmentsOut,
            inputsPerTransfer,
            outputsPerTransfer,
            nTransfers,
            bounds.maxTransfers,
            bounds.maxInputs,
            bounds.maxOutputs
        );

        _verifyProof(
            epochVerifier,
            config,
            bounds,
            treeState,
            usedAuthRoots,
            activeRoot,
            provingTimestamp,
            nTransfers,
            nullifiers,
            feeTokenCount,
            feeNpk,
            feeTransfer,
            digestResult,
            withdrawalSlots,
            proof
        );

        _spendNullifiers(nullifierSpent, nullifiers, inputsPerTransfer, nTransfers);
    }

    // ─────────────── Shared tree validation ───────────────

    /// @dev Shared by every tree appender so rollover and leaf-count invariants have one implementation.
    /// @param merkleDepth Depth of the tree being appended to
    /// @param countOld Leaf count before the append
    /// @param countNew Leaf count claimed after the append
    /// @param totalOutputs Number of leaves the append adds
    /// @param rollover True when this append starts a fresh tree
    function validateTreeCapacity(
        uint8 merkleDepth,
        uint32 countOld,
        uint32 countNew,
        uint256 totalOutputs,
        bool rollover
    ) external pure {
        _requireTreeCapacity(merkleDepth, countOld, countNew, totalOutputs, rollover);
    }

    // ─────────────── Internal helpers ───────────────

    function _validateCircuitShape(
        EpochSubmitConfig calldata config,
        uint32 nTransfers,
        uint32[] calldata inputsPerTransfer,
        uint32[] calldata outputsPerTransfer,
        uint256[][] calldata nullifiers,
        Transfer[] calldata transfers,
        Transfer calldata feeTransfer
    ) private pure returns (CircuitBounds memory bounds) {
        bounds.maxTransfers = uint32(nullifiers.length);

        bool invalidCircuitSize = (bounds.maxTransfers == 0) || (bounds.maxTransfers > config.maxBatchSize);
        bool invalidTransferCount = (nTransfers == 0) || (nTransfers > bounds.maxTransfers);
        if (invalidCircuitSize || invalidTransferCount) revert IPrivacyBoost.InvalidEpochConfig();

        bool mismatchedCountArrays =
            (inputsPerTransfer.length != bounds.maxTransfers) || (outputsPerTransfer.length != bounds.maxTransfers);
        bool mismatchedTransferArrays =
            (transfers.length != bounds.maxTransfers) || (feeTransfer.outputs.length != config.maxFeeTokens);
        if (mismatchedCountArrays || mismatchedTransferArrays) {
            revert IPrivacyBoost.InvalidArrayLengths();
        }

        bounds.maxInputs = uint32(nullifiers[0].length);
        bounds.maxOutputs = uint32(transfers[0].outputs.length);
        if (bounds.maxInputs == 0 || bounds.maxInputs > config.maxInputsPerTransfer) {
            revert IPrivacyBoost.InvalidEpochConfig();
        }
        if (bounds.maxOutputs == 0 || bounds.maxOutputs > config.maxOutputsPerTransfer) {
            revert IPrivacyBoost.InvalidEpochConfig();
        }

        for (uint256 t = 0; t < bounds.maxTransfers; ++t) {
            if (nullifiers[t].length != bounds.maxInputs || transfers[t].outputs.length != bounds.maxOutputs) {
                revert IPrivacyBoost.InvalidArrayLengths();
            }
            if (t < nTransfers) {
                if (inputsPerTransfer[t] == 0 || inputsPerTransfer[t] > bounds.maxInputs) {
                    revert IPrivacyBoost.InvalidEpochConfig();
                }
                if (outputsPerTransfer[t] == 0 || outputsPerTransfer[t] > bounds.maxOutputs) {
                    revert IPrivacyBoost.InvalidEpochConfig();
                }
            } else {
                if (inputsPerTransfer[t] != 0 || outputsPerTransfer[t] != 0) {
                    revert IPrivacyBoost.InvalidEpochConfig();
                }
            }
        }
    }

    function _validateStateAndRoots(
        mapping(uint256 => uint256) storage treeRoot,
        mapping(uint256 => uint32) storage treeCount,
        mapping(uint256 => uint256[ROOT_HISTORY_SIZE]) storage treeRootHistory,
        mapping(uint256 => uint256) storage treeRootHistoryCursor,
        IAuthRegistry authRegistry,
        uint256 currentTreeNumber,
        EpochSubmitConfig calldata config,
        EpochTreeState calldata treeState,
        TreeRootPair[] calldata usedAuthRoots
    ) private view returns (uint256 activeRoot) {
        if (treeState.activeTreeNumber != currentTreeNumber) {
            revert IPrivacyBoost.InvalidEpochState();
        }
        if (treeState.countOld != treeCount[treeState.activeTreeNumber]) revert IPrivacyBoost.InvalidEpochState();

        _validateEpochKnownRoots(
            treeRoot, treeRootHistory, treeRootHistoryCursor, currentTreeNumber, treeState.usedRoots
        );

        activeRoot = treeRoot[treeState.activeTreeNumber];
        _validateUsedAuthRoots(authRegistry, usedAuthRoots, config.maxEpochAuthStalenessBlocks);
    }

    function _validateFeeTokenCount(EpochSubmitConfig calldata config, uint32 feeTokenCount) private pure {
        if (feeTokenCount == 0 || feeTokenCount > config.maxFeeTokens) {
            revert IPrivacyBoost.InvalidEpochConfig();
        }
    }

    /// @dev Withdrawal output zero is a marker for a public payout, never a spendable leaf, so each
    ///      withdrawal contributes one fewer leaf than it contributes output commitments. The
    ///      subtraction cannot underflow: every active slot has at least one output and withdrawal
    ///      slots are distinct and below nTransfers, so withdrawalCount <= nTransfers <= totalOutputs.
    function _validateTreeCapacity(
        EpochSubmitConfig calldata config,
        EpochTreeState calldata treeState,
        uint32[] calldata outputsPerTransfer,
        uint32 nTransfers,
        uint32 feeTokenCount,
        uint256 withdrawalCount
    ) private pure {
        uint32 totalOutputs = 0;
        for (uint256 t = 0; t < nTransfers; ++t) {
            totalOutputs += outputsPerTransfer[t];
        }
        _requireTreeCapacity(
            config.merkleDepth,
            treeState.countOld,
            treeState.countNew,
            uint256(totalOutputs) + feeTokenCount - withdrawalCount,
            treeState.rollover
        );
    }

    function _requireTreeCapacity(
        uint8 merkleDepth,
        uint32 countOld,
        uint32 countNew,
        uint256 totalOutputs,
        bool rollover
    ) private pure {
        uint256 maxLeaves = uint256(1) << merkleDepth;
        uint256 expectedCountNew = rollover ? totalOutputs : uint256(countOld) + totalOutputs;
        if (rollover && countOld != maxLeaves) revert IPrivacyBoost.InvalidEpochState();
        if (!rollover && uint256(countOld) >= maxLeaves) revert IPrivacyBoost.InvalidEpochState();
        if (countNew != expectedCountNew || expectedCountNew > maxLeaves) revert IPrivacyBoost.InvalidEpochState();
    }

    /// @dev Active slots must be non-zero and inactive slots zero, binding per-transfer counts
    ///      between the circuit and contract so a padded slot cannot be interpreted as active.
    function _validateSlotPadding(
        uint256[][] calldata nullifiers,
        uint256[][] memory commitmentsOut,
        uint32[] calldata inputsPerTransfer,
        uint32[] calldata outputsPerTransfer,
        uint32 nTransfers,
        uint32 transferCount,
        uint32 circuitMaxInputs,
        uint32 circuitMaxOutputs
    ) private pure {
        for (uint256 t = 0; t < transferCount; ++t) {
            uint32 nIn = t < nTransfers ? inputsPerTransfer[t] : 0;
            uint32 nOut = t < nTransfers ? outputsPerTransfer[t] : 0;

            for (uint256 i = 0; i < circuitMaxInputs; ++i) {
                if ((nullifiers[t][i] != 0) != (i < nIn)) revert IPrivacyBoost.InvalidSlotPadding();
            }
            for (uint256 j = 0; j < circuitMaxOutputs; ++j) {
                if ((commitmentsOut[t][j] != 0) != (j < nOut)) revert IPrivacyBoost.InvalidSlotPadding();
            }
        }
    }

    function _computeTransferDigests(
        uint32[] calldata inputsPerTransfer,
        uint32[] calldata outputsPerTransfer,
        uint256[][] calldata nullifiers,
        Transfer[] calldata transfers,
        Withdrawal[] calldata withdrawals,
        uint32[] calldata withdrawalSlots,
        CircuitBounds memory bounds,
        uint32 nTransfers,
        GatewaySlot[] calldata gatewaySlots
    ) private view returns (TransferDigestResult memory result) {
        result.approveDigestHi = new uint256[](bounds.maxTransfers);
        result.approveDigestLo = new uint256[](bounds.maxTransfers);
        result.commitmentsOut = new uint256[][](bounds.maxTransfers);
        uint256 withdrawalsLen = withdrawals.length;
        uint256 withdrawalCursor = 0;
        uint256 gatewayCursor = 0;

        for (uint256 t = 0; t < bounds.maxTransfers; ++t) {
            result.commitmentsOut[t] = new uint256[](bounds.maxOutputs);
            if (t >= nTransfers) continue;

            for (uint256 j = 0; j < bounds.maxOutputs; ++j) {
                result.commitmentsOut[t][j] = transfers[t].outputs[j].commitment;
            }

            uint32 nInputs = inputsPerTransfer[t];
            uint32 nOutputs = outputsPerTransfer[t];

            // t < maxTransfers, which is derived from PrivacyBoost.maxBatchSize (uint16-bounded).
            // forge-lint: disable-next-line(unsafe-typecast)
            if (withdrawalCursor < withdrawalsLen && withdrawalSlots[withdrawalCursor] == uint32(t)) {
                Withdrawal calldata withdrawal = withdrawals[withdrawalCursor];
                if (withdrawal.amount == 0) revert IPrivacyBoost.InvalidWithdrawal();

                uint256 expectedCommitment =
                    LibDigest.computeWithdrawalCommitment(withdrawal.to, withdrawal.tokenId, withdrawal.amount);
                if (transfers[t].outputs[0].commitment != expectedCommitment) revert IPrivacyBoost.InvalidWithdrawal();

                bool gatewayPaired = gatewayCursor < gatewaySlots.length
                    && uint256(gatewaySlots[gatewayCursor].withdrawalIndex) == withdrawalCursor;
                if (gatewayPaired) {
                    (result.approveDigestHi[t], result.approveDigestLo[t]) = LibDigest.computeGatewayWithdrawalDigest(
                        block.chainid,
                        address(this),
                        nullifiers[t][:nInputs],
                        transfers[t].outputs[:nOutputs],
                        withdrawal,
                        transfers[t].viewingKey,
                        transfers[t].teeWrapKey,
                        gatewaySlots[gatewayCursor]
                    );
                    ++gatewayCursor;
                } else {
                    (result.approveDigestHi[t], result.approveDigestLo[t]) = LibDigest.computeWithdrawalDigest(
                        block.chainid,
                        address(this),
                        nullifiers[t][:nInputs],
                        transfers[t].outputs[:nOutputs],
                        withdrawal,
                        transfers[t].viewingKey,
                        transfers[t].teeWrapKey
                    );
                }
                ++withdrawalCursor;
            } else {
                (result.approveDigestHi[t], result.approveDigestLo[t]) = LibDigest.computeTransferDigest(
                    block.chainid,
                    address(this),
                    nullifiers[t][:nInputs],
                    transfers[t].outputs[:nOutputs],
                    transfers[t].viewingKey,
                    transfers[t].teeWrapKey
                );
            }
        }

        if (withdrawalCursor != withdrawalsLen) revert IPrivacyBoost.InvalidArrayLengths();
        if (gatewayCursor != gatewaySlots.length) revert IPrivacyBoost.InvalidGatewaySlot();
    }

    function _validateWithdrawalSlots(uint32[] calldata withdrawalSlots, uint256 withdrawalsLen, uint32 nTransfers)
        private
        pure
    {
        if (withdrawalSlots.length != withdrawalsLen) revert IPrivacyBoost.InvalidArrayLengths();
        uint32 prevSlot = 0;
        for (uint256 i = 0; i < withdrawalSlots.length; ++i) {
            uint32 slot = withdrawalSlots[i];
            if (slot >= nTransfers) revert IPrivacyBoost.InvalidWithdrawal();
            if (i > 0 && slot <= prevSlot) {
                revert IPrivacyBoost.WithdrawalSlotsNotStrictAscending(i, prevSlot, slot);
            }
            prevSlot = slot;
        }
    }

    function _verifyProof(
        IEpochVerifier epochVerifier,
        EpochSubmitConfig calldata config,
        CircuitBounds memory bounds,
        EpochTreeState calldata treeState,
        TreeRootPair[] calldata usedAuthRoots,
        uint256 activeRoot,
        uint64 provingTimestamp,
        uint32 nTransfers,
        uint256[][] calldata nullifiers,
        uint32 feeTokenCount,
        uint256 feeNpk,
        Transfer calldata feeTransfer,
        TransferDigestResult memory digestResult,
        uint32[] calldata withdrawalSlots,
        uint256[8] calldata proof
    ) private view {
        uint256[] memory feeCommitmentsOut = _buildFeeCommitments(feeTransfer, config.maxFeeTokens);
        // Commitments cover every slot up to maxFeeTokens, but the digest covers
        // only the active prefix. That asymmetry is sound solely because the
        // indexer decrypts the same active prefix, so inactive slot metadata is
        // never a recipient's discovery channel. Widening the indexer's fee-note
        // loop past feeTokenCount without widening this slice would leave the
        // newly-read metadata unauthenticated again.
        (uint256 feeTransferDigestHi, uint256 feeTransferDigestLo) = LibDigest.computeFeeTransferDigest(
            block.chainid,
            address(this),
            feeTransfer.outputs[:feeTokenCount],
            feeTransfer.viewingKey,
            feeTransfer.teeWrapKey
        );
        uint256[] memory publicInputs = LibPublicInputs.buildEpochInputs(
            treeState,
            usedAuthRoots,
            activeRoot,
            provingTimestamp,
            nTransfers,
            nullifiers,
            digestResult.commitmentsOut,
            digestResult.approveDigestHi,
            digestResult.approveDigestLo,
            feeTokenCount,
            feeNpk,
            feeCommitmentsOut,
            feeTransferDigestHi,
            feeTransferDigestLo,
            bounds.maxInputs,
            bounds.maxOutputs,
            config.maxFeeTokens,
            LibPublicInputs.packWithdrawalMask(withdrawalSlots, bounds.maxTransfers)
        );

        epochVerifier.verifyEpoch(bounds.maxTransfers, bounds.maxInputs, bounds.maxOutputs, proof, publicInputs);
    }

    function _buildFeeCommitments(Transfer calldata feeTransfer, uint32 feeCount)
        private
        pure
        returns (uint256[] memory feeCommitmentsOut)
    {
        feeCommitmentsOut = new uint256[](feeCount);
        for (uint256 i = 0; i < feeCount; ++i) {
            feeCommitmentsOut[i] = feeTransfer.outputs[i].commitment;
        }
    }

    function _spendNullifiers(
        mapping(uint256 => bool) storage nullifierSpent,
        uint256[][] calldata nullifiers,
        uint32[] calldata inputsPerTransfer,
        uint32 nTransfers
    ) private {
        for (uint256 t = 0; t < nTransfers; ++t) {
            uint32 nInputs = inputsPerTransfer[t];
            for (uint256 i = 0; i < nInputs; ++i) {
                uint256 nullifier = nullifiers[t][i];
                if (nullifier == 0) revert IPrivacyBoost.InvalidNullifierSet();
                if (nullifierSpent[nullifier]) revert IPrivacyBoost.InvalidNullifierSet();
                nullifierSpent[nullifier] = true;
            }
        }
    }

    function _validateEpochKnownRoots(
        mapping(uint256 => uint256) storage treeRoot,
        mapping(uint256 => uint256[ROOT_HISTORY_SIZE]) storage treeRootHistory,
        mapping(uint256 => uint256) storage treeRootHistoryCursor,
        uint256 currentTreeNumber,
        TreeRootPair[] calldata sparseRoots
    ) private view {
        uint256 len = sparseRoots.length;
        if (len == 0 || len > MAX_NOTE_ROOTS_PER_PROOF) revert IPrivacyBoost.InvalidBatchConfig();

        for (uint256 i = 0; i < len; ++i) {
            uint256 treeNum = sparseRoots[i].treeNumber;
            uint256 root = sparseRoots[i].root;

            for (uint256 j = 0; j < i; ++j) {
                if (sparseRoots[j].treeNumber == treeNum && sparseRoots[j].root == root) {
                    revert IPrivacyBoost.DuplicateTreeRootPair();
                }
            }

            if (!_isKnownTreeRoot(treeRoot, treeRootHistory, treeRootHistoryCursor, currentTreeNumber, treeNum, root)) {
                revert IPrivacyBoost.RootNotKnown();
            }
        }
    }

    function _isKnownTreeRoot(
        mapping(uint256 => uint256) storage treeRoot,
        mapping(uint256 => uint256[ROOT_HISTORY_SIZE]) storage treeRootHistory,
        mapping(uint256 => uint256) storage treeRootHistoryCursor,
        uint256 currentTreeNumber,
        uint256 treeNum,
        uint256 root_
    ) private view returns (bool) {
        if (root_ == 0) return false;
        if (treeRoot[treeNum] == root_) return true;
        if (treeNum < currentTreeNumber) return false;

        uint256 idx = treeRootHistoryCursor[treeNum];
        for (uint256 i = 0; i < ROOT_HISTORY_SIZE; ++i) {
            if (treeRootHistory[treeNum][idx] == root_) return true;
            unchecked {
                idx = (idx + ROOT_HISTORY_SIZE - 1) % ROOT_HISTORY_SIZE;
            }
        }
        return false;
    }

    function _validateUsedAuthRoots(
        IAuthRegistry authRegistry,
        TreeRootPair[] calldata usedAuthRoots,
        uint64 maxStalenessBlocks
    ) private view {
        uint256 len = usedAuthRoots.length;
        if (len == 0 || len > MAX_AUTH_ROOTS_PER_PROOF) revert IPrivacyBoost.InvalidBatchConfig();

        for (uint256 i = 0; i < len; ++i) {
            uint256 treeNum = usedAuthRoots[i].treeNumber;
            for (uint256 j = 0; j < i; ++j) {
                if (usedAuthRoots[j].treeNumber == treeNum) revert IPrivacyBoost.DuplicateTreeNumber();
            }
        }

        if (!authRegistry.areRecentAuthTreeRoots(usedAuthRoots, maxStalenessBlocks)) {
            revert IPrivacyBoost.RootNotKnown();
        }
    }
}
