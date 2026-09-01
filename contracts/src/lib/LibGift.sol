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

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {TOKEN_TYPE_ERC20, ROOT_HISTORY_SIZE, BASIS_POINTS} from "src/interfaces/Constants.sol";
import {EpochTreeState, TreeRootPair, Output} from "src/interfaces/IStructs.sol";
import {IPrivacyBoost, IGiftClaimVerifier} from "src/interfaces/IPrivacyBoost.sol";
import {ITokenRegistry} from "src/interfaces/ITokenRegistry.sol";
import {LibDigest} from "src/lib/LibDigest.sol";
import {LibPoolShared} from "src/lib/LibPoolShared.sol";
import {LibPublicInputs} from "src/lib/LibPublicInputs.sol";

/// @title LibGift
/// @notice Claimable-transfer (gift) helpers extracted from PrivacyBoost to keep the implementation bytecode
///         under the EIP-170 limit, exactly like LibPortal / LibForced / LibEpoch. Deployed as an external
///         (delegatecall) library, so every function runs in the calling pool's context: `address(this)`,
///         `block.*`, and pool storage all resolve to the pool, not the library.
/// @dev The pool wrapper keeps the `nonReentrant`/`onlyRelay` guard and ALL validation (batch/array/block
///      checks, the tree-state CAS, `_validateKnownRoots` / `_validateUsedAuthRoots` / `_validateTreeCapacity`,
///      and the token-registry / nullifier pre-checks) plus the one value-type write a delegatecall library
///      cannot perform — the `currentTreeNumber` advance + `TreeAdvanced` on rollover. It then forwards the
///      pool's tree + nullifier mappings BY REFERENCE and the verifier / token-registry / treasury reads BY
///      VALUE (immutables and value-type state are baked into the pool's bytecode, not reachable from the
///      library). The storage-heavy remainder — the per-claim digest loop, public-input build, proof verify,
///      tree-mapping writes, payouts, and events — runs here, against the pool's storage under delegatecall.
/// @custom:security-contact contact@sunnyside.io
library LibGift {
    using SafeERC20 for IERC20;

    /// @notice Storage-heavy remainder of PrivacyBoost.submitGiftClaimEpoch: the per-claim nullifier spend +
    ///         digest loop, the public-input build, the proof verify, the tree-mapping writes, and the
    ///         settlement events. The wrapper validated every input (batch/array/block/CAS/known-roots/auth-
    ///         roots/capacity) and performed the value-type `currentTreeNumber` advance before calling this.
    /// @dev `activeRoot` (= treeRoot[activeTreeNumber]) and `maxSlots` (= outputs.length) are computed by the
    ///      wrapper and passed in. The tree mappings are passed by reference; the gift-claim verifier is read
    ///      from pool storage and passed by value (a delegatecall library cannot read the caller's immutables).
    /// @param treeRoot Per-tree current root map
    /// @param treeCount Per-tree leaf-count map
    /// @param treeRootHistory Per-tree ring buffer of recent roots
    /// @param treeRootHistoryCursor Per-tree write cursor into that ring buffer
    /// @param nullifierSpent Global spent-nullifier map, written per claim
    /// @param giftClaimVerifier The gift-claim Groth16 verifier
    /// @param maxBatchSize Maximum claims permitted in one epoch
    /// @param treeState The epoch's note-tree state, already CAS-validated by the caller
    /// @param usedAuthRoots Sparse (treeNumber, root) pairs for the auth trees this proof references
    /// @param giftNullifiers The gift nullifiers this epoch spends, one per claim
    /// @param outputs The note outputs the epoch appends
    /// @param digestRootIndices Packed 4-bit `usedAuthRoots` slot index per claim, 64 per word
    /// @param currentBlock Caller-attested block number bounded by the wrapper (refund-deadline public input)
    /// @param provingTimestamp Timestamp the circuit used for auth expiry checks
    /// @param proof The Groth16 proof over the built public inputs
    function submitGiftClaimEpoch(
        mapping(uint256 => uint256) storage treeRoot,
        mapping(uint256 => uint32) storage treeCount,
        mapping(uint256 => uint256[ROOT_HISTORY_SIZE]) storage treeRootHistory,
        mapping(uint256 => uint256) storage treeRootHistoryCursor,
        mapping(uint256 => bool) storage nullifierSpent,
        IGiftClaimVerifier giftClaimVerifier,
        uint32 maxBatchSize,
        EpochTreeState calldata treeState,
        TreeRootPair[] calldata usedAuthRoots,
        uint256[] calldata giftNullifiers,
        Output[] calldata outputs,
        uint256[] calldata digestRootIndices,
        uint256 currentBlock,
        uint64 provingTimestamp,
        uint256[8] calldata proof
    ) external {
        // maxSlots (= outputs.length) and activeRoot (= treeRoot[activeTreeNumber]) are derived here rather
        // than passed, keeping the pool wrapper's stack shallow for the via-IR pipeline. The gift-specific
        // input validation below also runs here, moved off the wrapper with the rest of the gift logic to fit
        // the EIP-170 limit; the wrapper already performed the tree-state CAS + known/auth-root + capacity
        // checks and the value-type currentTreeNumber advance, so a revert here unwinds that advance atomically.
        uint32 maxSlots = uint32(outputs.length);
        uint256 nClaims = giftNullifiers.length;

        // maxSlots is bounded by the epoch transfer max and by the verifier's VK registry. nClaims carries
        // the active prefix length independently, so one registered shape can verify smaller padded batches.
        if (nClaims == 0 || nClaims > maxSlots || maxSlots > maxBatchSize) {
            revert IPrivacyBoost.InvalidEpochConfig();
        }
        if (!giftClaimVerifier.hasVerifyingKey(maxSlots)) revert IPrivacyBoost.InvalidEpochConfig();

        // digestRootIndices packs one 4-bit usedRoots slot index per claim (64 per word). Validate canonical
        // encoding: exactly enough words to cover the batch, with the last word's unused high nibbles zeroed.
        {
            uint256 expectedDigestRootWords = (nClaims + 63) / 64;
            if (digestRootIndices.length != expectedDigestRootWords) revert IPrivacyBoost.InvalidArrayLengths();
            uint256 lastWordUsedSlots = nClaims & 63;
            if (
                lastWordUsedSlots != 0 && digestRootIndices[expectedDigestRootWords - 1] >> (lastWordUsedSlots * 4) != 0
            ) {
                revert IPrivacyBoost.NonCanonicalEncoding();
            }
        }

        // currentBlock is a circuit public input the relay attests; it must not be in the future so the proof
        // binds a block that has occurred (the gift nullifier, not block freshness, prevents replay).
        if (currentBlock > block.number) revert IPrivacyBoost.GiftClaimBlockInFuture();

        uint256 activeRoot = treeRoot[treeState.activeTreeNumber];

        // Each slot mints exactly one canonical note; no fee outputs in v1 (recipient gets the full amount).
        uint256[] memory commitmentsOut = new uint256[](maxSlots);
        uint256[] memory claimDigestHi = new uint256[](maxSlots);
        uint256[] memory claimDigestLo = new uint256[](maxSlots);
        uint256[] memory giftNullifiersMem = new uint256[](maxSlots);

        for (uint256 s = 0; s < nClaims; ++s) {
            uint256 nullifier = giftNullifiers[s];
            if (nullifier == 0) revert IPrivacyBoost.InvalidNullifierSet();
            // Shared nullifier map: a claim and a refund of the same gift are mutually exclusive, and a
            // gift cannot be claimed twice in or across batches.
            if (nullifierSpent[nullifier]) revert IPrivacyBoost.InvalidNullifierSet();
            nullifierSpent[nullifier] = true;

            // Retain the packed index as a canonical declaration of the proof's sparse-root slot. Gift
            // authorization v2 does not sign this mutable root. The circuit binds gift membership and the
            // active append root separately, so root-history churn cannot stale an otherwise valid approval.
            uint256 word = digestRootIndices[s / 64];
            uint256 slotIdx = (word >> ((s % 64) * 4)) & 0xF;
            if (slotIdx >= treeState.usedRoots.length) revert IPrivacyBoost.InvalidBatchConfig();

            // Private mint mode hides token/amount: the mint digest mirrors the transfer digest and binds the
            // minted Output (commitment + per-output key material), which already commits to the gift token
            // and amount — so neither is forwarded as cleartext. viewingKey/teeWrapKey are carried inside the
            // Output, so they pass as zero here.
            (claimDigestHi[s], claimDigestLo[s]) = LibDigest.computeGiftClaimDigest(
                block.chainid, address(this), nullifier, outputs[s], bytes32(0), bytes32(0)
            );

            commitmentsOut[s] = outputs[s].commitment;
            giftNullifiersMem[s] = nullifier;
        }

        uint256[] memory publicInputs = LibPublicInputs.buildGiftClaimInputs(
            treeState,
            usedAuthRoots,
            activeRoot,
            nClaims,
            giftNullifiersMem,
            commitmentsOut,
            claimDigestHi,
            claimDigestLo,
            currentBlock,
            provingTimestamp
        );

        giftClaimVerifier.verifyGiftClaim(maxSlots, proof, publicInputs);

        // Tree-state mapping writes (the value-type `currentTreeNumber` advance + `TreeAdvanced` already
        // happened in the wrapper). The target tree is the active tree, or the next one on rollover — the
        // wrapper enforced activeTreeNumber == currentTreeNumber and the rollover bound, so this matches the
        // value the wrapper advanced `currentTreeNumber` to. Mirrors LibPortal.submitPortalDepositEpoch.
        uint256 targetTree = treeState.rollover ? treeState.activeTreeNumber + 1 : treeState.activeTreeNumber;
        treeRoot[targetTree] = treeState.rootNew;
        treeCount[targetTree] = treeState.countNew;
        LibPoolShared.pushTreeRoot(treeRootHistory, treeRootHistoryCursor, targetTree, treeState.rootNew);

        // Emit one undifferentiated settlement event per slot. Claim and refund are deliberately
        // indistinguishable on chain (identical public shape, shared nullifier, private BranchType witness),
        // so the contract emits a single GiftSettled rather than a claim-vs-refund label a public observer
        // could read off the logs. The operator recovers the true branch from its own off-chain request record.
        for (uint256 s = 0; s < nClaims; ++s) {
            emit IPrivacyBoost.GiftSettled(giftNullifiers[s], outputs[s].commitment);
        }
    }

    /// @notice Storage-heavy remainder of PrivacyBoost.publicGiftExit: the exit digest, public-input build,
    ///         proof verify, fee math, payout, and event. The wrapper validated destination / nullifier /
    ///         block / token-registry, checked the nullifier unspent, and read `treeNum` + `activeRoot` (via
    ///         `_validateKnownRoots`) + the exact active auth-leaf check before calling this.
    /// @dev Mirrors LibForced.executeForcedWithdrawal: the `tokenRegistry` immutable and the `treasury` /
    ///      `withdrawFeeBps` state are passed by value since a delegatecall library cannot read the pool's
    ///      immutables, and the nullifier map is passed by reference. `nullifierSpent` is set before the
    ///      payout (checks-effects-interactions) so the external transfer cannot re-enter into a second spend;
    ///      the pool's `nonReentrant` wrapper guard is the primary protection.
    /// @param nullifierSpent Global spent-nullifier map, written before the payout
    /// @param giftClaimVerifier The gift-claim Groth16 verifier
    /// @param tokenRegistry Registry used to resolve the token id to its ERC-20
    /// @param treasury Address receiving the withdrawal fee
    /// @param withdrawFeeBps Withdraw fee rate in basis points, quoted once and held through settlement
    /// @param knownRoots Sparse (treeNumber, root) pairs for the funding note trees
    /// @param usedAuthRoots Sparse (treeNumber, root) pairs for the auth trees referenced by this proof
    /// @param treeNum Note tree number the exit transitions through (a proof-only no-op for the exit)
    /// @param activeRoot Active-tree root the proof was built against
    /// @param activeTreeCount Caller-attested leaf count paired with `activeRoot`
    /// @param emptyTreeRoot Canonical empty-tree root used by the circuit's rollover branch
    /// @param fullTreeExit Whether to represent the no-append exit through the circuit's rollover branch
    /// @param giftNullifier The gift nullifier spent by this exit
    /// @param exitAuthLeaf Exact key or Safe-approval leaf, or zero for a secret-bearer exit
    /// @param destination Address receiving the net payout, bound into the exit digest
    /// @param tokenId The compact token ID
    /// @param amount The gift amount (gross, before fee)
    /// @param minNetAmount Payout floor bound into the digest, enforced after the fee
    /// @param viewingKey Viewing key bound into the exit digest
    /// @param teeWrapKey Wrapping key bound into the exit digest
    /// @param currentBlock Caller-attested block number bounded by the wrapper (refund-deadline public input)
    /// @param provingTimestamp Recent UNIX timestamp bounded by the wrapper (auth-expiry public input)
    /// @param proof The Groth16 proof over the built public inputs
    function publicGiftExit(
        mapping(uint256 => bool) storage nullifierSpent,
        IGiftClaimVerifier giftClaimVerifier,
        ITokenRegistry tokenRegistry,
        address treasury,
        uint16 withdrawFeeBps,
        TreeRootPair[] calldata knownRoots,
        TreeRootPair[] calldata usedAuthRoots,
        uint256 treeNum,
        uint256 activeRoot,
        uint32 activeTreeCount,
        uint256 emptyTreeRoot,
        bool fullTreeExit,
        uint256 giftNullifier,
        uint256 exitAuthLeaf,
        address destination,
        uint16 tokenId,
        uint96 amount,
        uint96 minNetAmount,
        bytes32 viewingKey,
        bytes32 teeWrapKey,
        uint256 currentBlock,
        uint64 provingTimestamp,
        uint256[8] calldata proof
    ) external {
        // Input validation moved off the pool wrapper (which keeps only the tree-number + exact auth-leaf slot check
        // that need its internal helpers) to fit the EIP-170 limit; fail-fast before the digest/verify.
        if (destination == address(0)) revert IPrivacyBoost.InvalidWithdrawal();
        if (giftNullifier == 0) revert IPrivacyBoost.InvalidNullifierSet();
        // currentBlock is the proof's block public input the caller attests; it must not be in the future so
        // an off-chain-built proof can anchor a recent past block instead of predicting its inclusion block.
        if (currentBlock > block.number) revert IPrivacyBoost.GiftClaimBlockInFuture();

        // Quote once and retain it through settlement. The minimum is part of the proof-bound digest below,
        // so a caller cannot loosen another user's payout floor. Checking it before token resolution and the
        // Groth16 pairing makes a stale, fee-adverse proof fail cheaply; a fee decrease remains executable and
        // simply pays the destination more than its minimum.
        // forge-lint: disable-next-line(unsafe-typecast) fee <= 10% of uint96 amount
        uint96 feeAmount = uint96((uint256(amount) * withdrawFeeBps) / BASIS_POINTS);
        uint96 netAmount = amount - feeAmount;
        if (netAmount < minNetAmount) revert IPrivacyBoost.GiftExitSlippage(minNetAmount, netAmount);
        // Validate tokenId so a malformed token can't reach the payout after a wasted verify, and keep the
        // resolved ERC-20 address to reuse for the transfer legs below — only the address (not tokenType too)
        // stays live across the deep public-input build, so the stack headroom the scoping protects is kept.
        address tokenAddress;
        {
            uint8 tokenType;
            (tokenType, tokenAddress,) = tokenRegistry.tokenOf(tokenId);
            if (tokenAddress == address(0)) revert IPrivacyBoost.InvalidWithdrawal();
            if (tokenType != TOKEN_TYPE_ERC20) revert IPrivacyBoost.TokenNotSupported(tokenType);
        }
        // Shared nullifier map: this exit is mutually exclusive with a private claim/refund — whoever spends
        // the gift nullifier first wins; the rest revert here.
        if (nullifierSpent[giftNullifier]) revert IPrivacyBoost.InvalidNullifierSet();

        // The destination is bound INTO the gift-exit digest, so the proof authorizes one specific payout
        // target and the contract cannot redirect funds. A public exit mints no note, so it uses the
        // withdrawal-style exit digest (destination + token + gross amount + minimum net), not the
        // commitment-bound mint digest.
        (uint256 digestHi, uint256 digestLo) = LibDigest.computeGiftExitDigest(
            block.chainid,
            address(this),
            giftNullifier,
            destination,
            tokenId,
            amount,
            minNetAmount,
            viewingKey,
            teeWrapKey
        );

        // Canonical GiftClaimPublicInputs layout: batchSize 1, public-payout mode (no append), and the
        // caller-attested currentBlock (validated <= block.number in the wrapper) so the circuit's refund
        // branch can enforce the deadline in-proof. activeTreeCount is likewise caller-attested (not read from
        // live treeCount) — the count paired with the historical activeRoot the proof was built against, so
        // the refund exit does not go stale when later epochs advance the live count; the proof binds the pair.
        uint256[] memory publicInputs = LibPublicInputs.buildGiftExitInputs(
            knownRoots,
            usedAuthRoots,
            treeNum,
            activeRoot,
            activeTreeCount,
            emptyTreeRoot,
            fullTreeExit,
            giftNullifier,
            exitAuthLeaf,
            tokenId,
            amount,
            digestHi,
            digestLo,
            currentBlock,
            provingTimestamp
        );

        giftClaimVerifier.verifyGiftClaim(1, proof, publicInputs);

        // The current fee quote was checked against the proof-bound minimum before verification. Mark spent
        // before paying out (checks-effects-interactions) so an external transfer cannot re-enter a second spend.
        nullifierSpent[giftNullifier] = true;

        _transferTokenResolved(tokenAddress, destination, netAmount);
        if (feeAmount > 0 && treasury != address(0)) {
            _transferTokenResolved(tokenAddress, treasury, feeAmount);
        }

        emit IPrivacyBoost.GiftExitExecuted(destination, tokenId, netAmount, giftNullifier);
    }

    /// @dev `safeTransfer` `amount` of the already-resolved ERC-20 `tokenAddress` to `to`. publicGiftExit
    ///      resolves and validates the token once via tokenRegistry.tokenOf before the verify, so each payout
    ///      leg reuses that address instead of repeating the registry lookup; the address-typed parameter
    ///      means a caller structurally cannot reach the transfer without having resolved the token first.
    function _transferTokenResolved(address tokenAddress, address to, uint96 amount) private {
        IERC20(tokenAddress).safeTransfer(to, amount);
    }
}
