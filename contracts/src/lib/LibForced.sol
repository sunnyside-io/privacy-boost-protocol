// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2026 Sunnyside Labs Inc.
 * Licensed under the Apache License, Version 2.0.
 */
pragma solidity 0.8.34;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {BASIS_POINTS} from "src/interfaces/Constants.sol";
import {Withdrawal, ForcedWithdrawalRequest, TreeRootPair} from "src/interfaces/IStructs.sol";
import {IPrivacyBoost, IForcedWithdrawVerifier} from "src/interfaces/IPrivacyBoost.sol";
import {IAuthRegistry} from "src/interfaces/IAuthRegistry.sol";
import {ITokenRegistry} from "src/interfaces/ITokenRegistry.sol";
import {LibDigest} from "src/lib/LibDigest.sol";
import {LibPoolShared} from "src/lib/LibPoolShared.sol";
import {LibPublicInputs} from "src/lib/LibPublicInputs.sol";

/// @title LibForced
/// @notice Minimal forced-withdrawal escape hatch with snapshot authorization.
/// @dev Authorization is checked exactly once when a request is accepted. A pending request is thereafter
///      independent of AuthRegistry mutation: it either executes after the delay, is explicitly cancelled by
///      the account owner, or is pruned after a competing nullifier spend makes execution impossible.
/// @custom:security-contact contact@sunnyside.io
library LibForced {
    using SafeERC20 for IERC20;

    bytes32 private constant REQUEST_KEY_DOMAIN = keccak256("PB:FORCED_REQUEST_KEY:SNAPSHOT:v1");

    uint256 private constant AUTH_MODE_SHIFT = 64;
    uint256 private constant AUTH_INDEX_SHIFT = 65;
    uint256 private constant AUTH_TREE_SHIFT = 85;
    uint256 private constant AUTH_VERSION_SHIFT = 100;
    uint256 private constant AUTH_CONTEXT_USED_BITS = 108;
    uint8 private constant AUTH_CONTEXT_VERSION = 1;
    uint8 private constant AUTH_MODE_APPROVAL = 1;
    uint256 private constant AUTH_INDEX_MASK = (1 << 20) - 1;
    uint256 private constant AUTH_TREE_MASK = (1 << 15) - 1;

    struct DecodedAuthContext {
        uint64 expiry;
        uint8 mode;
        uint16 treeNumber;
        uint32 leafIndex;
    }

    // ─────────────── Forced-withdrawal lifecycle ───────────────

    /// @notice Verify and record a snapshot-authorized forced-withdrawal request.
    /// @dev Executes by delegatecall against PrivacyBoost storage. The core validates parallel-array lengths,
    ///      input bounds, the withdrawal destination, token support, and sparse roots before calling this suffix.
    ///      This function validates unspent inputs and live authorization, verifies the proof, snapshots the fee and
    ///      payout, reserves each input commitment, and emits the request event.
    /// @param nullifierSpent Pool nullifier-spend map used to reject already-spent inputs.
    /// @param commitmentToRequestKey Pool reservation map used to reject and record commitment conflicts.
    /// @param forcedWithdrawalRequests Pool request map where the verified snapshot is stored.
    /// @param forcedVerifier Verifier used for the padded forced-withdrawal public inputs.
    /// @param authRegistry Registry used to resolve the live authorization leaf at request time.
    /// @param maxForcedInputs Circuit input width and maximum accepted input count.
    /// @param withdrawFeeBps Current withdrawal fee snapshotted into the request.
    /// @param knownRoots Prevalidated sparse note-tree roots bound into the proof.
    /// @param forcedAuthData Single packed authorization context and authorization identifier.
    /// @param spenderAccountId Account identifier bound into the authorization and proof.
    /// @param nullifiers Nullifiers for the notes being spent.
    /// @param inputCommitments Commitments for the notes being spent and reserved.
    /// @param withdrawal Gross payout destination, token ID, and amount.
    /// @param proof Groth16 proof of note ownership and the requested public inputs.
    function requestForcedWithdrawalSuffix(
        mapping(uint256 => bool) storage nullifierSpent,
        mapping(uint256 => uint256) storage commitmentToRequestKey,
        mapping(uint256 => ForcedWithdrawalRequest) storage forcedWithdrawalRequests,
        IForcedWithdrawVerifier forcedVerifier,
        IAuthRegistry authRegistry,
        uint32 maxForcedInputs,
        uint16 withdrawFeeBps,
        TreeRootPair[] calldata knownRoots,
        TreeRootPair[] calldata forcedAuthData,
        uint256 spenderAccountId,
        uint256[] calldata nullifiers,
        uint256[] calldata inputCommitments,
        Withdrawal calldata withdrawal,
        uint256[8] calldata proof
    ) external {
        uint256 inputLen = nullifiers.length;
        _validateFreshRequest(nullifierSpent, commitmentToRequestKey, nullifiers, inputCommitments, inputLen);

        (uint128 authContext, bytes32 authId) = _decodeForcedAuthData(forcedAuthData);
        DecodedAuthContext memory auth = _decodeAuthContext(authContext);
        _requireLiveAtRequest(auth);

        (uint256 authLeaf, bool authLive) = _resolveLiveAuth(authRegistry, authId, auth);
        if (!authLive) revert IPrivacyBoost.ForcedAuthorizationInvalid();

        bytes32 digest = LibDigest.computeForcedWithdrawalDigest(
            block.chainid,
            address(this),
            spenderAccountId,
            auth.mode,
            nullifiers,
            inputCommitments,
            withdrawal,
            withdrawFeeBps
        );

        uint256 maxInputs = uint256(maxForcedInputs);
        uint256[] memory nullifiersPadded = new uint256[](maxInputs);
        uint256[] memory inputCommitmentsPadded = new uint256[](maxInputs);
        for (uint256 i = 0; i < inputLen; ++i) {
            nullifiersPadded[i] = nullifiers[i];
            inputCommitmentsPadded[i] = inputCommitments[i];
        }

        TreeRootPair[] memory proofAuthData = new TreeRootPair[](1);
        proofAuthData[0] = TreeRootPair({treeNumber: authContext, root: authLeaf});
        uint256[] memory publicInputs = LibPublicInputs.buildForcedWithdrawalInputs(
            knownRoots,
            proofAuthData,
            inputLen,
            spenderAccountId,
            nullifiersPadded,
            inputCommitmentsPadded,
            digest,
            withdrawal.to,
            withdrawal.tokenId,
            withdrawal.amount
        );
        forcedVerifier.verifyForcedWithdraw(maxForcedInputs, proof, publicInputs);

        bytes32 nullifiersHash = keccak256(abi.encodePacked(nullifiers));
        bytes32 commitmentsHash = keccak256(abi.encodePacked(inputCommitments));
        uint256 requestKey = _snapshotRequestKey(nullifiersHash, commitmentsHash);
        // forge-lint: disable-next-line(unsafe-typecast) realistic chains cannot approach uint64.max blocks
        uint64 requestBlock = uint64(block.number);
        forcedWithdrawalRequests[requestKey] = ForcedWithdrawalRequest({
            requestBlock: requestBlock,
            requester: address(0),
            withdrawalTo: withdrawal.to,
            tokenId: withdrawal.tokenId,
            amount: withdrawal.amount,
            withdrawFeeBps: withdrawFeeBps,
            // forge-lint: disable-next-line(unsafe-typecast) checked by the core
            inputCount: uint8(inputLen),
            spenderAccountId: spenderAccountId,
            nullifiersHash: nullifiersHash,
            commitmentsHash: commitmentsHash
        });

        for (uint256 i = 0; i < inputLen; ++i) {
            commitmentToRequestKey[inputCommitments[i]] = requestKey;
        }

        emit IPrivacyBoost.ForcedWithdrawalRequested(
            msg.sender,
            spenderAccountId,
            withdrawal.to,
            withdrawal.tokenId,
            withdrawal.amount,
            withdrawFeeBps,
            nullifiers,
            inputCommitments
        );
    }

    /// @notice Execute a snapshot-authorized request, including layout-frozen requests accepted pre-upgrade.
    /// @param nullifierSpent Global spent-nullifier map, written by this call
    /// @param commitmentToRequestKey Map from input commitment to its request key
    /// @param forcedWithdrawalRequests Map of pending forced-withdrawal requests
    /// @param tokenRegistry Registry used to resolve the token id to its ERC-20
    /// @param treasury Address receiving the withdrawal fee
    /// @param forcedWithdrawalDelay The delay that must elapse before execution is allowed
    /// @param maxForcedInputs Maximum inputs permitted in one forced withdrawal
    /// @param nullifiers The nullifiers this withdrawal spends
    /// @param inputCommitments The input commitments identifying the request
    function executeForcedWithdrawal(
        mapping(uint256 => bool) storage nullifierSpent,
        mapping(uint256 => uint256) storage commitmentToRequestKey,
        mapping(uint256 => ForcedWithdrawalRequest) storage forcedWithdrawalRequests,
        ITokenRegistry tokenRegistry,
        address treasury,
        uint256 forcedWithdrawalDelay,
        uint32 maxForcedInputs,
        uint256[] calldata nullifiers,
        uint256[] calldata inputCommitments
    ) external {
        (ForcedWithdrawalRequest storage request, uint256 requestKey, uint256 inputLen) = _loadAndValidateRequest(
            commitmentToRequestKey, forcedWithdrawalRequests, maxForcedInputs, true, nullifiers, inputCommitments
        );
        if (block.number < uint256(request.requestBlock) + forcedWithdrawalDelay) {
            revert IPrivacyBoost.ForcedWithdrawalTooEarly();
        }
        _requireUnspent(nullifierSpent, nullifiers, inputLen);

        address withdrawalTo = request.withdrawalTo;
        uint16 tokenId = request.tokenId;
        uint96 amount = request.amount;
        uint16 feeBps = request.withdrawFeeBps;
        delete forcedWithdrawalRequests[requestKey];
        _settle(
            nullifierSpent,
            commitmentToRequestKey,
            tokenRegistry,
            treasury,
            withdrawalTo,
            tokenId,
            amount,
            feeBps,
            requestKey,
            nullifiers,
            inputCommitments,
            inputLen
        );
    }

    /// @notice Cancel explicitly, or prune a request that a competing nullifier spend made impossible.
    /// @dev The stored requester is ignored. Only the current account owner is a cancellation principal.
    /// @param nullifierSpent Global spent-nullifier map, read to detect a competing spend
    /// @param commitmentToRequestKey Map from input commitment to its request key
    /// @param forcedWithdrawalRequests Map of pending forced-withdrawal requests, cleared by this call
    /// @param authRegistry Registry consulted to authenticate the current account owner
    /// @param maxForcedInputs Maximum inputs permitted in one forced withdrawal
    /// @param nullifiers The nullifiers of the request being cancelled or pruned
    /// @param inputCommitments The input commitments identifying the request
    function cancelForcedWithdrawal(
        mapping(uint256 => bool) storage nullifierSpent,
        mapping(uint256 => uint256) storage commitmentToRequestKey,
        mapping(uint256 => ForcedWithdrawalRequest) storage forcedWithdrawalRequests,
        IAuthRegistry authRegistry,
        uint32 maxForcedInputs,
        uint256[] calldata nullifiers,
        uint256[] calldata inputCommitments
    ) external {
        (ForcedWithdrawalRequest storage request, uint256 requestKey, uint256 inputLen) = _loadAndValidateRequest(
            commitmentToRequestKey, forcedWithdrawalRequests, maxForcedInputs, false, nullifiers, inputCommitments
        );
        bool ownerCancel = msg.sender == authRegistry.ownerOf(request.spenderAccountId);
        bool prunable = _hasSpentNullifier(nullifierSpent, nullifiers, inputLen);
        if (!ownerCancel && !prunable) revert IPrivacyBoost.NotAccountOwner();

        _clearCommitmentBindings(commitmentToRequestKey, inputCommitments, requestKey, inputLen);
        delete forcedWithdrawalRequests[requestKey];
        if (ownerCancel) {
            emit IPrivacyBoost.ForcedWithdrawalCancelled(nullifiers, inputCommitments);
        } else {
            emit IPrivacyBoost.ForcedWithdrawalPruned(nullifiers, inputCommitments);
        }
    }

    // ─────────────── Internal helpers ───────────────

    function _validateFreshRequest(
        mapping(uint256 => bool) storage nullifierSpent,
        mapping(uint256 => uint256) storage commitmentToRequestKey,
        uint256[] calldata nullifiers,
        uint256[] calldata inputCommitments,
        uint256 inputLen
    ) private view {
        for (uint256 i = 0; i < inputLen; ++i) {
            if (nullifiers[i] == 0 || nullifierSpent[nullifiers[i]]) {
                revert IPrivacyBoost.InvalidNullifierSet();
            }
            if (inputCommitments[i] == 0) revert IPrivacyBoost.InvalidSlotPadding();
            if (commitmentToRequestKey[inputCommitments[i]] != 0) {
                revert IPrivacyBoost.ForcedWithdrawalAlreadyRequested();
            }
            for (uint256 j = 0; j < i; ++j) {
                if (nullifiers[j] == nullifiers[i]) revert IPrivacyBoost.DuplicateNullifier();
                if (inputCommitments[j] == inputCommitments[i]) revert IPrivacyBoost.DuplicateInputCommitment();
            }
        }
    }

    function _candidateRequest(
        mapping(uint256 => uint256) storage commitmentToRequestKey,
        uint32 maxForcedInputs,
        bool enforceMaxInputs,
        uint256[] calldata nullifiers,
        uint256[] calldata inputCommitments
    ) private view returns (uint256 requestKey, uint256 inputLen) {
        inputLen = inputCommitments.length;
        if (inputLen == 0 || nullifiers.length != inputLen) revert IPrivacyBoost.InvalidArrayLengths();
        // The maxForcedInputs bound caps proof size and is enforced at request and execute time. Cancel and
        // prune deliberately skip it so a request accepted before a maxForcedInputs downgrade (an upgrade to
        // an implementation with a smaller bound) stays cancellable; otherwise its commitment bindings would
        // be locked with no way to release them.
        if (enforceMaxInputs && inputLen > maxForcedInputs) revert IPrivacyBoost.InvalidEpochConfig();
        requestKey = commitmentToRequestKey[inputCommitments[0]];
        if (requestKey == 0) revert IPrivacyBoost.ForcedWithdrawalNotRequested();
    }

    function _loadAndValidateRequest(
        mapping(uint256 => uint256) storage commitmentToRequestKey,
        mapping(uint256 => ForcedWithdrawalRequest) storage forcedWithdrawalRequests,
        uint32 maxForcedInputs,
        bool enforceMaxInputs,
        uint256[] calldata nullifiers,
        uint256[] calldata inputCommitments
    ) private view returns (ForcedWithdrawalRequest storage request, uint256 requestKey, uint256 inputLen) {
        (requestKey, inputLen) =
            _candidateRequest(commitmentToRequestKey, maxForcedInputs, enforceMaxInputs, nullifiers, inputCommitments);
        request = forcedWithdrawalRequests[requestKey];
        if (request.requestBlock == 0) {
            revert IPrivacyBoost.ForcedWithdrawalNotRequested();
        }
        if (inputLen != request.inputCount) revert IPrivacyBoost.ForcedWithdrawalMismatch();
        if (keccak256(abi.encodePacked(nullifiers)) != request.nullifiersHash) {
            revert IPrivacyBoost.ForcedWithdrawalMismatch();
        }
        if (keccak256(abi.encodePacked(inputCommitments)) != request.commitmentsHash) {
            revert IPrivacyBoost.ForcedWithdrawalMismatch();
        }
        _requireCommitmentBindings(commitmentToRequestKey, inputCommitments, requestKey, inputLen);
    }

    function _snapshotRequestKey(bytes32 nullifiersHash, bytes32 commitmentsHash) private pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(REQUEST_KEY_DOMAIN, nullifiersHash, commitmentsHash)));
    }

    function _decodeForcedAuthData(TreeRootPair[] calldata forcedAuthData)
        private
        pure
        returns (uint128 authContext, bytes32 authId)
    {
        if (forcedAuthData.length != 1 || forcedAuthData[0].treeNumber > type(uint128).max) {
            revert IPrivacyBoost.InvalidForcedAuthContext();
        }
        // forge-lint: disable-next-line(unsafe-typecast) range checked immediately above
        authContext = uint128(forcedAuthData[0].treeNumber);
        authId = bytes32(forcedAuthData[0].root);
        if (authId == bytes32(0)) revert IPrivacyBoost.InvalidForcedAuthContext();
    }

    function _resolveLiveAuth(IAuthRegistry authRegistry, bytes32 authId, DecodedAuthContext memory auth)
        private
        view
        returns (uint256 leaf, bool live)
    {
        uint16 treeNumber;
        uint32 leafIndex;
        bool revoked;
        bool exists;
        if (auth.mode == AUTH_MODE_APPROVAL) {
            (treeNumber, leafIndex, revoked, exists, leaf) = authRegistry.getSpendApprovalBatchInfo(authId);
        } else {
            (treeNumber, leafIndex, revoked, exists, leaf) = authRegistry.getAuthKeyInfo(authId);
        }
        live = exists && !revoked && leaf != 0 && treeNumber == auth.treeNumber && leafIndex == auth.leafIndex;
    }

    /// @dev Bits 65 through 99 are registry locators. The circuit binds the complete packed context but delegates
    ///      locator interpretation to this decoder and exact-record validation to `_resolveLiveAuth`.
    function _decodeAuthContext(uint128 context) private pure returns (DecodedAuthContext memory auth) {
        uint256 raw = uint256(context);
        if (raw >> AUTH_CONTEXT_USED_BITS != 0) revert IPrivacyBoost.InvalidForcedAuthContext();
        // forge-lint: disable-next-line(unsafe-typecast) higher bits are rejected above
        uint8 version = uint8(raw >> AUTH_VERSION_SHIFT);
        if (version != AUTH_CONTEXT_VERSION) revert IPrivacyBoost.InvalidForcedAuthContext();
        // forge-lint: disable-next-line(unsafe-typecast) low 64 bits are the encoded uint64 field
        auth.expiry = uint64(raw);
        // forge-lint: disable-next-line(unsafe-typecast) value is masked to one bit
        auth.mode = uint8((raw >> AUTH_MODE_SHIFT) & 1);
        // forge-lint: disable-next-line(unsafe-typecast) value is masked to 20 bits
        auth.leafIndex = uint32((raw >> AUTH_INDEX_SHIFT) & AUTH_INDEX_MASK);
        // forge-lint: disable-next-line(unsafe-typecast) value is masked to 15 bits
        auth.treeNumber = uint16((raw >> AUTH_TREE_SHIFT) & AUTH_TREE_MASK);
        if (auth.mode == AUTH_MODE_APPROVAL && auth.expiry == 0) {
            revert IPrivacyBoost.InvalidForcedAuthContext();
        }
    }

    function _requireLiveAtRequest(DecodedAuthContext memory auth) private view {
        if (auth.expiry != 0 && block.timestamp > auth.expiry) {
            revert IPrivacyBoost.ForcedAuthorizationExpired();
        }
    }

    function _requireUnspent(
        mapping(uint256 => bool) storage nullifierSpent,
        uint256[] calldata nullifiers,
        uint256 inputLen
    ) private view {
        for (uint256 i = 0; i < inputLen; ++i) {
            if (nullifierSpent[nullifiers[i]]) revert IPrivacyBoost.InvalidNullifierSet();
        }
    }

    function _hasSpentNullifier(
        mapping(uint256 => bool) storage nullifierSpent,
        uint256[] calldata nullifiers,
        uint256 inputLen
    ) private view returns (bool) {
        for (uint256 i = 0; i < inputLen; ++i) {
            if (nullifierSpent[nullifiers[i]]) return true;
        }
        return false;
    }

    function _requireCommitmentBindings(
        mapping(uint256 => uint256) storage commitmentToRequestKey,
        uint256[] calldata inputCommitments,
        uint256 requestKey,
        uint256 inputLen
    ) private view {
        for (uint256 i = 0; i < inputLen; ++i) {
            if (commitmentToRequestKey[inputCommitments[i]] != requestKey) {
                revert IPrivacyBoost.ForcedWithdrawalMismatch();
            }
        }
    }

    function _clearCommitmentBindings(
        mapping(uint256 => uint256) storage commitmentToRequestKey,
        uint256[] calldata inputCommitments,
        uint256 requestKey,
        uint256 inputLen
    ) private {
        for (uint256 i = 0; i < inputLen; ++i) {
            if (commitmentToRequestKey[inputCommitments[i]] != requestKey) {
                revert IPrivacyBoost.ForcedWithdrawalMismatch();
            }
            delete commitmentToRequestKey[inputCommitments[i]];
        }
    }

    function _settle(
        mapping(uint256 => bool) storage nullifierSpent,
        mapping(uint256 => uint256) storage commitmentToRequestKey,
        ITokenRegistry tokenRegistry,
        address treasury,
        address withdrawalTo,
        uint16 tokenId,
        uint96 grossAmount,
        uint16 feeBps,
        uint256 requestKey,
        uint256[] calldata nullifiers,
        uint256[] calldata inputCommitments,
        uint256 inputLen
    ) private {
        for (uint256 i = 0; i < inputLen; ++i) {
            nullifierSpent[nullifiers[i]] = true;
        }
        _clearCommitmentBindings(commitmentToRequestKey, inputCommitments, requestKey, inputLen);

        // A missing treasury waives the fee so consuming the request cannot strand part of its gross amount.
        // The emitted payout is therefore the gross amount whenever the fee is waived.
        // forge-lint: disable-next-line(unsafe-typecast) feeBps is bounded by BASIS_POINTS in the pool
        uint96 feeAmount = treasury == address(0) ? 0 : uint96((uint256(grossAmount) * feeBps) / BASIS_POINTS);
        uint96 payoutAmount = grossAmount - feeAmount;
        LibPoolShared.transferToken(tokenRegistry, tokenId, withdrawalTo, payoutAmount);
        if (feeAmount > 0) {
            LibPoolShared.transferToken(tokenRegistry, tokenId, treasury, feeAmount);
        }
        emit IPrivacyBoost.ForcedWithdrawalExecuted(withdrawalTo, tokenId, payoutAmount, nullifiers, inputCommitments);
    }
}
