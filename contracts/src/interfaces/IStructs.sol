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

/// @notice Token registry entry
struct TokenInfo {
    uint8 tokenType;
    address tokenAddress;
    uint256 tokenSubId;
}

/// @notice Legacy 65-byte ECDSA signature tuple.
struct EcdsaSig {
    uint8 v;
    bytes32 r;
    bytes32 s;
}

/// @notice Per-output published metadata (calldata ABI shape)
/// Encrypted payload: senderAccountId(32) + recipientAccountId(32) + tokenId(2) + amount(12) + noteRnd(16) = 94B
/// AES-256-GCM output: 110B = ciphertext(94B) || tag(16B)
struct Output {
    uint256 commitment; // 32B
    bytes32 receiverWrapKey; // 32B: wrapped ephemeral key for receiver (256-bit security)
    bytes32 ct0; // 32B: ciphertext[0:32]
    bytes32 ct1; // 32B: ciphertext[32:64]
    bytes32 ct2; // 32B: ciphertext[64:94] + 2B padding
    bytes16 ct3; // 16B: tag
}

// Total: 176B

/// @notice Transfer metadata with shared keys and outputs
struct Transfer {
    bytes32 viewingKey; // 32B: blinded sender viewing key for ECDH
    bytes32 teeWrapKey; // 32B: wrapped ephemeral key for TEE (256-bit security)
    Output[] outputs; // Per-output data
}

/// @notice Public in -> private out
struct Deposit {
    uint32 t;
    address from;
    uint16 tokenId;
    uint96 amount;
}

/// @notice Private in -> public out
struct Withdrawal {
    address to;
    uint16 tokenId;
    uint96 amount;
}

enum DepositOrigin {
    UserShield,
    GatewayRedeposit
}

/// @notice Pending deposit request for 2-step deposit
/// @dev Supports multiple commitments per request with hidden individual amounts.
///      Only totalAmount is public; individual amounts are in encrypted ciphertext.
///      Append-only: `rescueCommitment` is the Gateway trailing field. Pre-Gateway deposits read 0.
struct PendingDeposit {
    address depositor;
    uint16 tokenId;
    uint96 totalAmount; // Total amount (public, sum of hidden individual amounts)
    uint64 requestBlock;
    uint32 nonce;
    uint16 commitmentCount; // Number of commitments in this request (supports up to 65535)
    uint256 commitmentsHash; // Sequential Poseidon hash: Hash(Hash(...Hash(0, c0), c1), ..., cN)
    bytes32 rescueCommitment; // Gateway: 0 for normal deposits; nonzero classifies gateway-origin
}

/// @notice Pending portal-deposit record for the hidden-recipient portal sweep flow
/// @dev Mirrors PendingDeposit but binds to the registered portal owner instead of a
///      caller-supplied commitments hash. A portal sweeper never knows the recipient
///      recipientMPK, so it cannot precompute a note commitment at sweep time; the record
///      therefore stores the owner binding H (read from E's account-side portal binding, never
///      caller-supplied) and a per-portal counter, and the epoch builds the note commitment from these.
///      Like the deposit path, "processed" is tracked in a separate mapping
///      (processedPortalDeposits), not as a struct field, so the record stays one word
///      smaller and the processed flag is a single cheap SSTORE.
///      The sweep fee, when enabled, belongs to `sweeper`, the requestPortalDeposit caller
///      who did the keeper work and paid its gas, not the epoch submitter. The payee must be
///      recorded at sweep time so an immediate payment or a deferred same-recipient claim
///      cannot be redirected by the relay.
struct PortalPendingDeposit {
    // Field order packs the record into 4 slots: {portal, requestBlock, tokenId, sweepFeeBps} |
    // {sweeper, amount} | counter | recipientBindH — one fewer SSTORE per sweep than the naive order.
    address portal; // E — the portal address that was swept
    uint64 requestBlock; // for the cancel delay
    uint16 tokenId;
    uint16 sweepFeeBps; // fee rate snapshotted at sweep time (0 in the operator-run MVP)
    address sweeper; // the requestPortalDeposit caller and fixed fee recipient
    uint96 amount; // gross received delta of the pool, capped at uint96 max; credited note = amount − fee
    uint256 counter; // portalCounter[E] at sweep time; feeds noteRnd so repeated sweeps stay unique
    uint256 recipientBindH; // H = E's portalBinding() at sweep time; never caller-supplied
}

/// @notice Encrypted deposit payload for TEE decryption
/// Encrypted payload: recipientAccountId(32) + tokenId(2) + amount(12) + noteRnd(16) = 62B
/// AES-256-GCM output: 78B = ciphertext(62B) || tag(16B)
struct DepositCiphertext {
    bytes32 viewingKey; // 32B: blinded sender viewing key for ECDH
    bytes32 teeWrapKey; // 32B: wrapped ephemeral key for TEE (256-bit security)
    bytes32 receiverWrapKey; // 32B: wrapped ephemeral key for receiver (256-bit security)
    bytes32 ct0; // 32B: ciphertext[0:32]
    bytes32 ct1; // 32B: ciphertext[32:62] + 2B padding
    bytes16 ct2; // 16B: tag
}

// Total: 176B

/// @notice Entry for processing a deposit in submitDepositEpoch
struct DepositEntry {
    uint256 depositRequestId;
}

/// @notice Entry for crediting a portal deposit in submitPortalDepositEpoch
/// @dev Portal analog of DepositEntry. Carries only the portalDepositId; the appended note
///      commitment travels in a parallel commitments[] array (one note per entry) rather than the
///      Output[] structs the normal deposit epoch uses, because a portal note carries no recipient
///      ciphertext (the sweeper has no recipientMPK to encrypt for).
struct PortalDepositEntry {
    uint256 portalDepositId;
}

/// @notice Pending forced withdrawal request for 2-step forced withdrawal
/// @dev This layout is frozen for proxy compatibility. The requester field is retained but ignored by the current
///      policy because permissionless proof relayers are not cancellation principals. Each commitment maps to the
///      request key through commitmentToRequestKey.
struct ForcedWithdrawalRequest {
    uint64 requestBlock; // Block number when requested
    address requester; // Legacy requester, retained only for storage compatibility
    address withdrawalTo; // Withdrawal destination address
    uint16 tokenId; // Token ID
    uint96 amount; // Withdrawal amount (gross, before fee)
    uint16 withdrawFeeBps; // Fee rate at request time (prevents fee changes from affecting pending requests)
    uint8 inputCount; // Number of input notes
    uint256 spenderAccountId; // Account ID for owner lookup via AuthRegistry
    bytes32 nullifiersHash; // keccak256(abi.encodePacked(nullifiers)) for verification
    bytes32 commitmentsHash; // keccak256(abi.encodePacked(commitments)) for verification
}

/// @notice Sparse tree root entry
struct TreeRootPair {
    uint256 treeNumber;
    uint256 root;
}

/// @notice Tree state for epoch submissions
struct EpochTreeState {
    TreeRootPair[] usedRoots;
    uint256 activeTreeNumber;
    uint32 countOld;
    uint256 rootNew;
    uint32 countNew;
    bool rollover;
}

/// @notice Per-root freshness anchor for non-current roots.
/// @dev supersededBlock == 0 means this root has not been superseded as a tracked historical root.
struct RootAnchor {
    uint64 supersededBlock;
}

/// @notice Batched auth-root freshness status for preflight callers.
struct AuthRootStatus {
    uint256 treeNumber;
    uint256 root;
    bool isCurrent;
    bool isRecent;
    uint64 supersededBlock;
    uint64 remainingBlocks;
}

/// @notice Packed auth key info for storage efficiency
struct AuthKeyInfo {
    uint16 treeNumber; // Tree number where the auth key is registered
    uint32 treeIndex; // Index within the tree
    uint32 listIndex; // 1-indexed position in _authKeyList (0 = not exists)
    bool revoked; // Whether the auth key has been revoked
}

/// @notice Packed spend approval info for storage efficiency
struct SpendApprovalInfo {
    uint16 treeNumber; // Tree number where the approval leaf is registered
    uint32 treeIndex; // Index within the tree
    bool revoked; // Whether the approval leaf has been revoked
    bool exists; // Whether this approval id has been used
}

/// @notice Packed account info for storage efficiency (owner + nonce in single slot)
struct AccountInfo {
    address owner; // 20 bytes: account owner
    uint96 nonce; // 12 bytes: replay protection nonce (2^96 is sufficient)
}

/// @notice Packed auth tree state for storage efficiency
struct AuthTreeState {
    uint256 root; // 32 bytes: current tree root (slot 1)
    uint64 cursor; // deprecated root-history cursor, kept for proxy storage compatibility
    uint32 leafCount; // 4 bytes: number of leaves in tree
    // 20 bytes remaining in slot 2
}

// ────────────────────────── Gateway Actions ──────────────────────────
// GatewayRoute.Sync is the legacy route name for registered gateway executors.
// Actions are intentionally generic: product-specific meaning lives in signed
// calldata plus the server-side adapter policy.

/// @notice Routes that approved gateways take. None is the default for unapproved addresses.
enum GatewayRoute {
    None,
    Sync
}

/// @notice Gateway actions. Zero is invalid so omitted/default action fields fail closed.
enum GatewayAction {
    Invalid,
    ExternalCall
}

/// @notice Settlement outcome for a gateway-origin deposit.
/// @dev `Failed` is reserved for ABI compatibility; fatal simulation failures revert instead.
enum GatewaySettlementOutcome {
    Executed,
    Fallback,
    Failed
}

/// @notice Rescue authorization kind, bound into the EIP-191 signed payload.
enum RescueKind {
    GatewayDeposit
}

/// @notice The user's future-private receipt for any gateway action.
struct GatewayReceipt {
    uint16 outputTokenId;
    uint96 minOutputAmount;
    uint256 npk; // strict BN254 field element
    bytes32 rescueCommitment; // key credential `(pubkey, salt)` or domain-separated authority `(authority, salt)`
    DepositCiphertext ciphertext; // gateway-origin: encrypts recipientMPK + noteRnd, amount=0 (authoritative amount = on-chain measuredOutputAmount)
}

/// @notice Sparse gateway slot paired with a withdrawal by withdrawalIndex.
struct GatewaySlot {
    uint16 withdrawalIndex;
    GatewayAction action;
    uint64 expiryBlock;
    address target;
    bytes callData;
    GatewayReceipt receipt;
    GatewayReceipt fallbackReceipt;
}
