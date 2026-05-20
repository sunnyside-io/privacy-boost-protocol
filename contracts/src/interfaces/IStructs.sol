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

/// @notice Pending deposit request for 2-step deposit
/// @dev Supports multiple commitments per request with hidden individual amounts.
///      Only totalAmount is public; individual amounts are in encrypted ciphertext.
struct PendingDeposit {
    address depositor;
    uint16 tokenId;
    uint96 totalAmount; // Total amount (public, sum of hidden individual amounts)
    uint64 requestBlock;
    uint32 nonce;
    uint16 commitmentCount; // Number of commitments in this request (supports up to 65535)
    uint256 commitmentsHash; // Sequential Poseidon hash: Hash(Hash(...Hash(0, c0), c1), ..., cN)
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

/// @notice Pending forced withdrawal request for 2-step forced withdrawal
/// @dev Storage key = keccak256(requester, commitmentsHash). One request per batch.
///      Each commitment maps to this requestKey via commitmentToRequestKey mapping.
struct ForcedWithdrawalRequest {
    uint64 requestBlock; // Block number when requested
    address requester; // Who requested the withdrawal (for access control)
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

/// @notice Auth snapshot state for epoch submissions
struct AuthSnapshotState {
    TreeRootPair[] usedAuthRoots;
    uint256 authSnapshotRound;
}

/// @notice Packed auth key info for storage efficiency
struct AuthKeyInfo {
    uint16 treeNumber; // Tree number where the auth key is registered
    uint32 treeIndex; // Index within the tree
    uint32 listIndex; // 1-indexed position in _authKeyList (0 = not exists)
    bool revoked; // Whether the auth key has been revoked
}

/// @notice Packed account info for storage efficiency (owner + nonce in single slot)
struct AccountInfo {
    address owner; // 20 bytes: account owner
    uint96 nonce; // 12 bytes: replay protection nonce (2^96 is sufficient)
}

/// @notice Packed auth tree state for storage efficiency
struct AuthTreeState {
    uint256 root; // 32 bytes: current tree root (slot 1)
    uint64 cursor; // 8 bytes: history ring buffer cursor
    uint32 leafCount; // 4 bytes: number of leaves in tree
    // 20 bytes remaining in slot 2
}
