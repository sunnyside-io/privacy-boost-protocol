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

/// @dev Poseidon domain separators prevent hash collisions between different contexts.
///      Each domain tag creates a unique hash space for its specific use case.
uint256 constant DOMAIN_ACCOUNTID = 1; // Used by circuits only: account ID derivation
uint256 constant DOMAIN_NOTE = 2; // Note commitment hashing
uint256 constant DOMAIN_NULLIFIER = 3; // Used by circuits only: nullifier derivation
uint256 constant DOMAIN_REG_LEAF = 4; // AuthRegistry leaf hash
uint256 constant DOMAIN_REG_NODE = 5; // AuthRegistry internal node hash
uint256 constant DOMAIN_APPROVE = 6; // Used by circuits only: EdDSA approval message hash
uint256 constant DOMAIN_DEPOSIT_REQUEST = 7; // Deposit request ID derivation
uint256 constant DOMAIN_MPK = 8; // Used by circuits only: master public key derivation
uint256 constant DOMAIN_PORTAL_BIND = 9; // Portal owner binding: H = Poseidon(.., recipientMPK, blind)
uint256 constant DOMAIN_PORTAL_NOTE = 10; // Portal note randomness: noteRnd = Poseidon(.., blind, E, counter)
uint256 constant DOMAIN_PORTAL_REQUEST = 11; // Portal deposit request ID derivation
uint256 constant DOMAIN_GIFT_BIND = 12; // Claimable-transfer gift NPK bind (inner + outer)
uint256 constant DOMAIN_GIFT_REFUND = 13; // Claimable-transfer gift refund binding (senderMPK, refundAfterBlock)
uint256 constant DOMAIN_GIFT_NULL = 14; // Claimable-transfer gift nullifier base (+ fundingTreeNumber*256)
uint256 constant DOMAIN_GIFT_SECRET = 15; // Used by circuits only: secret-bearer claim W = Poseidon(.., claimSecret)
uint256 constant DOMAIN_APPROVAL_LEAF = 16; // Account-owner spend approval auth leaf hash
uint256 constant DOMAIN_APPROVE_COMMIT = 17; // Account-owner spend approval digest commitment
uint256 constant DOMAIN_APPROVAL_DISPLAY = 18; // Approval account/token/fee/sender binding (circuit only)

/// @dev Spend approval batch sub-tree: a fixed depth-8 Poseidon2 hash2 Merkle
///      tree over commitments (zero-padded), so one approval leaf authorizes
///      up to 256 spends. Depth is uniform: a size-1 batch folds the commitment
///      with the hash2 zero-subtree constants (LibZeroHashes).
uint8 constant SPEND_APPROVAL_BATCH_DEPTH = 8;
uint256 constant MAX_SPEND_APPROVAL_BATCH = 256;

/// @dev Epoch witness/circuit compatibility version. Generated epoch VK
///      artifact names include this value so deployment scripts cannot load
///      dimension-compatible artifacts for an older constraint system.
///      Version 9 used gnark v0.15's sound scalar-multiplication constraints.
///      Version 10 binds fee-note ciphertext metadata into the epoch proof, which
///      widens the public-input vector.
///      Version 11 rejects non-canonical signature scalars by comparing against
///      the subgroup order minus one. Version 12 expands spend-approval batch
///      paths from depth 5 to depth 8, changing the emitted constraints.
uint32 constant EPOCH_WITNESS_SCHEMA_VERSION = 12;

/// @dev Transfer slots packed into one public withdrawal-mask word. The epoch circuit declares
///      ceil(maxTransfers / WITHDRAWAL_MASK_BITS_PER_WORD) mask words, least-significant bit
///      first, and the pool derives them from the withdrawalSlots array it has already validated.
uint256 constant WITHDRAWAL_MASK_BITS_PER_WORD = 128;

/// @dev Gift-claim witness/circuit compatibility version. Gift CCS/PK/VK
///      artifact names include this value so deployment cannot load the
///      constraint system compiled with the vulnerable scalar-mul gadget.
///      Version 11 constrains secret-bearer claims to the public-payout branch.
///      Version 12 rejects non-canonical signature scalars by comparing against
///      the subgroup order minus one. Version 13 expands spend-approval batch
///      paths from depth 5 to depth 8 and requires an EdDSA signature over the
///      destination-bound claim digest on a direct-key sender refund, changing
///      the emitted constraints.
uint32 constant GIFT_CLAIM_WITNESS_SCHEMA_VERSION = 13;

uint8 constant TOKEN_TYPE_ERC20 = 0;

/// @dev Tree configuration shared by PrivacyBoost and AuthRegistry.
///      MERKLE_DEPTH=20 is the default circuit-oriented tree depth and supports ~1M leaves per tree.
///      MAX_*_TREE_DEPTH defines the maximum supported depth for each on-chain tree.
///      MAX_*_ROOTS_PER_PROOF = sparse root capacity included in a proof.
///      MAX_*_TREE_NUMBER = maximum global tree identifier that fits in 15 bits.
uint8 constant MERKLE_DEPTH = 20;
uint8 constant MAX_NOTE_TREE_DEPTH = 24;
uint8 constant MAX_AUTH_TREE_DEPTH = 20;
uint8 constant MAX_NOTE_ROOTS_PER_PROOF = 16;
uint8 constant MAX_AUTH_ROOTS_PER_PROOF = 16;
uint16 constant MAX_NOTE_TREE_NUMBER = 32767;
uint16 constant MAX_AUTH_TREE_NUMBER = 32767;

/// @dev Per-tree note-root ring buffer depth. A larger window lets epoch/forced/deposit proofs
///      validate against older historical roots, tolerating more state drift between proof
///      generation and on-chain submission.
///
///      Upgrade safety: `treeRootHistory` is `mapping(uint256 => uint256[ROOT_HISTORY_SIZE])` at a
///      fixed slot. The fixed-array length only sizes the per-key value region addressed at
///      `keccak256(treeNum . slot) + idx`; it never occupies inline slots, so growing it does not
///      move `treeRootHistoryCursor` or any later state. Indices 0..63 keep their addresses (data
///      preserved) and 64..127 were previously zero, which is the correct empty-slot value.
///
///      Gas: `isKnownTreeRoot` short-circuits on the current root, so the happy path is unaffected.
///      Worst case is a linear scan over the full buffer when validating a stale or unknown root
///      (and `MAX_NOTE_ROOTS_PER_PROOF` such scans per proof), which grows linearly with this value.
uint256 constant ROOT_HISTORY_SIZE = 128;

/// @dev Precomputed zero roots for empty Merkle trees at depth 20.
///      MERKLE_ZERO_ROOT uses hash2(left, right) for note commitments.
///      AUTH_ZERO_ROOT uses hash3(DOMAIN_REG_NODE, left, right) for auth registry.
uint256 constant MERKLE_ZERO_ROOT = 12912536786691007423957206067517486813236154886763950786309034005218474477397;
uint256 constant AUTH_ZERO_ROOT = 5126366598568957508996612635770875836246285197448927819410732545299241365093;

/// @dev Bit width for splitting keccak256 digest into hi/lo halves (circuit field compatibility)
uint8 constant DIGEST_HALF_BITS = 128;

/// @dev Number of bits per slot in packed counts field (CountOld, CountNew, Rollover, NTransfers, FeeTokenCount)
uint8 constant COUNT_BITS_PER_SLOT = 32;

/// @dev Number of slots in packed counts field
uint8 constant COUNT_PACKED_SLOTS = 5;

/// @dev BN254 scalar field modulus (same as Groth16Verifier.R / Poseidon2T4.PRIME).
uint256 constant SNARK_SCALAR_FIELD = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

/// @dev Smallest note public key any spend relation will open. A withdrawal marker is
///      Poseidon(DOMAIN_NOTE, uint160(to), tokenId, amount), which is the same domain, arity and
///      field ordering a note commitment uses, so the 160-bit address range is reserved in the key
///      position to keep a marker structurally unopenable as a note. This floor guards the gateway
///      receipt, the one creation path where a caller hands the pool a raw key and the pool itself
///      builds the commitment. The circuits enforce the same floor on every key a caller chooses,
///      so no note leaf that reaches the tree carries a reserved-range key. The one exception is
///      the withdrawal marker itself, which is not a note and is never appended.
///      frontend/spendable_npk.go records the full site list. Mirrors the circuits'
///      ReservedNPKBits and `core.SpendableNPKFloor`.
uint256 constant SPENDABLE_NPK_FLOOR = 1 << 160;

/// @dev Maximum age of a proof's proving timestamp accepted by PrivacyBoost.
uint64 constant MAX_PROOF_AGE = 1 hours;

/// @dev Fee denominator in basis points (1 bp = 0.01%); shared by every settlement library's fee math.
uint256 constant BASIS_POINTS = 10_000;

struct PointG1 {
    uint256 x;
    uint256 y;
}

struct PointG2 {
    uint256 x0;
    uint256 x1;
    uint256 y0;
    uint256 y1;
}

struct VerifyingKey {
    PointG1 alpha;
    PointG2 betaNeg;
    PointG2 gammaNeg;
    PointG2 deltaNeg;
    uint256[] icX;
    uint256[] icY;
}
