// Copyright (c) 2026 Sunnyside Labs Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Copyright (c) 2026 Sunnyside Labs Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package frontend

import "math/big"

// =============================================================================
// Circuit constants and domains
// =============================================================================
//
// This file centralizes constants that define circuit sizing defaults, range-check bit lengths,
// and Poseidon domain separators.
//
// What these constants are:
// - Default sizes used by tools/tests to pick a circuit shape (depths, max tree counts).
// - Bit-lengths used for range checks (`api.ToBinary` / `AssertIsNBits`) across circuits.
// - Domain separators used as the first input(s) to Poseidon hashes.
//
// What these constants are NOT:
// - They are not "protocol parameters" enforced by the circuit unless referenced from `Define`.
// - Changing a default does not change constraints unless the circuit shape is compiled with it.
const (
	// =============================================================================
	// Default circuit sizing
	// =============================================================================

	// DefaultNoteDepth is the default depth for note commitment trees.
	DefaultNoteDepth = 20

	// NullifierTreeNumberMultiplier defines the multiplier for encoding tree number in nullifier domain.
	// Tree number is encoded as: domain = domainNullifier + treeNumber * NullifierTreeNumberMultiplier.
	// Value 256 (2^8) provides clear separation between domains while keeping the combined value small.
	NullifierTreeNumberMultiplier = 256

	// MaxNoteRootsPerProof is the maximum number of note roots carried in a single proof.
	MaxNoteRootsPerProof = 16

	// =============================================================================
	// Bit lengths for range checks
	// =============================================================================
	//
	// These are a single source of truth for `ToBinary` / `AssertIsNBits` usage across circuits.

	// BoolBits is the bit length for boolean flags (0/1).
	BoolBits = 1

	// CountBits is the bit length for counters like NTransfers, FeeTokenCount, CountOld/CountNew.
	CountBits = 32

	// PortalCounterBits is the bit length of a portal sweep counter, fixed by the uint64 counter
	// the portal record carries on chain rather than chosen for headroom.
	PortalCounterBits = 64

	// DepositNonceBits is the bit length of a deposit request nonce, fixed by the uint32 nonce
	// the deposit request carries on chain.
	DepositNonceBits = 32

	// TokenIDBits is the width of legacy registry IDs. Native asset fields use AddressBits.
	TokenIDBits = 16

	// FeeBpsBits is the bit length for fee rates (basis points).
	FeeBpsBits = 16

	// AmountBits is the bit length for note values and fee amounts.
	// Also used for value sums, consistent with the contract's uint96 amount type.
	AmountBits = 96

	// AddressBits is the bit length for Ethereum addresses.
	// Used by the forced-withdrawal circuit to bound WithdrawalTo, matching the pool's
	// uint256(uint160(withdrawal.to)) encoding; the width is fixed by that ABI encoding
	// rather than chosen for headroom.
	AddressBits = 160

	// DigestHalfBits is the bit length of each public limb of a 256-bit digest.
	DigestHalfBits = 128

	// ScalarFieldBits is the bit length of the BN254 scalar field the circuits are compiled over.
	// A decomposition of this width is what makes gnark add its reducedness check, which is what
	// makes a bit pattern a statement about the value rather than about one of its two possible
	// 254-bit representations.
	ScalarFieldBits = 254

	// ReservedNPKBits marks the low range [0, 2^ReservedNPKBits) that no spendable note public key
	// may occupy. Withdrawal markers hash a 160-bit recipient address in the NPK position under the
	// same note domain, so reserving exactly the address width makes a marker structurally
	// unopenable as a note without changing the marker formula or any deployed root.
	ReservedNPKBits = AddressBits

	// BlockNumberBits is the bit length for L1/L2 block numbers and gift refund deadlines.
	// Used by the gift claim circuit to compare CurrentBlock against refundAfterBlock; 64 bits
	// comfortably covers any realistic chain height plus MAX_GIFT_REFUND_DELAY (~13M blocks).
	BlockNumberBits = 64
	// TimestampBits is the bit length for auth expiry and proving timestamps.
	TimestampBits = 64

	// FeeRemainderBits is the bit length for `x mod 10_000` remainder bounds (since 10_000 < 2^14).
	FeeRemainderBits = 14

	// =============================================================================
	// Fee math
	// =============================================================================

	// FeeBpsDenominator is the divisor used for basis-point fee rates.
	FeeBpsDenominator = 10_000

	// =============================================================================
	// Auth registry sizing
	// =============================================================================

	// DefaultAuthDepth is the default depth for auth registry trees.
	DefaultAuthDepth = 20

	// TreeNumberBitsPerSlot is the number of bits per packed tree number (15 bits × 16 slots = 240 bits).
	TreeNumberBitsPerSlot = 15

	// MaxAuthRootsPerProof is the maximum number of auth roots carried in a single proof.
	MaxAuthRootsPerProof = 16

	// SpendApprovalBatchDepth is the fixed depth of the Safe spend approval
	// batch sub-tree. Every Path B slot walks this depth from the consumed
	// commitment to the batch root committed in the approval leaf, so one
	// approval leaf authorizes up to 2^SpendApprovalBatchDepth spends and a
	// spend does not reveal its batch size.
	SpendApprovalBatchDepth = 8

	// NoteTreeNumberBits is the bit length for global note tree identifiers.
	NoteTreeNumberBits = TreeNumberBitsPerSlot

	// AuthTreeNumberBits is the bit length for global auth tree identifiers.
	AuthTreeNumberBits = TreeNumberBitsPerSlot

	// MaxNoteTreeNumber is the maximum valid note tree identifier (15-bit, inclusive).
	MaxNoteTreeNumber = (1 << NoteTreeNumberBits) - 1 // 32767

	// MaxAuthTreeNumber is the maximum valid auth tree identifier (15-bit, inclusive).
	MaxAuthTreeNumber = (1 << AuthTreeNumberBits) - 1 // 32767

	// =============================================================================
	// Forced-withdrawal AuthContext layout
	// =============================================================================
	// Offsets are least-significant-bit positions in the packed uint128. The leaf-index width
	// is fixed by the production AuthRegistry capacity, not by a circuit instance's test depth.

	ForcedAuthContextExpiryStart     = 0
	ForcedAuthContextExpiryEnd       = ForcedAuthContextExpiryStart + TimestampBits
	ForcedAuthContextModeBit         = ForcedAuthContextExpiryEnd
	ForcedAuthContextLeafIndexBits   = 20
	ForcedAuthContextLeafIndexStart  = ForcedAuthContextModeBit + BoolBits
	ForcedAuthContextLeafIndexEnd    = ForcedAuthContextLeafIndexStart + ForcedAuthContextLeafIndexBits
	ForcedAuthContextTreeNumberStart = ForcedAuthContextLeafIndexEnd
	ForcedAuthContextTreeNumberEnd   = ForcedAuthContextTreeNumberStart + AuthTreeNumberBits
	ForcedAuthContextVersionBits     = 8
	ForcedAuthContextVersionStart    = ForcedAuthContextTreeNumberEnd
	ForcedAuthContextVersionEnd      = ForcedAuthContextVersionStart + ForcedAuthContextVersionBits
	ForcedAuthContextUsedBits        = ForcedAuthContextVersionEnd
	ForcedAuthContextTotalBits       = 128
	ForcedAuthContextVersion         = 2
	MaxForcedAuthLeafIndex           = (1 << ForcedAuthContextLeafIndexBits) - 1

	// WithdrawalMaskBitsPerWord is the number of transfer slots packed into one public
	// withdrawal-mask field element. 128 keeps a mask word well inside the scalar field and
	// matches the digest-limb width the rest of the public vector already uses.
	WithdrawalMaskBitsPerWord = 128

	// CountsPackedSlots is the number of values in the packed counts field.
	CountsPackedSlots = 5

	// CountsPackedBitsPerSlot is the number of bits per slot in packed counts (32 bits × 5 slots = 160 bits).
	CountsPackedBitsPerSlot = 32

	// =============================================================================
	// Legacy asset snapshot sizing
	// =============================================================================

	// AssetSnapshotDepth covers the complete uint16 registry ID space, including reserved ID zero.
	AssetSnapshotDepth = 16
)

var (
	// =============================================================================
	// Poseidon domain separators
	// =============================================================================
	//
	// These constants are used to domain-separate Poseidon hashes by prepending a fixed first input.
	// They are field elements represented as `*big.Int` to keep allocation explicit and stable.

	// domainAccountId domain-separates hashes derived from a user's account key.
	// Used by account-key-related circuits/helpers when hashing account-scoped identifiers.
	domainAccountId = big.NewInt(1)

	// domainNoteCommitment opens a legacy note commitment:
	// Legacy commitment = Poseidon(domainNoteCommitment, NPK, tokenID, value)
	// Native commitments instead use domainNoteCommitmentV2 and a uint160 token address.
	domainNoteCommitment = big.NewInt(2)

	// domainNotePublicKey derives the note public key in both protocols:
	// NPK = Poseidon(domainNotePublicKey, MPK, noteRnd)
	// It deliberately shares tag 2 with domainNoteCommitment. The derivation is unchanged across
	// both generations, so the two purposes get separate names over one number rather than a new tag.
	domainNotePublicKey = big.NewInt(2)

	// domainNullifier domain-separates legacy wallet-note nullifier derivation:
	// Nullifier = Poseidon(domainNullifier + treeNumber*NullifierTreeNumberMultiplier, nullifyingKey, noteLeafIndex).
	// Native wallet-note nullifiers use domainNullifierV2 instead.
	domainNullifier = big.NewInt(3)

	// domainRegLeaf domain-separates auth registry leaf hashing.
	// Key leaf = Poseidon(domainRegLeaf, accountId, authPkX, authPkY, expiry).
	domainRegLeaf = big.NewInt(4)

	// domainRegNode domain-separates internal auth registry Merkle nodes.
	// Used by `computeDomainRoot` when hashing auth path elements.
	domainRegNode = big.NewInt(5)

	// domainApprove domain-separates the approval message hash verified by EdDSA.
	// Used by circuits to bind signatures to an on-chain digest (hi/lo).
	domainApprove = big.NewInt(6)

	// domainDepositRequest domain-separates legacy deposit request IDs, binding
	// (chainId, pool, depositor, tokenID, amount, nonce, commitmentsHash).
	// Native requests use domainDepositRequestV2 and a token address instead.
	domainDepositRequest = big.NewInt(7)

	// domainMPK domain-separates master public key derivation:
	// MPK = Poseidon(domainMPK, accountId, nullifyingKey).
	domainMPK = big.NewInt(8)

	// domainPortalBind domain-separates the portal-deposit owner binding:
	// H = Poseidon(domainPortalBind, recipientMPK, blind).
	// H is the public on-chain commitment that hides which account owns a portal
	// address; the portal-deposit circuit opens it against an opaque recipientMPK witness.
	domainPortalBind = big.NewInt(9)

	// domainPortalNote domain-separates the portal-deposit note randomness:
	// noteRnd = Poseidon(domainPortalNote, blind, E, counter).
	// blind (the secret per-portal value) keeps the leaf unlinkable on-chain — the indexer
	// recomputes it from the registry's (recipientMPK, blind), not from public values alone.
	// E (the public portal address) keeps the leaf unique per portal: two portals of one
	// recipient that share a blind would otherwise collide on one commitment, since
	// the owner binding is write-once per E but not per H. counter keeps repeated sweeps distinct.
	domainPortalNote = big.NewInt(10)

	// domainPortalRequest domain-separates the legacy portal-deposit request id digest:
	// portalDepositId = keccak256(abi.encode(domainPortalRequest, chainId, pool, E, tokenID, amount, counter, H)).
	// Native requests use domainPortalRequestV2 and a token address instead.
	// It is the sibling of domainDepositRequest for the hidden-recipient sweep path; keccak (not
	// Poseidon) because this id is only an on-chain key, never a circuit input.
	domainPortalRequest = big.NewInt(11)

	// The gift (claimable-transfer) separators follow the portal block at 12..14 — portal
	// claimed 9..11 first, so gift moves up to keep the global Poseidon domain namespace
	// collision-free (values must equal their prover/core and Solidity counterparts).

	// domainGiftBind domain-separates claimable-transfer gift-note public key derivation:
	// giftNPK = Poseidon(domainGiftBind, W, Poseidon(domainGiftBind, blind, refundField)).
	// Used twice (inner + outer) so a gift NPK cannot collide with a normal note NPK
	// (domainNoteCommitment), keeping gift notes spendable only by the gift claim circuit.
	domainGiftBind = big.NewInt(12)

	// domainGiftRefund domain-separates the sender's refund binding:
	// refundField = Poseidon(domainGiftRefund, senderMPK, refundAfterBlock).
	// It excludes tokenAddress/amount (those are bound by C_gift) so the claim branch
	// never has to open refundField, preserving the claim/refund shared-nullifier XOR.
	domainGiftRefund = big.NewInt(13)

	// domainGiftNullifier domain-separates the gift nullifier, tree-number-bound like a
	// normal note nullifier:
	// GiftNullifier = Poseidon(domainGiftNullifier + fundingTreeNumber*NullifierTreeNumberMultiplier, giftNPK, giftLeafIndex).
	domainGiftNullifier = big.NewInt(14)

	// domainGiftSecret domain-separates the secret-bearer claim commitment:
	// in secret-claim mode the gift's W slot is W = Poseidon(domainGiftSecret, claimSecret), so
	// proving knowledge of claimSecret authorizes the claim without any wallet/auth binding.
	domainGiftSecret = big.NewInt(15)
	// domainApprovalLeaf domain-separates Safe spend approval leaves.
	domainApprovalLeaf = big.NewInt(16)

	// domainApproveCommit domain-separates Safe spend approval commitments.
	domainApproveCommit = big.NewInt(17)

	// domainApprovalDisplay binds a Path-B approval blinding to the actual
	// token and fee constrained by the epoch circuit.
	domainApprovalDisplay = big.NewInt(18)

	// The address-native separators occupy 19..27. They are distinct from the legacy
	// tags above because a native note commits to a uint160 token address where the
	// legacy one commits to a uint16 registry ID, so the two hash families must never
	// collide. Values are shared with Solidity and the pinned circuit artifacts.

	// domainNoteCommitmentV2 opens a native note commitment:
	// commitment = Poseidon(domainNoteCommitmentV2, NPK, tokenAddress, value).
	domainNoteCommitmentV2 = big.NewInt(19)

	// domainNullifierV2 domain-separates native wallet-note nullifier derivation,
	// tree-number-bound the same way domainNullifier is.
	domainNullifierV2 = big.NewInt(20)

	// domainDepositRequestV2 domain-separates native deposit request IDs, binding
	// a token address where domainDepositRequest binds a registry ID.
	domainDepositRequestV2 = big.NewInt(21)

	// domainPortalNoteV2 domain-separates the native portal-deposit note randomness,
	// the sibling of domainPortalNote.
	domainPortalNoteV2 = big.NewInt(22)

	// domainPortalScopeV2 binds native portal randomness to one deployment.
	domainPortalScopeV2 = big.NewInt(28)

	// domainPortalRequestV2 domain-separates the native portal-deposit request id digest,
	// the sibling of domainPortalRequest.
	domainPortalRequestV2 = big.NewInt(23)

	// domainGiftNullifierV2 domain-separates the native gift nullifier,
	// the sibling of domainGiftNullifier.
	domainGiftNullifierV2 = big.NewInt(24)

	// domainApprovalDisplayV2 binds a native approval blinding to the actual token
	// address and fee constrained by the epoch circuit, the sibling of domainApprovalDisplay.
	domainApprovalDisplayV2 = big.NewInt(25)

	// domainAssetSnapshotLeaf domain-separates a legacy asset snapshot leaf, hashing the
	// registry ID together with its asset. It must match leaf hashing in the AssetSnapshot contract.
	domainAssetSnapshotLeaf = big.NewInt(26)

	// domainAssetSnapshotNode domain-separates internal legacy asset snapshot Merkle nodes.
	// It must match node hashing in the AssetSnapshot contract.
	domainAssetSnapshotNode = big.NewInt(27)
)

// EpochWithdrawalMaskWords returns the number of public mask words an epoch circuit of the given
// transfer capacity declares. The count is part of the circuit shape, so the contract's packing
// loop and the witness builder must derive it from here rather than assume a single word.
func EpochWithdrawalMaskWords(maxTransfers int) int {
	return (maxTransfers + WithdrawalMaskBitsPerWord - 1) / WithdrawalMaskBitsPerWord
}
