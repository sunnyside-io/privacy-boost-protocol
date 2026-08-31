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

import (
	"github.com/consensys/gnark/frontend"
)

// =============================================================================
// GiftClaimCircuit
// =============================================================================
//
// This circuit proves a batch of "gift claim" re-mints for Claimable Transfer. A gift note is a
// wallet-bound note funded by a sender for a wallet address that may not yet be a registered PB
// account; this circuit consumes one gift note per slot and either mints a canonical shielded note
// (recipient claim) or returns funds to the sender (sender refund). Both outcomes share ONE gift
// nullifier so claim and refund are mutually exclusive on chain.
//
// What this circuit enforces (high level, per active claim slot):
//   - **Gift binding**: both branches re-derive
//     giftNPK = Poseidon(domainGiftBind, recipientSlot, Poseidon(domainGiftBind, blind, refundField))
//     and assert C_gift = Poseidon(domainNote, giftNPK, tokenId, amount) — so a malformed gift can
//     be neither claimed nor refunded inconsistently.
//   - **Membership**: C_gift exists in the funding note tree (Merkle membership against a selected
//     historical/current root, tree-number-bound like a normal note spend).
//   - **Nullifier**: GiftNullifier = Poseidon(domainGiftNull + fundingTreeNumber*256, giftNPK,
//     giftLeafIndex) is bound to the public NullifiersOut[c].
//   - **Value conservation**: the single gift input equals the single mint output in both token id
//     and amount (no fee, no value creation).
//   - **Branch authority**:
//       * Recipient claim (BranchType=0): a shared accountId_R witness binds wallet ownership
//         (accountId_R = Poseidon(domainAccountId, recipientSlot, salt_R)), an admissible auth-leaf membership proof,
//         an EdDSA signature over the PB:GIFT_CLAIM:v2 digest, and the mint target
//         MPK_target = Poseidon(domainMPK, accountId_R, nk_R) — so only the wallet owner can claim,
//         and only to themselves.
//       * Sender refund (BranchType=1): opens {recipientSlot, blind, refundField}, proves
//         senderMPK = Poseidon(domainMPK, accountId_S, senderNk) consistent with refundField,
//         proves either the sender's registered key leaf or a Safe spend-approval leaf, and enforces
//         CurrentBlock >= refundAfterBlock. Approval-only Safe accounts cannot register a key leaf,
//         so their refunds require the Safe-approved branch.
//   - **Tree append**: the mint output commitment is appended to the active output tree in private-
//     mint mode (the public-exit / refund-to-EOA payout path is handled on chain, not appended here).
//
// Identical on-chain shape (privacy): CurrentBlock is a public input in BOTH branches (only the
// refund branch enforces the >= check) so a private claim and a private refund have an identical
// public-input layout and are indistinguishable on chain. BranchType is
// a private witness.
//
// What this circuit does NOT prove:
//   - It does not prove that (NoteKnownRoots/AuthKnownRoots) are consistent with the contract's root
//     histories/snapshots; the contract enforces that before verifying the proof.
//   - It does not prove uniqueness of gift nullifiers across the batch; uniqueness is enforced on
//     chain by the nullifier mapping (claim and refund share the nullifier, so exactly one mines).
//   - It does not prove auth-root freshness. Private epochs apply their configured root window; public
//     wallet exits instead expose the exact proven auth leaf so the contract can require that leaf to
//     remain active. It also enforces finite expiry against ProvingTimestamp.
//
// Witness author notes:
//   - Arrays are fixed-size. Only the first `NClaims` slots are active; inactive slots MUST be zero
//     padded. Constraints for inactive slots are gated by `claimActive[c]`.
//   - Merkle paths must match the tree hash convention (see `computeRoot` / `computeDomainRoot`).

// =============================================================================
// Types
// =============================================================================
type GiftClaimCircuit struct {
	// Shape holds fixed sizing parameters (compile-time circuit shape, not constrained).
	Shape GiftClaimShape

	// Public inputs are verified by the verifier/contract.
	Pub GiftClaimPublicInputs

	// Private inputs are provided by the prover as witness-only values.
	Priv GiftClaimPrivateInputs
}

// GiftClaimShape defines fixed sizing parameters for this circuit instance.
// These values affect circuit allocation/structure but do not add constraints by themselves.
type GiftClaimShape struct {
	MaxGiftClaims        int // number of gift-claim slots in the circuit instance
	NoteDepth            int // depth of note commitment trees (leaf capacity = 2^NoteDepth)
	MaxNoteRootsPerProof int // number of funding-tree note roots provided in a proof
	MaxAuthRootsPerProof int // number of auth registry roots provided in a proof
	SenderAuthDepth      int // depth of auth registry trees (recipient claim membership proof)
}

type GiftClaimPublicInputs struct {
	// Funding note-tree roots (multi-tree input support; the gift may live in a finalized tree).
	NoteKnownRoots             []frontend.Variable `gnark:",public"` // [MaxNoteRootsPerProof] historical/current note commitment tree roots
	NoteKnownTreeNumbersPacked frontend.Variable   `gnark:",public"` // packed tree numbers (15 bits each)

	// Auth registry roots (recipient-claim auth-leaf membership; current-round snapshot model).
	AuthKnownRoots             []frontend.Variable `gnark:",public"` // [MaxAuthRootsPerProof] auth registry roots (snapshotted)
	AuthKnownTreeNumbersPacked frontend.Variable   `gnark:",public"` // packed auth tree numbers (15 bits each)

	// Tree-append state for the private-mint output tree.
	ActiveNoteTreeNumber frontend.Variable `gnark:",public"` // selects which NoteKnownRoots is the active output tree
	ActiveNoteTreeRoot   frontend.Variable `gnark:",public"` // current root of the active output tree (for frontier binding)
	CountOld             frontend.Variable `gnark:",public"` // leaf count of the active output tree before mint appends
	RootNew              frontend.Variable `gnark:",public"` // root after appending all active mint outputs
	CountNew             frontend.Variable `gnark:",public"` // leaf count after appends
	Rollover             frontend.Variable `gnark:",public"` // 0/1 rollover flag for the active output tree

	// Batch sizing.
	NClaims frontend.Variable `gnark:",public"` // number of active claim slots (1..MaxGiftClaims)

	// Time references are public in every branch so claim/refund remain indistinguishable on chain.
	CurrentBlock     frontend.Variable `gnark:",public"` // caller-attested block bounded by the contract
	ProvingTimestamp frontend.Variable `gnark:",public"` // recent UNIX timestamp bounded by the contract

	// Per-claim outputs.
	NullifiersOut   []frontend.Variable `gnark:",public"` // [MaxGiftClaims] gift nullifiers for active claims; zero padded
	CommitmentsOut  []frontend.Variable `gnark:",public"` // [MaxGiftClaims] mint commitment in private mode; exact authorization leaf in public mode
	OutputTokenIds  []frontend.Variable `gnark:",public"` // [MaxGiftClaims] gift token id in public-exit mode; zero in private-mint mode and inactive slots
	OutputAmounts   []frontend.Variable `gnark:",public"` // [MaxGiftClaims] gift amount in public-exit mode; zero in private-mint mode and inactive slots
	ClaimDigestHi   []frontend.Variable `gnark:",public"` // [MaxGiftClaims] PB:GIFT_CLAIM:v2 digest, high half
	ClaimDigestLo   []frontend.Variable `gnark:",public"` // [MaxGiftClaims] PB:GIFT_CLAIM:v2 digest, low half
	BranchSelectors []frontend.Variable `gnark:",public"` // [MaxGiftClaims] mint mode: 1 = private mint (append output), 0 = public payout (no append)
}

type GiftClaimPrivateInputs struct {
	// Per-claim branch selector and opened gift material.
	BranchType       []frontend.Variable // [MaxGiftClaims] 0 = recipient claim, 1 = sender refund (witness only)
	CGift            []frontend.Variable // [MaxGiftClaims] gift commitment (re-derived and matched in-circuit)
	GiftNPK          []frontend.Variable // [MaxGiftClaims] gift note public key (re-derived and matched in-circuit)
	TokenId          []frontend.Variable // [MaxGiftClaims] gift token id (bound by C_gift, equal to output)
	Amount           []frontend.Variable // [MaxGiftClaims] gift amount (bound by C_gift, equal to output)
	RecipientSlot    []frontend.Variable // [MaxGiftClaims] wallet address or secret commitment, depending on claim mode
	Blind            []frontend.Variable // [MaxGiftClaims] fresh per-gift hiding blind
	RefundField      []frontend.Variable // [MaxGiftClaims] Poseidon(domainGiftRefund, senderMPK, refundAfterBlock)
	RefundAfterBlock []frontend.Variable // [MaxGiftClaims] sender-chosen refund deadline

	// Secret-bearer claim mode (off-by-default, audit-gated). On an active recipient claim, SecretMode=1 selects a
	// secret-bearer claim: the gift's recipient slot commits to ClaimSecret (recipientSlot = Poseidon(domainGiftSecret,
	// ClaimSecret)) instead of a wallet address, so knowledge of ClaimSecret authorizes the claim with
	// no auth key or EdDSA. Secret-bearer claims are forced to public payout, where the claimant chooses
	// the external destination. SecretMode=0 is the wallet-bound recipient claim. SecretMode is forced
	// to zero on refund and inactive slots.
	SecretMode  []frontend.Variable // [MaxGiftClaims] 0 = wallet-bound recipient claim, 1 = secret-bearer claim
	ClaimSecret []frontend.Variable // [MaxGiftClaims] secret preimage of the gift's recipient slot in secret mode

	// Funding-tree membership witness.
	FundingTreeNumber []frontend.Variable   // [MaxGiftClaims] which note tree the gift was funded into (15-bit global id)
	GiftLeafIndex     []frontend.Variable   // [MaxGiftClaims] gift leaf index in the funding tree
	FundingTreePath   [][]frontend.Variable // [MaxGiftClaims][NoteDepth] Merkle path for gift membership

	// Recipient-claim witness (BranchType=0).
	RecipientAccountId []frontend.Variable   // [MaxGiftClaims] accountId_R = Poseidon(domainAccountId, recipientSlot, salt_R)
	RecipientSalt      []frontend.Variable   // [MaxGiftClaims] salt_R
	RecipientNk        []frontend.Variable   // [MaxGiftClaims] nk_R (target MPK derivation)
	TargetMPK          []frontend.Variable   // [MaxGiftClaims] MPK_target = Poseidon(domainMPK, accountId_R, nk_R)
	OutputNoteRnd      []frontend.Variable   // [MaxGiftClaims] randomness for the minted note NPK
	AuthTreeNumber     []frontend.Variable   // [MaxGiftClaims] which auth tree contains the recipient auth key
	AuthExpiry         []frontend.Variable   // [MaxGiftClaims] expiry used in the auth leaf hash
	AuthLeafIndex      []frontend.Variable   // [MaxGiftClaims] auth leaf index
	AuthPathElements   [][]frontend.Variable // [MaxGiftClaims][SenderAuthDepth] auth Merkle path
	AuthPkX            []frontend.Variable   // [MaxGiftClaims] recipient auth pubkey X
	AuthPkY            []frontend.Variable   // [MaxGiftClaims] recipient auth pubkey Y
	AuthSigR8x         []frontend.Variable   // [MaxGiftClaims] signature R8.x over the claim digest
	AuthSigR8y         []frontend.Variable   // [MaxGiftClaims] signature R8.y over the claim digest
	AuthSigS           []frontend.Variable   // [MaxGiftClaims] signature scalar S

	// Sender-refund witness (BranchType=1). The same auth path/key fields above are reused for the
	// sender authorization: RefundUseApproval=0 proves a registered key leaf, while 1 proves the
	// Safe's batch approval leaf. Approval-only accounts cannot have key leaves, so they can refund
	// only through an on-chain Safe approval.
	SenderAccountId     []frontend.Variable   // [MaxGiftClaims] accountId_S
	SenderNk            []frontend.Variable   // [MaxGiftClaims] senderNk; senderMPK = Poseidon(domainMPK, accountId_S, senderNk)
	RefundUseApproval   []frontend.Variable   // [MaxGiftClaims] bool: select Safe approval leaf over sender key leaf
	RefundBlinding      []frontend.Variable   // [MaxGiftClaims] Safe approval commitment blinding
	RefundBatchIndex    []frontend.Variable   // [MaxGiftClaims] member index in the fixed-depth approval batch
	RefundBatchSiblings [][]frontend.Variable // [MaxGiftClaims][SpendApprovalBatchDepth] approval batch siblings

	// Active output-tree witness (single, shared across the batch; the frontier before mints append).
	NoteFrontierOld []frontend.Variable // [NoteDepth] frontier of the active output tree, bound to ActiveNoteTreeRoot
}

// giftClaimInternalState carries cached selectors and the evolving output tree state used while
// constructing constraints in `Define`.
type giftClaimInternalState struct {
	currentCount    frontend.Variable   // evolving leaf count for the active output tree
	currentFrontier []frontend.Variable // evolving frontier for the active output tree
	fullTreeRoot    frontend.Variable   // root when the output tree becomes full (count = 2^depth)
	claimActive     []Bool              // claimActive[c] := (c < NClaims)
}

// =============================================================================
// Constructor
// =============================================================================

// NewGiftClaimCircuit allocates a sized circuit instance (all slices are allocated to fixed sizes).
//
// Notes:
//   - These sizing parameters define the circuit shape at compile time.
//   - They do not add constraints by themselves, but they determine how many constraints exist once
//     `Define` is executed (more slots/depth => larger circuit).
func NewGiftClaimCircuit(maxGiftClaims, noteDepth, maxNoteRootsPerProof, maxAuthRootsPerProof, senderAuthDepth int) *GiftClaimCircuit {
	c := &GiftClaimCircuit{
		Shape: GiftClaimShape{
			MaxGiftClaims:        maxGiftClaims,
			NoteDepth:            noteDepth,
			MaxNoteRootsPerProof: maxNoteRootsPerProof,
			MaxAuthRootsPerProof: maxAuthRootsPerProof,
			SenderAuthDepth:      senderAuthDepth,
		},
		Pub: GiftClaimPublicInputs{
			NoteKnownRoots:  make([]frontend.Variable, maxNoteRootsPerProof),
			AuthKnownRoots:  make([]frontend.Variable, maxAuthRootsPerProof),
			NullifiersOut:   make([]frontend.Variable, maxGiftClaims),
			CommitmentsOut:  make([]frontend.Variable, maxGiftClaims),
			OutputTokenIds:  make([]frontend.Variable, maxGiftClaims),
			OutputAmounts:   make([]frontend.Variable, maxGiftClaims),
			ClaimDigestHi:   make([]frontend.Variable, maxGiftClaims),
			ClaimDigestLo:   make([]frontend.Variable, maxGiftClaims),
			BranchSelectors: make([]frontend.Variable, maxGiftClaims),
		},
		Priv: GiftClaimPrivateInputs{
			BranchType:          make([]frontend.Variable, maxGiftClaims),
			CGift:               make([]frontend.Variable, maxGiftClaims),
			GiftNPK:             make([]frontend.Variable, maxGiftClaims),
			TokenId:             make([]frontend.Variable, maxGiftClaims),
			Amount:              make([]frontend.Variable, maxGiftClaims),
			RecipientSlot:       make([]frontend.Variable, maxGiftClaims),
			Blind:               make([]frontend.Variable, maxGiftClaims),
			RefundField:         make([]frontend.Variable, maxGiftClaims),
			RefundAfterBlock:    make([]frontend.Variable, maxGiftClaims),
			SecretMode:          make([]frontend.Variable, maxGiftClaims),
			ClaimSecret:         make([]frontend.Variable, maxGiftClaims),
			FundingTreeNumber:   make([]frontend.Variable, maxGiftClaims),
			GiftLeafIndex:       make([]frontend.Variable, maxGiftClaims),
			FundingTreePath:     make([][]frontend.Variable, maxGiftClaims),
			RecipientAccountId:  make([]frontend.Variable, maxGiftClaims),
			RecipientSalt:       make([]frontend.Variable, maxGiftClaims),
			RecipientNk:         make([]frontend.Variable, maxGiftClaims),
			TargetMPK:           make([]frontend.Variable, maxGiftClaims),
			OutputNoteRnd:       make([]frontend.Variable, maxGiftClaims),
			AuthTreeNumber:      make([]frontend.Variable, maxGiftClaims),
			AuthExpiry:          make([]frontend.Variable, maxGiftClaims),
			AuthLeafIndex:       make([]frontend.Variable, maxGiftClaims),
			AuthPathElements:    make([][]frontend.Variable, maxGiftClaims),
			AuthPkX:             make([]frontend.Variable, maxGiftClaims),
			AuthPkY:             make([]frontend.Variable, maxGiftClaims),
			AuthSigR8x:          make([]frontend.Variable, maxGiftClaims),
			AuthSigR8y:          make([]frontend.Variable, maxGiftClaims),
			AuthSigS:            make([]frontend.Variable, maxGiftClaims),
			SenderAccountId:     make([]frontend.Variable, maxGiftClaims),
			SenderNk:            make([]frontend.Variable, maxGiftClaims),
			RefundUseApproval:   make([]frontend.Variable, maxGiftClaims),
			RefundBlinding:      make([]frontend.Variable, maxGiftClaims),
			RefundBatchIndex:    make([]frontend.Variable, maxGiftClaims),
			RefundBatchSiblings: make([][]frontend.Variable, maxGiftClaims),
			NoteFrontierOld:     make([]frontend.Variable, noteDepth),
		},
	}
	for c0 := 0; c0 < maxGiftClaims; c0++ {
		c.Priv.FundingTreePath[c0] = make([]frontend.Variable, noteDepth)
		c.Priv.AuthPathElements[c0] = make([]frontend.Variable, senderAuthDepth)
		c.Priv.RefundBatchSiblings[c0] = make([]frontend.Variable, SpendApprovalBatchDepth)
	}
	return c
}

// =============================================================================
// Define
// =============================================================================

func (c *GiftClaimCircuit) Define(api frontend.API) error {
	// Build all sizing-dependent selectors and validate the output-tree public inputs.
	state := c.validateInputs(api)

	// Per-claim core logic: gift binding, membership, nullifier, branch authority, value
	// conservation, and (in private-mint mode) appending the output commitment to the tree.
	for c0 := 0; c0 < c.Shape.MaxGiftClaims; c0++ {
		c.processClaim(api, &state, c0)
	}

	// Bind the evolving output-tree state to the public (RootNew, CountNew).
	c.assertFinalState(api, state)

	return nil
}

// =============================================================================
// Validation and cached selectors
// =============================================================================

// validateInputs performs basic range/bounds checks on the output-tree public inputs, enforces
// rollover semantics, binds the provided frontier witness to the active output-tree root, and
// builds the `claimActive` selectors. It stays "validation-only" — no hashing/membership/auth.
func (c *GiftClaimCircuit) validateInputs(api frontend.API) giftClaimInternalState {
	// 1 <= NClaims <= MaxGiftClaims (a batch with zero claims is semantically invalid).
	AssertIsNonZero(api, c.Pub.NClaims)
	AssertIsLessOrEqual(api, c.Pub.NClaims, uint64(c.Shape.MaxGiftClaims), CountBits)

	// The contract freshness-bounds this public timestamp. Range-check it once per
	// batch here; recipient slots reuse the scalar for their finite-expiry checks.
	AssertIsNBits(api, c.Pub.ProvingTimestamp, TimestampBits)

	// Bound the active output tree number.
	AssertIsLess(api, c.Pub.ActiveNoteTreeNumber, uint64(MaxNoteTreeNumber)+1, NoteTreeNumberBits+1)

	// Output-tree count bounds.
	maxNoteLeaves := uint64(1) << c.Shape.NoteDepth
	AssertIsLessOrEqual(api, c.Pub.CountOld, maxNoteLeaves, CountBits)
	AssertIsLessOrEqual(api, c.Pub.CountNew, maxNoteLeaves, CountBits)

	// Rollover semantics for the output tree (mirrors the epoch circuit): when not rolling over the
	// tree must not be full and the frontier must reproduce the active root; when rolling over the
	// tree must be full and we start from an empty state.
	rollover := AsBool(c.Pub.Rollover)
	AssertIsBool(api, rollover)
	notRollover := Not(api, rollover)
	AssertIsLessIf(api, notRollover, c.Pub.CountOld, maxNoteLeaves, CountBits)
	AssertEqualIfU64(api, rollover, c.Pub.CountOld, maxNoteLeaves)

	// The active output tree's frontier is supplied as a private witness (NoteFrontierOld) and bound to
	// the public ActiveNoteTreeRoot when not rolling over; in private-mint mode we append onto it. This
	// mirrors the epoch circuit so gift claims can mint into a NON-empty active tree (CountOld > 0), not
	// just an empty one. Inactive (public-payout) claims do not append, so the evolving state is reused.
	currentFrontier := make([]frontend.Variable, c.Shape.NoteDepth)
	frontierRoot := computeRootFromFrontier(api, c.Priv.NoteFrontierOld, c.Pub.CountOld, c.Shape.NoteDepth)
	AssertEqualIf(api, notRollover, frontierRoot, c.Pub.ActiveNoteTreeRoot)

	// Rollover starts from an empty state; otherwise from the witnessed old frontier/count.
	currentCount := Select(api, rollover, 0, c.Pub.CountOld)
	for i := 0; i < c.Shape.NoteDepth; i++ {
		currentFrontier[i] = Select(api, rollover, 0, c.Priv.NoteFrontierOld[i])
	}

	claimActive := make([]Bool, c.Shape.MaxGiftClaims)
	for c0 := 0; c0 < c.Shape.MaxGiftClaims; c0++ {
		claimActive[c0] = isGreaterThanConst(api, c.Pub.NClaims, uint64(c0), CountBits)
	}

	return giftClaimInternalState{
		currentCount:    currentCount,
		currentFrontier: currentFrontier,
		fullTreeRoot:    0,
		claimActive:     claimActive,
	}
}

// =============================================================================
// Per-claim core logic
// =============================================================================

// processClaim enforces the full per-claim constraint set for slot c0, gated by claimActive[c0].
func (c *GiftClaimCircuit) processClaim(api frontend.API, state *giftClaimInternalState, c0 int) {
	claimActive := state.claimActive[c0]
	claimInactive := Not(api, claimActive)

	// Zero padding for inactive claim slots (binds NClaims between circuit and contract).
	AssertIsZeroIf(api, claimInactive, c.Pub.NullifiersOut[c0])
	AssertIsZeroIf(api, claimInactive, c.Pub.CommitmentsOut[c0])
	AssertIsZeroIf(api, claimInactive, c.Pub.OutputTokenIds[c0])
	AssertIsZeroIf(api, claimInactive, c.Pub.OutputAmounts[c0])
	// Inactive (padded) slots must also carry a zero digest, like the per-slot outputs above. The
	// recipient EdDSA check that binds ClaimDigestHi/Lo is gated off on inactive slots, so without
	// this a multi-claim batch would expose two unconstrained public field elements per padded slot
	// and leave the NClaims zero-padding incomplete. The witness builder zero-fills both halves for
	// padded slots (giftClaimZeroSlot), so this only adds the matching circuit constraint.
	AssertIsZeroIf(api, claimInactive, c.Pub.ClaimDigestHi[c0])
	AssertIsZeroIf(api, claimInactive, c.Pub.ClaimDigestLo[c0])

	// Range checks for active slots.
	AssertIsNBits(api, c.Priv.Amount[c0], AmountBits)
	AssertIsNBits(api, c.Priv.TokenId[c0], TokenIDBits)
	AssertIsLessIf(api, claimActive, c.Priv.FundingTreeNumber[c0], uint64(MaxNoteTreeNumber)+1, NoteTreeNumberBits+1)

	// BranchType must be boolean (0 = recipient claim, 1 = sender refund).
	branchType := AsBool(c.Priv.BranchType[c0])
	AssertIsBool(api, branchType)
	recipientBranch := And(api, claimActive, Not(api, branchType))
	refundBranch := And(api, claimActive, branchType)

	// Secret-bearer claim sub-mode (off-by-default, audit-gated): split an active recipient claim into the wallet-bound
	// path (eoaClaim) and the secret-bearer path (secretClaim). SecretMode is meaningful only on an
	// active recipient claim, so it is forced to zero on refund and inactive slots (Not(recipientBranch)).
	secretMode := AsBool(c.Priv.SecretMode[c0])
	AssertIsBool(api, secretMode)
	AssertIsZeroIf(api, Not(api, recipientBranch), c.Priv.SecretMode[c0])
	eoaClaim := And(api, recipientBranch, Not(api, secretMode))
	secretClaim := And(api, recipientBranch, secretMode)

	// BranchSelectors selects the on-chain payout mode: 1 = private mint (append output to the tree),
	// 0 = public payout (no append; the contract pays an external destination). Must be boolean.
	mintMode := AsBool(c.Pub.BranchSelectors[c0])
	AssertIsBool(api, mintMode)
	// Secret-bearer authority never permits an amount-hidden mint. Its only valid settlement
	// is the public-payout branch, whose destination is bound through the public claim digest.
	AssertIsZeroIf(api, secretClaim, c.Pub.BranchSelectors[c0])
	// A set selector on an inactive slot would imply an append for a padded claim.
	AssertIsZeroIf(api, claimInactive, c.Pub.BranchSelectors[c0])

	// --- Gift binding: BOTH branches re-derive giftNPK and assert C_gift. ---
	// inner = Poseidon(domainGiftBind, blind, refundField)
	// giftNPK = Poseidon(domainGiftBind, recipientSlot, inner)
	inner := Poseidon2T4(api, domainGiftBind, c.Priv.Blind[c0], c.Priv.RefundField[c0])
	giftNPK := Poseidon2T4(api, domainGiftBind, c.Priv.RecipientSlot[c0], inner)
	AssertEqualIf(api, claimActive, giftNPK, c.Priv.GiftNPK[c0])
	// C_gift below is a note-domain leaf proved against the shared note tree, and that tree still
	// holds the withdrawal markers appended before the marker-free cutover. A marker has the same
	// Poseidon(domainNote, key, tokenId, amount) shape with an address in the key position, so the
	// gift relation is a third path to one. giftNPK is itself a Poseidon output, so that path costs
	// a preimage search: this closes it structurally rather than pricing it, the same way the epoch
	// and forced spend relations do.
	//
	// Gated on claimActive rather than recipientBranch, so it binds the sender refund at :386 too.
	// A gift whose key landed in the reserved range would be neither claimable nor refundable, which
	// is the right trade at a rate near 2^-94 and the reason the range is refused rather than
	// remapped.
	AssertSpendableNPKIf(api, claimActive, giftNPK)

	// C_gift = Poseidon(domainNote, giftNPK, tokenId, amount)
	cGift := Poseidon2T4(api, domainNote, giftNPK, c.Priv.TokenId[c0], c.Priv.Amount[c0])
	AssertEqualIf(api, claimActive, cGift, c.Priv.CGift[c0])

	// --- Funding-tree membership: C_gift exists in the selected funding tree (tree-number-bound). ---
	fundingRoot := computeRoot(api, cGift, c.Priv.GiftLeafIndex[c0], c.Priv.FundingTreePath[c0], c.Shape.NoteDepth)
	AssertRootWithTreeNumberIf(api, claimActive, fundingRoot, c.Priv.FundingTreeNumber[c0], c.Pub.NoteKnownRoots, c.Pub.NoteKnownTreeNumbersPacked)

	// --- Gift nullifier: tree-number-bound, shared by claim and refund. ---
	// combinedDomain = domainGiftNull + fundingTreeNumber * NullifierTreeNumberMultiplier
	combinedDomain := api.Add(domainGiftNull, api.Mul(c.Priv.FundingTreeNumber[c0], NullifierTreeNumberMultiplier))
	giftNullifier := Poseidon2T4(api, combinedDomain, giftNPK, c.Priv.GiftLeafIndex[c0])
	AssertEqualIf(api, claimActive, giftNullifier, c.Pub.NullifiersOut[c0])
	AssertIsNonZeroIf(api, claimActive, c.Pub.NullifiersOut[c0])

	// --- Branch authority. ---
	// Wallet-bound recipient claim vs secret-bearer claim are mutually exclusive on a recipient claim.
	recipientAccountID := c.assertRecipientBranch(api, eoaClaim, c0)
	c.assertSecretClaimBranch(api, secretClaim, c0)
	approvalLeaf, refundUseApproval, refundApprovalActive := c.assertRefundBranch(api, refundBranch, c0)
	directAccountID := Select(api, branchType, c.Priv.SenderAccountId[c0], recipientAccountID)
	directKeyLeaf := Poseidon2T4(
		api,
		domainRegLeaf,
		directAccountID,
		c.Priv.AuthPkX[c0],
		c.Priv.AuthPkY[c0],
		c.Priv.AuthExpiry[c0],
	)
	refundAuthLeaf := Select(api, refundUseApproval, approvalLeaf, directKeyLeaf)
	authEnabled := Or(api, eoaClaim, refundBranch)
	selectedAuthLeaf := Select(api, branchType, refundAuthLeaf, directKeyLeaf)
	AssertIsNonZeroIf(api, authEnabled, selectedAuthLeaf)
	c.assertAuthorizationMembership(api, authEnabled, selectedAuthLeaf, c0)

	// --- Authorization signature. ---
	// One EdDSA verification serves both signature-bearing branches: the wallet-bound recipient
	// claim and the direct-key sender refund. Both verify under the same AuthPkX/AuthPkY columns
	// that directKeyLeaf commits to, so the membership proof above also pins the signing key to
	// the registered authorization key for that account. Without this the refund branch would be
	// authorized purely by senderNk plus public registry data, which a proof service can hold.
	// The Safe approval refund carries its authority in the approval commitment (which itself binds
	// ClaimDigestHi/Lo) and stays signature-free, as do secret-bearer claims and inactive slots.
	//
	// The gate is authEnabled minus the Safe-approved refunds, which is exactly
	// eoaClaim OR (refundBranch AND NOT refundUseApproval). Both terms are products the slot has
	// already paid for, and the subtraction is affine, so widening the signature gate to cover
	// direct-key refunds costs no additional constraints. The identity is sound because eoaClaim
	// and refundBranch can never both be set: branchType is boolean and the two branches multiply
	// claimActive by branchType and by its complement, so their product is identically zero, which
	// makes approvalActive a subset of authEnabled.
	//
	// The message is the destination-bound claim digest, so a signature cannot be replayed against a
	// different payout target, token, or amount.
	signatureEnabled := AsBool(api.Sub(authEnabled.AsField(), refundApprovalActive.AsField()))
	claimMsg := Poseidon2T4(api, domainApprove, c.Pub.ClaimDigestHi[c0], c.Pub.ClaimDigestLo[c0])
	authPk := AffinePoint{X: c.Priv.AuthPkX[c0], Y: c.Priv.AuthPkY[c0]}
	authSig := EdDSASignature{
		R8: AffinePoint{X: c.Priv.AuthSigR8x[c0], Y: c.Priv.AuthSigR8y[c0]},
		S:  c.Priv.AuthSigS[c0],
	}
	VerifyEdDSAIf(api, signatureEnabled, authPk, authSig, claimMsg)

	// --- Value conservation + per-mode token/amount privacy. ---
	// Token and amount are PRIVATE witnesses. They bind to the public OutputTokenIds/OutputAmounts only
	// in public-payout (exit) mode, where the on-chain withdrawal must reveal them to pay the ERC-20.
	// In private-mint mode (wallet recipient claim / sender refund) the public columns are forced to zero, so a
	// private claim never exposes the gifted value on chain; the output commitment below binds the real
	// token/amount from the private witnesses instead. The payout-mode equality keeps exit payout-sound
	// (the proven gift amount equals the revealed amount, so the exit cannot over-pay).
	mintActive := And(api, claimActive, mintMode)
	payoutActive := And(api, claimActive, Not(api, mintMode))
	publicEOAClaim := And(api, payoutActive, eoaClaim)
	publicRefund := And(api, payoutActive, refundBranch)
	publicSecretClaim := And(api, payoutActive, secretClaim)
	// A public payout has no minted note, so reuse its otherwise-unused commitment
	// column as a per-leaf revocation binding. Wallet claims and sender refunds expose
	// the exact authorization leaf; only secret-bearer exits remain authless.
	AssertEqualIf(api, publicEOAClaim, c.Pub.CommitmentsOut[c0], directKeyLeaf)
	AssertEqualIf(api, publicRefund, c.Pub.CommitmentsOut[c0], refundAuthLeaf)
	AssertIsZeroIf(api, publicSecretClaim, c.Pub.CommitmentsOut[c0])
	AssertIsZeroIf(api, mintActive, c.Pub.OutputTokenIds[c0])
	AssertIsZeroIf(api, mintActive, c.Pub.OutputAmounts[c0])
	AssertEqualIf(api, payoutActive, c.Pub.OutputTokenIds[c0], c.Priv.TokenId[c0])
	AssertEqualIf(api, payoutActive, c.Pub.OutputAmounts[c0], c.Priv.Amount[c0])

	// --- Mint output commitment and append in private-mint mode. ---
	c.assertAndAppendMint(api, state, claimActive, mintMode, c0)
}

// assertRecipientBranch enforces the recipient-claim authority (gated by `enabled`):
//   - accountId_R = Poseidon(domainAccountId, recipientSlot, salt_R) binds wallet ownership;
//   - the recipient auth key is registered in a contract-admissible auth tree (Merkle membership);
//   - MPK_target = Poseidon(domainMPK, accountId_R, nk_R) binds the mint to the recipient's own MPK.
//
// One shared accountId_R witness spans wallet binding, auth membership, and target-MPK derivation,
// so the claim can mint only to the account that controls the funded wallet address.
//
// The EdDSA signature over the PB:GIFT_CLAIM:v2 digest lives in processClaim, which gates one shared
// verification on this branch plus the direct-key refund branch.
func (c *GiftClaimCircuit) assertRecipientBranch(api frontend.API, enabled Bool, c0 int) frontend.Variable {
	// accountId_R = Poseidon(domainAccountId, recipientSlot, salt_R) — wallet ownership binding.
	accountIdR := Poseidon2T4(api, domainAccountId, c.Priv.RecipientSlot[c0], c.Priv.RecipientSalt[c0])
	AssertEqualIf(api, enabled, accountIdR, c.Priv.RecipientAccountId[c0])

	// MPK_target = Poseidon(domainMPK, accountId_R, nk_R) — mint destination bound to recipient MPK.
	targetMPK := Poseidon2T4(api, domainMPK, accountIdR, c.Priv.RecipientNk[c0])
	AssertEqualIf(api, enabled, targetMPK, c.Priv.TargetMPK[c0])
	return accountIdR
}

// assertSecretClaimBranch enforces the secret-bearer claim authority (gated by `enabled`).
// In this mode the gift's recipient slot commits to a claim secret, where
// recipientSlot = low160(Poseidon(domainGiftSecret, ClaimSecret)). Proving knowledge of ClaimSecret is sufficient
// to spend the gift, with no wallet binding, auth-leaf membership, or EdDSA. Whoever holds the secret
// can claim to a public payout destination of their choosing. The private-mint branch is disabled for
// secret claims in processClaim, so TargetMPK and OutputNoteRnd are unused. Anti-clawback is unchanged
// because claim and refund still share one nullifier.
//
// The recipient slot is the LOW 160 bits of the Poseidon commitment, not the full field element, so a
// secret-bearer gift's slot has the same 20-byte/address shape as a wallet-bound gift's. Every gift wire
// format, including the gift ciphertext, claim-link opening, and on-chain GiftFunding, carries it in a 20-byte slot,
// so a full field-element commitment would be truncated there and the rebuilt giftNPK would not match.
// 160-bit preimage resistance is ample for a bearer secret.
func (c *GiftClaimCircuit) assertSecretClaimBranch(api frontend.API, enabled Bool, c0 int) {
	secretCommit := Poseidon2T4(api, domainGiftSecret, c.Priv.ClaimSecret[c0])
	commitBits := api.ToBinary(secretCommit, 254)
	low160 := api.FromBinary(commitBits[:160]...)
	AssertEqualIf(api, enabled, low160, c.Priv.RecipientSlot[c0])
}

// assertRefundBranch enforces the sender-refund authority (gated by `enabled`):
//   - senderMPK = Poseidon(domainMPK, accountId_S, senderNk);
//   - refundField = Poseidon(domainGiftRefund, senderMPK, refundAfterBlock) — ties the opened
//     refundField (which fed giftNPK) to the sender's MPK and chosen deadline;
//   - either the sender's registered key leaf or a Safe batch approval leaf is present in the
//     selected auth tree; and
//   - CurrentBlock >= refundAfterBlock (deadline elapsed).
//
// The refund field still proves the original sender controls senderNk. The authorization leaf adds
// the missing spend-policy check: ordinary accounts retain their key-leaf path, while approval-only
// Safe accounts have no key leaf and must consume a Safe-approved commitment bound to this refund
// digest. A private-mint refund remains bound to senderMPK; a public payout exposes the exact leaf so
// the contract can reject a revoked approval or key immediately.
func (c *GiftClaimCircuit) assertRefundBranch(api frontend.API, enabled Bool, c0 int) (frontend.Variable, Bool, Bool) {
	// senderMPK = Poseidon(domainMPK, accountId_S, senderNk).
	senderMPK := Poseidon2T4(api, domainMPK, c.Priv.SenderAccountId[c0], c.Priv.SenderNk[c0])

	// refundField = Poseidon(domainGiftRefund, senderMPK, refundAfterBlock) must match the opened
	// refundField that was hashed into giftNPK — binding the refunder to the real gift's sender.
	refundField := Poseidon2T4(api, domainGiftRefund, senderMPK, c.Priv.RefundAfterBlock[c0])
	AssertEqualIf(api, enabled, refundField, c.Priv.RefundField[c0])

	// Deadline: CurrentBlock >= refundAfterBlock. Equivalent to NOT(CurrentBlock < refundAfterBlock).
	beforeDeadline := isLessThanVar(api, c.Pub.CurrentBlock, c.Priv.RefundAfterBlock[c0], BlockNumberBits)
	AssertIsFalseIf(api, enabled, beforeDeadline)

	return c.assertRefundAuthorization(api, enabled, c0)
}

// assertRefundAuthorization builds the Safe approval candidate and selects whether the refund
// uses it. The recipient and refund branches are mutually exclusive, so this reuses the slot's
// existing auth-tree witness fields.
// A direct-key refund is authorized by the EdDSA signature processClaim verifies under the same
// AuthPkX/AuthPkY columns its key leaf commits to, so senderNk plus public registry data is not
// sufficient to build the witness. Key-leaf membership additionally keeps the direct path
// unavailable to approval-only Safe accounts, which must consume an approval commitment instead.
func (c *GiftClaimCircuit) assertRefundAuthorization(api frontend.API, enabled Bool, c0 int) (frontend.Variable, Bool, Bool) {
	useApproval := AsBool(c.Priv.RefundUseApproval[c0])
	AssertIsBool(api, useApproval)
	AssertIsZeroIf(api, Not(api, enabled), c.Priv.RefundUseApproval[c0])
	approvalActive := And(api, enabled, useApproval)

	commitment := Poseidon2T4(
		api,
		domainApproveCommit,
		c.Pub.ClaimDigestHi[c0],
		c.Pub.ClaimDigestLo[c0],
		c.Priv.RefundBlinding[c0],
	)
	batchRoot := computeRoot(
		api,
		commitment,
		c.Priv.RefundBatchIndex[c0],
		c.Priv.RefundBatchSiblings[c0],
		SpendApprovalBatchDepth,
	)
	approvalLeaf := Poseidon2T4(
		api,
		domainApprovalLeaf,
		c.Priv.SenderAccountId[c0],
		batchRoot,
		c.Priv.AuthExpiry[c0],
	)
	AssertIsNonZeroIf(api, approvalActive, c.Priv.AuthExpiry[c0])
	return approvalLeaf, useApproval, approvalActive
}

// assertAuthorizationMembership authenticates the leaf selected by the active
// wallet-claim or sender-refund branch. Both branches use the same witness path,
// so selecting first avoids a second depth-sized Merkle computation per slot.
func (c *GiftClaimCircuit) assertAuthorizationMembership(api frontend.API, enabled Bool, authLeaf frontend.Variable, c0 int) {
	authRoot := computeDomainRoot(
		api,
		authLeaf,
		c.Priv.AuthLeafIndex[c0],
		c.Priv.AuthPathElements[c0],
		c.Shape.SenderAuthDepth,
		domainRegNode,
	)
	AssertRootWithTreeNumberIf(
		api,
		enabled,
		authRoot,
		c.Priv.AuthTreeNumber[c0],
		c.Pub.AuthKnownRoots,
		c.Pub.AuthKnownTreeNumbersPacked,
	)

	// AuthRegistry leaf expiries are uint64 UNIX timestamps and zero means no
	// expiry. A finite leaf must remain live at the proof's anchored timestamp.
	AssertIsNBitsIf(api, enabled, c.Priv.AuthExpiry[c0], TimestampBits)
	finiteExpiry := And(api, enabled, Not(api, IsEqual(api, c.Priv.AuthExpiry[c0], 0)))
	AssertIsNBitsIf(api, finiteExpiry, api.Sub(c.Priv.AuthExpiry[c0], c.Pub.ProvingTimestamp), TimestampBits)
}

// assertAndAppendMint binds the per-claim output commitment and appends it to the active output tree
// in private-mint mode.
//
// In private-mint mode (mintMode=1) the recipient/sender note is appended to the tree. In public-
// payout mode (mintMode=0) the contract pays an external destination and nothing is appended; its
// commitment column is instead used by processClaim for the public-exit auth-leaf binding.
func (c *GiftClaimCircuit) assertAndAppendMint(api frontend.API, state *giftClaimInternalState, claimActive, mintMode Bool, c0 int) {
	// The minted note's NPK: a wallet recipient mints to TargetMPK, while a sender refund mints back to senderMPK.
	// Both are carried by the witness; the active branch's binding above pins the correct one.
	// outputNPK = Poseidon(domainNote, mintMPK, outputNoteRnd).
	branchType := AsBool(c.Priv.BranchType[c0])
	senderMPK := Poseidon2T4(api, domainMPK, c.Priv.SenderAccountId[c0], c.Priv.SenderNk[c0])
	mintMPK := Select(api, branchType, senderMPK, c.Priv.TargetMPK[c0])

	outputNPK := Poseidon2T4(api, domainNote, mintMPK, c.Priv.OutputNoteRnd[c0])
	// Bind the output commitment to the PRIVATE token/amount, not the public columns (which are zero in
	// mint mode): the commitment hides the gifted value behind its Poseidon hash on the private path.
	outputCommitment := Poseidon2T4(api, domainNote, outputNPK, c.Priv.TokenId[c0], c.Priv.Amount[c0])

	// Append into the active output tree only in private-mint mode for active claims.
	appendEnabled := And(api, claimActive, mintMode)
	AssertEqualIf(api, appendEnabled, outputCommitment, c.Pub.CommitmentsOut[c0])
	AssertIsNonZeroIf(api, appendEnabled, c.Pub.CommitmentsOut[c0])
	nextFrontier, nextCount, finalCarry := appendFrontier(api, state.currentFrontier, state.currentCount, c.Pub.CommitmentsOut[c0], c.Shape.NoteDepth)
	for i := 0; i < c.Shape.NoteDepth; i++ {
		state.currentFrontier[i] = Select(api, appendEnabled, nextFrontier[i], state.currentFrontier[i])
	}
	state.currentCount = Select(api, appendEnabled, nextCount, state.currentCount)
	state.fullTreeRoot = Select(api, appendEnabled, finalCarry, state.fullTreeRoot)
}

// assertFinalState binds the evolving output-tree state to public (RootNew, CountNew).
func (c *GiftClaimCircuit) assertFinalState(api frontend.API, state giftClaimInternalState) {
	maxCount := uint64(1) << c.Shape.NoteDepth
	isFull := IsEqual(api, state.currentCount, maxCount)

	computedRoot := computeRootFromFrontier(api, state.currentFrontier, state.currentCount, c.Shape.NoteDepth)
	rootNew := api.Select(isFull.AsField(), state.fullTreeRoot, computedRoot)

	AssertEqual(api, rootNew, c.Pub.RootNew)
	AssertEqual(api, state.currentCount, c.Pub.CountNew)
}
