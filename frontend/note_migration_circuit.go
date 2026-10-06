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

import "github.com/consensys/gnark/frontend"

// =============================================================================
// NoteMigration circuit
// =============================================================================

// NoteMigrationCircuit rewrites each legacy leaf to an address leaf with the
// exact same NPK and amount. It cannot transfer, charge fees, or change gift
// conditions, so no spend authorization is needed. Both note kinds share one
// relation and consume their original legacy nullifiers, so NoteMigration and a
// legacy recovery cannot both spend the same leaf.
//
// Division of labour with LibNoteMigration on chain. The contract bounds the
// batch against the pool's maxBatchSize, requires a non-empty nullifier array of
// the same length as the commitment array, admits each claimed root through the
// shared root-history policy, records every nullifier in the pool-wide spent map
// so a replay or a competing legacy exit reverts, and supplies assetSnapshotRoot
// and firstNoteTreeV2 from activation storage. The circuit assumes none
// of that: it proves membership under the roots it is handed, derives each
// nullifier and output commitment, and enforces the append arithmetic.
//
// Witness authors must present the active notes as a prefix of every array,
// leave every inactive slot entirely zero, and zero the half of an active slot
// that belongs to the other note kind.
type NoteMigrationCircuit struct {
	// Shape holds fixed sizing parameters (compile-time circuit shape, not constrained).
	Shape NoteMigrationShape

	// Public inputs are verified by the verifier/contract.
	Pub NoteMigrationPublicInputs

	// Private inputs are provided by the prover as witness-only values.
	Priv NoteMigrationPrivateInputs
}

// NoteMigrationShape defines fixed sizing parameters for this circuit instance.
// These values affect circuit allocation/structure but do not add constraints by themselves.
type NoteMigrationShape struct {
	MaxNotes             int // maximum legacy notes rewritten in one proof
	MerkleDepth          int // depth of note commitment trees (leaf capacity = 2^MerkleDepth)
	MaxNoteRootsPerProof int // number of note roots provided in a proof
}

// NoteMigrationPublicInputs binds the legacy spend and native append to one activation.
// Field order is shared with LibNoteMigration.publicInputs in Solidity. Reordering
// fields changes the verifier's public vector and requires new proving keys.
// Exported field spelling is frozen for witness-builder compatibility. New identifiers use Go initialisms.
type NoteMigrationPublicInputs struct {
	// The shared append relation. Its NoteKnownRoots table is also the legacy root table the
	// spent notes are proven against, and its NAppends is the active prefix length of both
	// per-note arrays below, because one migrated note produces exactly one appended leaf.
	NoteAppend

	// Per-note results, active prefix first and zero padded to MaxNotes.
	Nullifiers     []frontend.Variable `gnark:",public"` // [MaxNotes] legacy nullifiers consumed
	CommitmentsOut []frontend.Variable `gnark:",public"` // [MaxNotes] native leaves appended, in the same order

	// Immutable activation boundary, supplied by the pool rather than the prover.
	AssetSnapshotRoot frontend.Variable `gnark:",public"` // root of the sealed legacy ID-to-address snapshot
	FirstNoteTreeV2   frontend.Variable `gnark:",public"` // lowest native tree number, so inputs must be below it
}

// NoteMigrationPrivateInputs holds the witness-only legacy openings and the
// frontier the native append starts from.
// Exported field spelling is frozen for witness-builder compatibility. New identifiers use Go initialisms.
type NoteMigrationPrivateInputs struct {
	Notes           []NoteMigrationOpening // [MaxNotes] legacy note openings, active prefix first
	NoteFrontierOld []frontend.Variable    // [MerkleDepth] frontier for the active output tree
}

// NoteMigrationOpening opens one legacy wallet or gift note and its registry asset.
// IsGift selects the NPK/nullifier preimages; fields belonging to the other kind
// must be zero, as must every field in an inactive slot.
//
// The other circuits in this package use parallel per-field slices. This one nests
// instead because a slot is only meaningful as a whole: the two kinds share a slot and
// a reader has to see which fields belong to the same note to check the zero-padding
// rules above. Asset is nested for the same reason, and its Siblings is a fixed-size
// array rather than a Shape-sized slice because the legacy snapshot depth is sealed by
// the deployed format, not chosen per verifier registration.
type NoteMigrationOpening struct {
	// Asset proves the legacy ID-to-address mapping; Path proves note membership.
	Asset        AssetSnapshotOpening
	TokenAddress frontend.Variable   // 160-bit ERC-20 address the legacy ID normalizes to
	Amount       frontend.Variable   // 96-bit note value, preserved unchanged by the rewrite
	TreeNumber   frontend.Variable   // 15-bit legacy tree the note lives in, below the boundary
	LeafIndex    frontend.Variable   // leaf position within that tree
	Path         []frontend.Variable // [MerkleDepth] sibling path to the legacy note root
	IsGift       frontend.Variable   // boolean selecting which preimage half below is live

	// Wallet-note NPK and nullifier preimages, zero for a gift note.
	AccountId     frontend.Variable // wallet account identifier
	NullifyingKey frontend.Variable // wallet nullifier derivation key
	NoteRnd       frontend.Variable // wallet note randomness

	// Gift-note recipient and refund bindings, preserved by NoteMigration and
	// zero for a wallet note.
	RecipientSlot frontend.Variable // gift recipient binding
	Blind         frontend.Variable // gift commitment blinding
	RefundField   frontend.Variable // gift refund conditions
}

// AssetSnapshotOpening is private even when a proof spends several legacy IDs
// that normalize to one address. Inactive openings must be zero.
type AssetSnapshotOpening struct {
	ID       frontend.Variable                     // nonzero legacy registry id of the note's asset
	Siblings [AssetSnapshotDepth]frontend.Variable // sibling path under the sealed snapshot root
}

// NoteFormatContext binds the first native tree to the pool's activation boundary.
// It is assembled inside validateInputs from the circuit's own public inputs and is
// never embedded in a witness struct, so its field carries no gnark visibility tag.
type NoteFormatContext struct {
	FirstNoteTreeV2 frontend.Variable // first tree containing V2 notes
}

// =============================================================================
// Constructor
// =============================================================================

// NewNoteMigrationCircuit allocates the fixed note capacity, Merkle paths, and
// public root slots. The supplied dimensions must match the registered verifier.
func NewNoteMigrationCircuit(maxNotes, merkleDepth, maxNoteRootsPerProof int) *NoteMigrationCircuit {
	c := &NoteMigrationCircuit{
		Shape: NoteMigrationShape{
			MaxNotes:             maxNotes,
			MerkleDepth:          merkleDepth,
			MaxNoteRootsPerProof: maxNoteRootsPerProof,
		},
		Pub: NoteMigrationPublicInputs{
			NoteAppend:     NoteAppend{NoteKnownRoots: make([]frontend.Variable, maxNoteRootsPerProof)},
			Nullifiers:     make([]frontend.Variable, maxNotes),
			CommitmentsOut: make([]frontend.Variable, maxNotes),
		},
		Priv: NoteMigrationPrivateInputs{
			Notes:           make([]NoteMigrationOpening, maxNotes),
			NoteFrontierOld: make([]frontend.Variable, merkleDepth),
		},
	}

	for i := range c.Priv.Notes {
		c.Priv.Notes[i].Path = make([]frontend.Variable, merkleDepth)
	}

	return c
}

// =============================================================================
// Define
// =============================================================================

// Define proves legacy membership and nullifiers, preserves each note's spend
// rights and value, and appends the corresponding native commitments.
func (c *NoteMigrationCircuit) Define(api frontend.API) error {
	state := c.validateInputs(api)

	c.processNotes(api, state)

	// Commit one native leaf per active legacy input, preserving their order.
	c.Pub.applyBatchAppend(api, c.Shape.MerkleDepth, c.Pub.CommitmentsOut, &state)
	c.Pub.assertFinalState(api, c.Shape.MerkleDepth, state)

	return nil
}

// =============================================================================
// Validation helpers
// =============================================================================

// validateInputs is this circuit's single validation entry point: it binds the format boundary,
// validates the append relation's public tree inputs, and bounds and pads every per-note witness
// the processing loop hashes. It returns the tree state Define needs to commit the migrated leaves.
func (c *NoteMigrationCircuit) validateInputs(api frontend.API) noteAppendState {
	// Bind the immutable format boundary and the native append tree.
	context := NoteFormatContext{FirstNoteTreeV2: c.Pub.FirstNoteTreeV2}
	context.validateBoundary(api)
	context.assertNative(api, True(), c.Pub.ActiveNoteTreeNumber)
	AssertIsNonZero(api, c.Pub.AssetSnapshotRoot)
	AssertIsNBits(api, api.Add(c.Pub.ActiveNoteTreeNumber, c.Pub.Rollover), NoteTreeNumberBits)

	// The embedded append relation validates its own public tree inputs and builds the one
	// activity prefix this circuit needs, since a migrated note is exactly one appended leaf.
	state := c.Pub.validateAndInitTreeState(api, c.Shape.MaxNotes, c.Shape.MerkleDepth, c.Priv.NoteFrontierOld)

	c.validateNotes(api, state)
	return state
}

// validateNotes bounds and pads the per-note preimage fields. Every field the contract encodes at
// a fixed width is bounded here rather than at its point of use, the padding that pins an inactive
// slot and the unused half of an active slot's note kind to zero sits alongside it, and so does the
// boundary that keeps an input in a legacy tree. The ID-to-bits decomposition stays with membership
// instead, because there it is not a standalone range check but the sibling-ordering selector.
func (c *NoteMigrationCircuit) validateNotes(api frontend.API, state noteAppendState) {
	for i, note := range c.Priv.Notes {
		active := state.commitmentActive[i]
		inactive := Not(api, active)
		gift := AsBool(note.IsGift)

		AssertIsBool(api, gift)

		// Match the on-chain address, amount, and tree-number widths.
		AssertIsNBits(api, note.TokenAddress, AddressBits)
		AssertIsNonZeroIf(api, active, note.TokenAddress)
		AssertIsNBits(api, note.Amount, AmountBits)
		AssertIsNBits(api, note.RecipientSlot, AddressBits)
		AssertIsNBits(api, note.TreeNumber, NoteTreeNumberBits)

		// Input trees must precede the immutable activation boundary. The append
		// relation targets a native tree, so an output cannot migrate a second time.
		AssertIsNBitsIf(api, active, api.Sub(c.Pub.FirstNoteTreeV2, note.TreeNumber, 1), NoteTreeNumberBits)

		// An active slot opens a real registry entry, whose ids start at one.
		AssertIsNonZeroIf(api, active, note.Asset.ID)

		// Canonical padding pins every field of an inactive slot to zero.
		AssertIsZeroIf(api, inactive, note.Asset.ID)
		AssertIsZeroIf(api, inactive, note.TokenAddress)
		AssertIsZeroIf(api, inactive, note.Amount)
		AssertIsZeroIf(api, inactive, note.TreeNumber)
		AssertIsZeroIf(api, inactive, note.LeafIndex)
		AssertIsZeroIf(api, inactive, note.IsGift)
		for _, sibling := range note.Asset.Siblings {
			AssertIsZeroIf(api, inactive, sibling)
		}
		for _, node := range note.Path {
			AssertIsZeroIf(api, inactive, node)
		}

		// The half of the slot belonging to the other note kind is zero too, so the
		// preimage selection below cannot smuggle a value in from the unused kind.
		walletUnused := Or(api, inactive, gift)
		giftUnused := Not(api, And(api, active, gift))
		AssertIsZeroIf(api, walletUnused, note.AccountId)
		AssertIsZeroIf(api, walletUnused, note.NullifyingKey)
		AssertIsZeroIf(api, walletUnused, note.NoteRnd)
		AssertIsZeroIf(api, giftUnused, note.RecipientSlot)
		AssertIsZeroIf(api, giftUnused, note.Blind)
		AssertIsZeroIf(api, giftUnused, note.RefundField)
	}
}

// =============================================================================
// Core processing
// =============================================================================

// processNotes derives each active note's NPK, proves its legacy leaf, consumes its original
// nullifier, and binds the native commitment that replaces it. Operation order is fixed: the
// asset membership authenticates the token address the output commitment then reuses.
func (c *NoteMigrationCircuit) processNotes(api frontend.API, state noteAppendState) {
	for i, note := range c.Priv.Notes {
		active := state.commitmentActive[i]
		inactive := Not(api, active)
		gift := AsBool(note.IsGift)

		note.Asset.verifyMembership(api, active, c.Pub.AssetSnapshotRoot, note.TokenAddress)

		// Select the preimages before hashing: both kinds have a two-hash NPK
		// construction, so the unused kind does not need its own Poseidon pair.
		// Wallet: inner = Poseidon(domainMPK, accountId, nullifyingKey),
		//         npk = Poseidon(domainNotePublicKey, inner, noteRnd).
		// Gift:   inner = Poseidon(domainGiftBind, blind, refundField),
		//         npk = Poseidon(domainGiftBind, recipientSlot, inner).
		inner := Poseidon2T4(api, Select(api, gift, domainGiftBind, domainMPK),
			Select(api, gift, note.Blind, note.AccountId), Select(api, gift, note.RefundField, note.NullifyingKey))
		npk := Poseidon2T4(api, Select(api, gift, domainGiftBind, domainNotePublicKey),
			Select(api, gift, note.RecipientSlot, inner), Select(api, gift, inner, note.NoteRnd))
		AssertSpendableNPKIf(api, active, npk)

		// Prove the original leaf in its selected legacy tree.
		commitmentV1 := Poseidon2T4(api, domainNoteCommitment, npk, note.Asset.ID, note.Amount)
		root := computeRoot(api, commitmentV1, note.LeafIndex, note.Path, c.Shape.MerkleDepth)
		AssertRootWithTreeNumberIf(api, active, root, note.TreeNumber, c.Pub.NoteKnownRoots, c.Pub.NoteKnownTreeNumbersPacked)

		// Consume the original nullifier: NoteMigration and an existing legacy exit
		// contend for the same on-chain spent entry even though the output domain changes.
		domain := api.Add(Select(api, gift, domainGiftNullifier, domainNullifier), api.Mul(note.TreeNumber, NullifierTreeNumberMultiplier))
		nullifier := Poseidon2T4(api, domain, Select(api, gift, npk, note.NullifyingKey), note.LeafIndex)
		AssertEqualIf(api, active, c.Pub.Nullifiers[i], nullifier)
		AssertIsNonZeroIf(api, active, c.Pub.Nullifiers[i])
		AssertIsZeroIf(api, inactive, c.Pub.Nullifiers[i])

		// Reuse the proven NPK and value with the native commitment domain and
		// the token address authenticated by the legacy asset snapshot above.
		// Preserving gift NPK also preserves the recipient and refund conditions.
		commitmentV2 := Poseidon2T4(api, domainNoteCommitmentV2, npk, note.TokenAddress, note.Amount)
		AssertEqualIf(api, active, c.Pub.CommitmentsOut[i], commitmentV2)
		AssertIsNonZeroIf(api, active, c.Pub.CommitmentsOut[i])
		AssertIsZeroIf(api, inactive, c.Pub.CommitmentsOut[i])
	}
}

// =============================================================================
// NoteMigration witnesses and helpers
// =============================================================================

// validateBoundary requires a nonzero boundary that fits the protocol tree-number width.
func (ctx NoteFormatContext) validateBoundary(api frontend.API) {
	AssertIsNBits(api, ctx.FirstNoteTreeV2, NoteTreeNumberBits)
	AssertIsNonZero(api, ctx.FirstNoteTreeV2)
}

// assertNative excludes legacy trees whenever the associated slot is active.
func (ctx NoteFormatContext) assertNative(api frontend.API, active Bool, tree frontend.Variable) {
	// Both operands are 15-bit integers, so a negative difference cannot wrap
	// into the permitted range of the scalar field.
	AssertIsNBits(api, tree, NoteTreeNumberBits)
	AssertIsNBitsIf(api, active, api.Sub(tree, ctx.FirstNoteTreeV2), NoteTreeNumberBits)
}

// verifyMembership authenticates the legacy ID-to-address leaf under the sealed snapshot.
// The ID decomposition here is the sibling-ordering selector, not a standalone range check,
// which is why it stays with the membership rather than moving into validateNotes.
func (o AssetSnapshotOpening) verifyMembership(api frontend.API, enabled Bool, root, asset frontend.Variable) {
	bits := api.ToBinary(o.ID, AssetSnapshotDepth)

	h := Poseidon2T4(api, domainAssetSnapshotLeaf, o.ID, asset)
	for i, sibling := range o.Siblings {
		left := api.Select(bits[i], sibling, h)
		right := api.Sub(api.Add(h, sibling), left)
		h = Poseidon2T4(api, domainAssetSnapshotNode, left, right)
	}

	AssertEqualIf(api, enabled, h, root)
}
