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
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// =============================================================================
// DepositPortalCircuit
// =============================================================================
//
// This circuit proves a batch of hidden-recipient *portal* deposits that append
// note commitments into an active note commitment tree. It is the sibling of
// DepositEpochCircuit for the portal-deposit (CEX-style reusable address) path.
//
// Why a separate circuit instead of a branch in DepositEpochCircuit: the normal
// deposit binds outputs by having the depositor supply commitments at request
// time, folded into a caller-supplied `commitmentsHash` baked into the request
// id. A portal sweeper does not know `recipientMPK`, so it cannot construct a
// commitment at sweep time — that binding cannot be reused. The portal instead
// binds each appended note to the on-chain `H = Poseidon(D_BIND, recipientMPK, blind)`
// recorded at owner registration, opened in-circuit against an OPAQUE `recipientMPK`
// witness. Keeping this in its own circuit avoids adding portal constraints to
// every normal deposit (the most safety-critical circuit).
//
// What this circuit enforces, per active slot:
//   - **Owner binding**: H_PUB == Poseidon(D_BIND, recipientMPK, blind). Opening the
//     registered H ties the credited note to the account that registered the
//     portal — crediting any other account would require a Poseidon second
//     preimage (the crediting-integrity invariant).
//   - **Note derivation**: noteRnd = Poseidon(D_PNOTE, blind_WITNESS, E_PUB, counter_PUB);
//     NPK = Poseidon(D_NOTE, recipientMPK, noteRnd) — the SAME recipientMPK witness that
//     opened H also builds NPK, which is the hinge that makes the proof
//     satisfiable only when the bound account is the credited account. noteRnd binds
//     the SECRET blind so the leaf is unlinkable on-chain, and public E so two
//     portals sharing a blind cannot collide — see "Recipient hiding" below.
//   - **Commitment correctness**: commitment_PUB == Poseidon(D_NOTE, NPK,
//     tokenId, amount), where amount is the net credited value supplied by the
//     contract from the stored record.
//   - **Tree update**: all active commitments are appended to the active tree
//     (with optional rollover) and the resulting (RootNew, CountNew) matches the
//     public outputs — reusing the deposit-epoch frontier/append logic.
//
// Recipient hiding: `recipientMPK` and `blind` are witness-only, and noteRnd is
// derived from the secret `blind` plus public `E` and `counter`, so the appended
// leaf is NOT recomputable from on-chain-public values alone — reconstructing it
// requires `blind`. This is what keeps the credit unlinkable to a Privacy Boost
// account even against someone holding the recipient's (widely-shared) MPK:
// without blind they cannot recompute noteRnd, hence NPK, hence the commitment.
// `E` is bound as a public domain input so two portals that share a blind still
// produce distinct notes. `blind` lives only with the owner and the discovery
// registry. There is exactly ONE note per portal deposit (the swept balance credits
// a single owner), so unlike DepositEpochCircuit there is no per-request fan-out:
// slot i is request i is commitment i.
//
// What this circuit does NOT prove (same boundaries as DepositEpochCircuit):
//   - It does not prove `NoteKnownRoots` matches the contract's root history; the
//     contract verifies that.
//   - It does not prove the witness `recipientMPK` is itself a well-formed MPK of any
//     registered account; binding only requires it to open the registered H. An
//     attacker cannot exploit this: opening another owner's H to a chosen
//     recipientMPK' is a second-preimage break, and even a self-chosen recipientMPK only
//     credits that same opaque value's notes, never lets the prover spend them
//     (spending still needs the secret nullifyingKey and an EdDSA signature).
//   - It does NOT bind ChainId/PoolAddress in-circuit. Unlike DepositEpochCircuit
//     — which folds them into a computedRequestId (in deposit_epoch_circuit.go)
//     because the depositor supplies commitments at request time — the portal
//     path's chain/pool domain separation is enforced ON-CHAIN: the contract keys
//     each pending record by portalDepositId = keccak256(abi.encode(D_PORTAL_REQUEST,
//     chainId, pool, ...)) and feeds every public input from that record. These
//     two inputs ride in the public vector purely for layout parity with the
//     on-chain verifier; a reviewer must not assume the epoch circuit's request-id
//     binding exists here (it intentionally does not — see the struct doc).
//
// Witness author notes:
//   - Arrays are fixed-size. Only the first `Pub.NRequests` entries are active;
//     all trailing slots MUST be zero-padded.
type DepositPortalCircuit struct {
	// Shape holds fixed sizing parameters (compile-time circuit shape, not constrained).
	Shape DepositPortalShape

	// Public inputs are verified by the verifier/contract.
	Pub DepositPortalPublicInputs

	// Private inputs are provided by the prover as witness-only values.
	Priv DepositPortalPrivateInputs
}

// DepositPortalShape defines fixed sizing parameters for this circuit instance.
// These values affect circuit allocation/structure but do not add constraints by themselves.
type DepositPortalShape struct {
	MaxSlots             int // maximum number of portal deposits per proof (one note each)
	MerkleDepth          int // depth of note commitment trees (leaf capacity = 2^MerkleDepth)
	MaxNoteRootsPerProof int // number of note roots provided in a proof
}

type DepositPortalPublicInputs struct {
	// Tree state — identical shape to the deposit-epoch circuit so the portal
	// epoch can append to the SAME shared note tree under the same CAS rules.
	//
	// ChainId/PoolAddress are present for public-input-layout PARITY with the
	// on-chain verifier (buildPortalDepositInputs emits them in slots 0/1, the
	// same positions buildDepositInputs uses), NOT to bind them in-circuit. The
	// chain/pool domain separation lives ON-CHAIN: the contract keys each pending
	// record by portalDepositId = keccak256(abi.encode(D_PORTAL_REQUEST, chainId,
	// pool, E, tokenId, amount, counter, H)), loads the record by that key, and
	// supplies every public input — including these two — from storage. The
	// circuit is therefore only ever fed the honest contract's chain/pool values;
	// a proof built for one (chain, pool) is not transferable to another because
	// no other contract holds the matching record. Deliberately unconstrained
	// here so the audited circuit stays minimal (it opens H against the opaque
	// recipientMPK witness and nothing more); the layout/no-op is locked by
	// TestDepositPortalCircuit_PublicInputLayout and the WrongChainId/WrongPool
	// tamper tests.
	ChainId                    frontend.Variable   `gnark:",public"` // chain id — contract-pinned for layout parity; not circuit-constrained (see struct doc)
	PoolAddress                frontend.Variable   `gnark:",public"` // pool address — contract-pinned for layout parity; not circuit-constrained (see struct doc)
	NoteKnownRoots             []frontend.Variable `gnark:",public"` // [MaxNoteRootsPerProof] historical note commitment tree roots
	NoteKnownTreeNumbersPacked frontend.Variable   `gnark:",public"` // packed tree numbers (15 bits each)
	ActiveNoteTreeNumber       frontend.Variable   `gnark:",public"` // selects which NoteKnownRoots is the active output tree
	CountOld                   frontend.Variable   `gnark:",public"` // old leaf count in the active output tree
	RootNew                    frontend.Variable   `gnark:",public"` // root after appending all active commitments
	CountNew                   frontend.Variable   `gnark:",public"` // new leaf count after appends
	Rollover                   frontend.Variable   `gnark:",public"` // 0/1 rollover flag for the active tree

	// Batch sizing: number of active portal deposits (1..MaxSlots). One note each,
	// so there is no separate commitment count.
	NRequests frontend.Variable `gnark:",public"` // number of active portal deposits

	// Per-deposit public arrays (active first, then zero padded). The on-chain
	// `buildPortalDepositInputs` lays these out as {E, counter, H, tokenId, amount, commitment}.
	PortalAddresses []frontend.Variable `gnark:",public"` // [MaxSlots] E — public; on active slots E feeds noteRnd (so two portals sharing a blind yield distinct commitments), padding slots are unconstrained
	Counters        []frontend.Variable `gnark:",public"` // [MaxSlots] per-portal sweep counter (feeds noteRnd → note uniqueness)
	RecipientBindHs []frontend.Variable `gnark:",public"` // [MaxSlots] H — the registered owner binding, read on-chain from E's portalBinding()
	TokenIDs        []frontend.Variable `gnark:",public"` // [MaxSlots] token id of the swept balance
	Amounts         []frontend.Variable `gnark:",public"` // [MaxSlots] net credited amount (gross − fee), supplied by the contract from storage
	CommitmentsOut  []frontend.Variable `gnark:",public"` // [MaxSlots] note leaf appended to the tree
}

type DepositPortalPrivateInputs struct {
	// Per-deposit witness (active first, then zero padded). These are the ONLY
	// owner-identifying values, and they never appear in the public witness, so
	// recipient hiding is checkable at a glance.
	RecipientMPKs []frontend.Variable // [MaxSlots] opaque owner master public key (NOT recomputed from a spend secret)
	Blinds        []frontend.Variable // [MaxSlots] per-portal blinding factor that opens H

	// Active tree witness (before appending) — same role as in DepositEpochCircuit.
	NoteFrontierOld []frontend.Variable // [MerkleDepth] frontier for the active output tree
}

// portalInternalState carries cached selectors and the evolving output tree state
// used while constructing constraints in `Define`. It mirrors depositInternalState
// but drops the per-request running accumulators (there is one note per slot).
type portalInternalState struct {
	currentCount    frontend.Variable   // evolving leaf count for the active output tree
	currentFrontier []frontend.Variable // evolving frontier for the active output tree
	fullTreeRoot    frontend.Variable   // root of the full tree, set by applyBatchAppend; read only when currentCount == 2^depth
	depositActive   []Bool              // depositActive[i] := (i < NRequests)
}

// =============================================================================
// Constructor
// =============================================================================

// NewDepositPortalCircuit allocates a sized circuit instance (all slices are allocated to fixed sizes).
//
// These sizing parameters define the circuit shape at compile time; they do not
// add constraints by themselves but determine how many constraints exist once
// `Define` runs (more slots/depth => larger circuit).
func NewDepositPortalCircuit(maxSlots, merkleDepth, maxNoteRootsPerProof int) *DepositPortalCircuit {
	return &DepositPortalCircuit{
		Shape: DepositPortalShape{
			MaxSlots:             maxSlots,
			MerkleDepth:          merkleDepth,
			MaxNoteRootsPerProof: maxNoteRootsPerProof,
		},
		Pub: DepositPortalPublicInputs{
			NoteKnownRoots:  make([]frontend.Variable, maxNoteRootsPerProof),
			PortalAddresses: make([]frontend.Variable, maxSlots),
			Counters:        make([]frontend.Variable, maxSlots),
			RecipientBindHs: make([]frontend.Variable, maxSlots),
			TokenIDs:        make([]frontend.Variable, maxSlots),
			Amounts:         make([]frontend.Variable, maxSlots),
			CommitmentsOut:  make([]frontend.Variable, maxSlots),
		},
		Priv: DepositPortalPrivateInputs{
			RecipientMPKs:   make([]frontend.Variable, maxSlots),
			Blinds:          make([]frontend.Variable, maxSlots),
			NoteFrontierOld: make([]frontend.Variable, merkleDepth),
		},
	}
}

// =============================================================================
// Define
// =============================================================================

// Define builds the constraint system for the portal deposit batch.
func (c *DepositPortalCircuit) Define(api frontend.API) error {
	// Build sizing-dependent selectors and validate public tree inputs / rollover.
	state := c.validateInputs(api)

	// Range-check all per-deposit net amounts (prevents overflow when appended and
	// keeps the credited value within the contract's uint96 amount type).
	for i := 0; i < c.Shape.MaxSlots; i++ {
		AssertIsNBits(api, c.Pub.Amounts[i], AmountBits)
	}

	// Bind each deposit to its owner H and derive its note.
	c.processDeposits(api, &state)

	// Append every active deposit note into the output tree in one batch.
	c.applyBatchAppend(api, &state)

	// Bind the final tree state to public outputs.
	c.assertFinalState(api, state)

	return nil
}

// =============================================================================
// Validation helpers
// =============================================================================

// validateInputs performs basic range/bounds checks and builds cached selectors used by later helpers.
func (c *DepositPortalCircuit) validateInputs(api frontend.API) portalInternalState {
	currentCount, currentFrontier := c.validatePublicInputsAndInitTreeState(api)

	// depositActive[i] gates per-slot constraints so trailing padded slots add no note.
	depositActive := make([]Bool, c.Shape.MaxSlots)
	for i := 0; i < c.Shape.MaxSlots; i++ {
		depositActive[i] = isGreaterThanConst(api, c.Pub.NRequests, uint64(i), CountBits)
	}

	return portalInternalState{
		currentCount:    currentCount,
		currentFrontier: currentFrontier,
		depositActive:   depositActive,
	}
}

// validatePublicInputsAndInitTreeState enforces public bounds, rollover semantics, and binds the
// provided `NoteFrontierOld` witness to the selected active tree root (when not rolling over).
//
// This mirrors DepositEpochCircuit.validatePublicInputsAndInitTreeState exactly so the portal epoch
// shares the same tree-state validation as the deposit/transfer epochs that append to the same tree.
func (c *DepositPortalCircuit) validatePublicInputsAndInitTreeState(api frontend.API) (currentCount frontend.Variable, currentFrontier []frontend.Variable) {
	// Range-check tree counters.
	AssertIsNBits(api, c.Pub.CountOld, CountBits)
	AssertIsNBits(api, c.Pub.CountNew, CountBits)

	// 1 <= NRequests <= MaxSlots (at least one active deposit; the rest are padding).
	AssertIsNonZero(api, c.Pub.NRequests)
	AssertIsLessOrEqual(api, c.Pub.NRequests, uint64(c.Shape.MaxSlots), CountBits)

	// ActiveNoteTreeNumber is within [0, MaxNoteTreeNumber].
	AssertIsLess(api, c.Pub.ActiveNoteTreeNumber, uint64(MaxNoteTreeNumber)+1, NoteTreeNumberBits+1)

	// Tree capacity checks.
	noteTreeCapacityLeaves := uint64(1) << c.Shape.MerkleDepth
	AssertIsLessOrEqual(api, c.Pub.CountOld, noteTreeCapacityLeaves, CountBits)
	AssertIsLessOrEqual(api, c.Pub.CountNew, noteTreeCapacityLeaves, CountBits)

	// Rollover semantics: non-rollover requires CountOld < capacity; rollover requires CountOld == capacity.
	rollover := AsBool(c.Pub.Rollover)
	AssertIsBool(api, rollover)
	notRollover := Not(api, rollover)
	AssertIsLessIf(api, notRollover, c.Pub.CountOld, noteTreeCapacityLeaves, CountBits)
	AssertEqualIfU64(api, rollover, c.Pub.CountOld, noteTreeCapacityLeaves)

	// Bind frontier witness to the selected active tree root when not rolling over.
	knownTreeNumbers := unpackSlots(
		api,
		c.Pub.NoteKnownTreeNumbersPacked,
		len(c.Pub.NoteKnownRoots),
		TreeNumberBitsPerSlot,
	)
	AssertSingleActiveRootForTreeNumber(
		api,
		c.Pub.NoteKnownRoots,
		knownTreeNumbers,
		c.Pub.ActiveNoteTreeNumber,
	)
	activeTreeRoot := selectByTreeNumber(
		api,
		c.Pub.NoteKnownRoots,
		knownTreeNumbers,
		c.Pub.ActiveNoteTreeNumber,
	)
	rootFromFrontier := computeRootFromFrontier(api, c.Priv.NoteFrontierOld, c.Pub.CountOld, c.Shape.MerkleDepth)
	AssertEqualIf(api, notRollover, rootFromFrontier, activeTreeRoot)

	// Rollover starts from an empty state; otherwise from the old state. Select keeps append constraints uniform.
	currentCount = Select(api, rollover, 0, c.Pub.CountOld)
	currentFrontier = make([]frontend.Variable, c.Shape.MerkleDepth)
	for i := 0; i < c.Shape.MerkleDepth; i++ {
		currentFrontier[i] = Select(api, rollover, 0, c.Priv.NoteFrontierOld[i])
	}
	return currentCount, currentFrontier
}

// =============================================================================
// Core processing
// =============================================================================

// processDeposits binds each active portal deposit to its owner H, derives the note from the secret
// blind plus the public (E, counter), and checks the commitment. The notes themselves reach the
// tree later, in one batch, via applyBatchAppend. Trailing inactive slots are zero-padded and
// contribute no note.
func (c *DepositPortalCircuit) processDeposits(api frontend.API, state *portalInternalState) {
	for i := 0; i < c.Shape.MaxSlots; i++ {
		depositActive := state.depositActive[i]
		depositInactive := Not(api, depositActive)

		// Zero padding for inactive slots: every public and witness field of a padded
		// slot must be zero so a prover cannot smuggle an extra note past NRequests.
		AssertIsZeroIf(api, depositInactive, c.Pub.PortalAddresses[i])
		AssertIsZeroIf(api, depositInactive, c.Pub.Counters[i])
		AssertIsZeroIf(api, depositInactive, c.Pub.RecipientBindHs[i])
		AssertIsZeroIf(api, depositInactive, c.Pub.TokenIDs[i])
		AssertIsZeroIf(api, depositInactive, c.Pub.Amounts[i])
		AssertIsZeroIf(api, depositInactive, c.Pub.CommitmentsOut[i])
		AssertIsZeroIf(api, depositInactive, c.Priv.RecipientMPKs[i])
		AssertIsZeroIf(api, depositInactive, c.Priv.Blinds[i])

		// Active deposits must credit a positive amount: a zero-value leaf would
		// consume tree capacity while crediting nothing.
		AssertIsNonZeroIf(api, depositActive, c.Pub.Amounts[i])

		// (1) Open the registered owner binding H against the opaque (recipientMPK, blind)
		// witness. This is the crediting-integrity check: only the account whose
		// recipientMPK satisfies H can be credited; any other requires a Poseidon
		// second preimage. recipientMPK is a witness, never recomputed from a spend secret.
		expectedH := Poseidon2T4(api, domainPortalBind, c.Priv.RecipientMPKs[i], c.Priv.Blinds[i])
		AssertEqualIf(api, depositActive, expectedH, c.Pub.RecipientBindHs[i])

		// (2) Derive the note randomness from the SECRET blind witness, the public portal
		// address E, and the public counter: noteRnd = Poseidon(D_PNOTE, blind, E, counter).
		// blind keeps the credit unlinkable — every other commitment input is public, so a
		// blind-free noteRnd would let anyone holding the recipient's (widely-shared) MPK
		// recompute the leaf and link it to the account; blind is known only to the owner and
		// the discovery registry, so the leaf stays recomputable by the registry-holding
		// indexer but not by an on-chain observer. Binding the public E makes the leaf unique
		// per portal: the circuit does not assume blind differs between a recipient's portals
		// (nothing forces it to), so two portals sharing a blind would — without E in the
		// preimage — produce a colliding commitment on equal-(counter, token, amount) sweeps,
		// leaving the second note unspendable. E is unique per portal by construction.
		noteRnd := Poseidon2T4(api, domainPortalNote, c.Priv.Blinds[i], c.Pub.PortalAddresses[i], c.Pub.Counters[i])

		// (3) The SAME recipientMPK that opened H builds the NPK — this is the hinge that
		// ties the registered binding to the credited note. NPK still hides recipientMPK.
		npk := Poseidon2T4(api, domainNote, c.Priv.RecipientMPKs[i], noteRnd)

		// (4) The commitment binds NPK, token, and the net credited amount. The amount
		// is supplied by the contract from the stored record, so a relay cannot
		// substitute a different credited value here.
		expectedCommitment := Poseidon2T4(api, domainNote, npk, c.Pub.TokenIDs[i], c.Pub.Amounts[i])
		AssertEqualIf(api, depositActive, expectedCommitment, c.Pub.CommitmentsOut[i])
		AssertIsNonZeroIf(api, depositActive, c.Pub.CommitmentsOut[i])

	}
}

// applyBatchAppend appends every active deposit note into the output tree in one batch.
//
// depositActive[i] := (i < NRequests), so the live notes already occupy a prefix of the
// slot array and no routing is needed — a single packed block goes straight into the
// batched append. That costs ~MaxSlots + MerkleDepth Poseidon permutations where appending
// one leaf at a time cost ~MaxSlots * MerkleDepth.
func (c *DepositPortalCircuit) applyBatchAppend(api frontend.API, state *portalInternalState) {
	batch := newPrefixPackedList(api, c.Pub.CommitmentsOut, state.depositActive)

	// currentCount is < 2^MerkleDepth here: rollover forces it to 0, and without rollover
	// validatePublicInputsAndInitTreeState already required CountOld < 2^MerkleDepth.
	// appendFrontierBatch re-checks that, plus that the batch fits in the remaining capacity.
	nextFrontier, nextCount, finalCarry := appendFrontierBatch(
		api,
		state.currentFrontier,
		state.currentCount,
		batch,
		c.Shape.MerkleDepth,
	)
	state.currentFrontier = nextFrontier
	state.currentCount = nextCount
	state.fullTreeRoot = finalCarry
}

// assertFinalState binds the internal working tree state to public outputs.
//
// Identical to DepositEpochCircuit.assertFinalState: when the tree fills,
// computeRootFromFrontier returns an incorrect value, so the full-tree carry from the batch
// append is used instead.
func (c *DepositPortalCircuit) assertFinalState(api frontend.API, state portalInternalState) {
	maxCount := uint64(1) << c.Shape.MerkleDepth
	isFull := IsEqual(api, state.currentCount, maxCount)

	computedRoot := computeRootFromFrontier(api, state.currentFrontier, state.currentCount, c.Shape.MerkleDepth)
	rootNew := api.Select(isFull.AsField(), state.fullTreeRoot, computedRoot)

	AssertEqual(api, rootNew, c.Pub.RootNew)
	AssertEqual(api, state.currentCount, c.Pub.CountNew)
}

// =============================================================================
// Public-input builder (off-circuit)
// =============================================================================
//
// BuildPortalDepositInputs flattens a portal-deposit batch into the exact public
// input vector the Groth16 verifier consumes. It is the Go-side source of truth
// for the layout; the on-chain `buildPortalDepositInputs` (Solidity)
// mirrors it index-for-index so the contract's verify call lines up with the proof.
//
// CRITICAL — the layout is NOT free to choose: gnark serializes a circuit's public
// witness in struct-field DECLARATION order, emitting each `[]frontend.Variable`
// public slice as a CONTIGUOUS block of its elements. So the only correct vector is
// the one matching DepositPortalPublicInputs field order:
//
//	[ chainId, pool,
//	  knownRoots[0..15], packedTreeNumbers,
//	  activeTree, countOld, rootNew, countNew, rollover,
//	  nRequests,
//	  portalAddresses[0..maxSlots-1],   // E
//	  counters[0..maxSlots-1],
//	  recipientBindHs[0..maxSlots-1],       // H, read on-chain from E's portalBinding()
//	  tokenIds[0..maxSlots-1],
//	  amounts[0..maxSlots-1],           // net credited (gross - fee)
//	  commitmentsOut[0..maxSlots-1] ]
//
// The per-slot fields are GROUPED-by-array (all E's, then all counters, ...), the
// same shape the normal deposit's on-chain buildDepositInputs uses (four maxSlots
// loops, LibPublicInputs.sol) — NOT interleaved {E, counter, H, ...} per
// slot. The design's prose `{per slot: E, counter, H, ...}` describes the logical
// per-deposit tuple; the wire order is array-grouped because that is what gnark's
// public-witness serialization produces. TestBuildPortalDepositInputs_MatchesCircuitWitness
// pins this to the ground truth (the materialized public witness) so the two can
// never silently diverge.
//
// recipientMPK / blind are witness-only and therefore deliberately absent from this
// vector (recipient hiding).
type PortalDepositPublicInputs struct {
	ChainID                    *big.Int   // chain id (layout slot 0; not circuit-constrained — see struct doc)
	PoolAddress                *big.Int   // pool address (layout slot 1; not circuit-constrained)
	NoteKnownRoots             []*big.Int // [maxNoteRoots] historical note-tree roots
	NoteKnownTreeNumbersPacked *big.Int   // packed tree numbers (15 bits each)
	ActiveNoteTreeNumber       *big.Int   // index of the active output tree within NoteKnownRoots
	CountOld                   *big.Int   // old leaf count of the active tree
	RootNew                    *big.Int   // root after appending all active commitments
	CountNew                   *big.Int   // new leaf count after appends
	Rollover                   *big.Int   // 0/1 rollover flag
	NRequests                  *big.Int   // number of active portal deposits (1..maxSlots)

	// Per-deposit arrays, each already padded to maxSlots (trailing slots zero).
	PortalAddresses []*big.Int // E
	Counters        []*big.Int // per-portal sweep counter
	RecipientBindHs []*big.Int // H
	TokenIDs        []*big.Int // token id
	Amounts         []*big.Int // net credited amount
	CommitmentsOut  []*big.Int // appended note leaf
}

// BuildPortalDepositInputs lays out the public-input vector for portal-deposit
// verification. `maxNoteRoots` and `maxSlots` fix the expected slice lengths; every
// slice in `in` must already be padded to those lengths (the circuit rejects
// non-zero padding, so the contract pads the same way). It returns an error rather
// than panicking on a length mismatch so a caller building inputs from a malformed
// record fails loudly instead of producing a misaligned vector the verifier would
// silently reject.
func BuildPortalDepositInputs(in PortalDepositPublicInputs, maxNoteRoots, maxSlots int) ([]*big.Int, error) {
	// Validate slice lengths up front: a short/long slice would shift every
	// downstream index and misalign the whole vector against the proof.
	if len(in.NoteKnownRoots) != maxNoteRoots {
		return nil, fmt.Errorf("NoteKnownRoots length %d != maxNoteRoots %d", len(in.NoteKnownRoots), maxNoteRoots)
	}
	for _, f := range []struct {
		name string
		s    []*big.Int
	}{
		{"PortalAddresses", in.PortalAddresses},
		{"Counters", in.Counters},
		{"RecipientBindHs", in.RecipientBindHs},
		{"TokenIDs", in.TokenIDs},
		{"Amounts", in.Amounts},
		{"CommitmentsOut", in.CommitmentsOut},
	} {
		if len(f.s) != maxSlots {
			return nil, fmt.Errorf("%s length %d != maxSlots %d", f.name, len(f.s), maxSlots)
		}
	}

	// Pre-size the vector so appends never reallocate: 2 (chainId/pool) +
	// maxNoteRoots + 1 (packedTreeNumbers) + 6 scalar tree-state/count fields +
	// 6 per-deposit arrays of maxSlots. The +9 mirrors the contract's `+ 10`
	// for the normal deposit minus the dropped nTotalCommitments field.
	out := make([]*big.Int, 0, 2+maxNoteRoots+1+6+maxSlots*6)

	// Scalar prefix — same order and positions as the deposit epoch's
	// buildDepositInputs (chainId/pool at 0/1, then packed roots, then the
	// scalar tree-state block) so the shared note tree's CAS lines up.
	out = append(out, in.ChainID, in.PoolAddress)
	out = append(out, in.NoteKnownRoots...)
	out = append(out,
		in.NoteKnownTreeNumbersPacked,
		in.ActiveNoteTreeNumber,
		in.CountOld,
		in.RootNew,
		in.CountNew,
		in.Rollover,
		in.NRequests,
	)

	// Per-deposit tail — array-grouped (all E, then all counters, ...), matching
	// gnark's contiguous serialization of each public slice. The portal tail drops
	// the deposit path's nTotalCommitments + requestId/commitmentCount arrays (one
	// note per portal deposit) and carries the portal-specific fields instead.
	out = append(out, in.PortalAddresses...)
	out = append(out, in.Counters...)
	out = append(out, in.RecipientBindHs...)
	out = append(out, in.TokenIDs...)
	out = append(out, in.Amounts...)
	out = append(out, in.CommitmentsOut...)

	return out, nil
}
