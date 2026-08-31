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
// DepositEpochCircuit
// =============================================================================
//
// This circuit proves a batch of deposit requests that append note commitments into an active
// note commitment tree.
//
// What this circuit enforces (high level):
//   - **Request totals**: for each request, the public total equals the sum of its private per-recipient values.
//   - **Commitment correctness**: each active output commitment matches the hashed note fields.
//   - **Tree update**: all active commitments are appended to the active tree (with optional rollover)
//     and the resulting `(RootNew, CountNew)` matches public outputs.
//   - **Request id binding**: each request's public id matches the computed digest over its public/private fields.
//
// Multi-tree support:
// - `Pub.NoteKnownRoots` provides roots of historical deposit trees (size `Shape.MaxNoteRootsPerProof`).
// - `Pub.ActiveNoteTreeNumber` selects which root is the active output tree.
// - All commitments in this batch are appended to the active tree.
//
// Rollover semantics:
// - `Pub.Rollover = 0`: start from `(Pub.CountOld, Priv.NoteFrontierOld)` and require frontier matches the selected root.
// - `Pub.Rollover = 1`: require `Pub.CountOld == 2^Shape.MerkleDepth` and start appending from an empty tree state.
//
// Readability invariants used throughout:
// - `requestActive[r] := (r < Pub.NRequests)` and inactive request slots are zero padded.
// - `commitmentActive[i] := (i < Pub.NTotalCommitments)` and inactive commitment slots are zero padded.
//
// What this circuit does NOT prove:
//   - It does not prove that `NoteKnownRoots` corresponds to the contract's root history; the contract verifies that.
//   - It does not prove uniqueness of commitments across batches; uniqueness/deduplication is handled elsewhere.
//   - It does not enforce any offchain semantics about "who is allowed to deposit"; it only binds the witness to the
//     provided public request ids and tree transition.
//
// Witness author notes:
// - Arrays are fixed-size. Only the first `Pub.NRequests` / `Pub.NTotalCommitments` entries are active; all others MUST be zero.
// - `CommitmentsOut` must be sorted by request: commitments for request 0 first, then request 1, etc.
// - `CommitmentCounts[r]` is the number of commitments for request r and must be non-zero for active requests.
type DepositEpochCircuit struct {
	// Shape holds fixed sizing parameters (compile-time circuit shape, not constrained).
	Shape DepositEpochShape

	// Public inputs are verified by the verifier/contract.
	Pub DepositEpochPublicInputs

	// Private inputs are provided by the prover as witness-only values.
	Priv DepositEpochPrivateInputs
}

// DepositEpochShape defines fixed sizing parameters for this circuit instance.
// These values affect circuit allocation/structure but do not add constraints by themselves.
type DepositEpochShape struct {
	MaxSlots             int // shared maximum for both request slots and commitment slots
	MerkleDepth          int // depth of note commitment trees (leaf capacity = 2^MerkleDepth)
	MaxNoteRootsPerProof int // number of note roots provided in a proof
	// TODO(refactor): disambiguate MaxSlots into MaxRequests and MaxCommitments.
}

type DepositEpochPublicInputs struct {
	// Tree state.
	ChainId                    frontend.Variable   `gnark:",public"` // chain id included in request id digest
	PoolAddress                frontend.Variable   `gnark:",public"` // pool address included in request id digest
	NoteKnownRoots             []frontend.Variable `gnark:",public"` // [MaxNoteRootsPerProof] historical note commitment tree roots
	NoteKnownTreeNumbersPacked frontend.Variable   `gnark:",public"` // packed tree numbers (15 bits each)
	ActiveNoteTreeNumber       frontend.Variable   `gnark:",public"` // selects which NoteKnownRoots is the active output tree
	CountOld                   frontend.Variable   `gnark:",public"` // old leaf count in the active output tree
	RootNew                    frontend.Variable   `gnark:",public"` // root after appending all active commitments
	CountNew                   frontend.Variable   `gnark:",public"` // new leaf count after appends
	Rollover                   frontend.Variable   `gnark:",public"` // 0/1 rollover flag for the active tree

	// Batch sizing.
	NRequests         frontend.Variable `gnark:",public"` // number of active requests (1..MaxSlots)
	NTotalCommitments frontend.Variable `gnark:",public"` // number of active commitments (1..MaxSlots)

	// Per-request arrays (active first, then zero padded).
	DepositRequestIds []frontend.Variable `gnark:",public"` // [MaxSlots] request ids for active requests; zero for inactive
	TotalAmounts      []frontend.Variable `gnark:",public"` // [MaxSlots] total amounts for active requests; zero for inactive
	CommitmentCounts  []frontend.Variable `gnark:",public"` // [MaxSlots] commitment count per request; zero for inactive

	// Per-commitment array (active first, then zero padded).
	CommitmentsOut []frontend.Variable `gnark:",public"` // [MaxSlots] commitments for active slots; zero for inactive
}

type DepositEpochPrivateInputs struct {
	// Per-request witness (active first, then zero padded).
	Depositors []frontend.Variable // [MaxSlots] depositor addresses (for request id digest)
	TokenIDs   []frontend.Variable // [MaxSlots] token id per request (for request id digest)
	Nonces     []frontend.Variable // [MaxSlots] nonce per request (for request id digest)

	// Per-commitment witness (active first, then zero padded).
	OutputNPKs   []frontend.Variable // [MaxSlots] recipient NPKs for commitments (witness only)
	OutputValues []frontend.Variable // [MaxSlots] per-recipient values for commitments (witness only)

	// Active tree witness (before appending).
	NoteFrontierOld []frontend.Variable // [MerkleDepth] frontier for the active output tree
}

// depositInternalState carries cached selectors and the evolving output tree state used while
// constructing constraints in `Define`.
//
// This is not a structure for input witnesses; it groups intermediate variables (selectors and
// evolving Merkle state) derived while building constraints.
type depositInternalState struct {
	currentCount     frontend.Variable   // evolving leaf count for the active output tree
	currentFrontier  []frontend.Variable // evolving frontier for the active output tree
	fullTreeRoot     frontend.Variable   // root of the full tree, set by applyBatchAppend; read only when currentCount == 2^depth
	requestActive    []Bool              // requestActive[r] := (r < NRequests)
	commitmentActive []Bool              // commitmentActive[i] := (i < NTotalCommitments)
}

// =============================================================================
// Constructor
// =============================================================================

// NewDepositEpochCircuit allocates a sized circuit instance (all slices are allocated to fixed sizes).
//
// Notes:
//   - These sizing parameters define the circuit shape at compile time.
//   - They do not add constraints by themselves, but they determine how many constraints exist once
//     `Define` is executed (more slots/depth => larger circuit).
func NewDepositEpochCircuit(maxSlots, merkleDepth, maxNoteRootsPerProof int) *DepositEpochCircuit {
	c := &DepositEpochCircuit{
		Shape: DepositEpochShape{
			MaxSlots:             maxSlots,
			MerkleDepth:          merkleDepth,
			MaxNoteRootsPerProof: maxNoteRootsPerProof,
		},
		Pub: DepositEpochPublicInputs{
			NoteKnownRoots:    make([]frontend.Variable, maxNoteRootsPerProof),
			DepositRequestIds: make([]frontend.Variable, maxSlots),
			TotalAmounts:      make([]frontend.Variable, maxSlots),
			CommitmentCounts:  make([]frontend.Variable, maxSlots),
			CommitmentsOut:    make([]frontend.Variable, maxSlots),
		},
		Priv: DepositEpochPrivateInputs{
			Depositors:      make([]frontend.Variable, maxSlots),
			TokenIDs:        make([]frontend.Variable, maxSlots),
			Nonces:          make([]frontend.Variable, maxSlots),
			OutputNPKs:      make([]frontend.Variable, maxSlots),
			OutputValues:    make([]frontend.Variable, maxSlots),
			NoteFrontierOld: make([]frontend.Variable, merkleDepth),
		},
	}
	return c
}

// =============================================================================
// Define
// =============================================================================

// Define builds the constraint system for the deposit batch.
func (c *DepositEpochCircuit) Define(api frontend.API) error {
	// Build all sizing-dependent selectors and perform basic range/bounds validation.
	state := c.validateInputs(api)

	// Enforce structural integrity of request sizing.
	c.assertTotalCommitmentCount(api, state)

	// Range-check all per-recipient output values (prevents overflow in running sums).
	for i := 0; i < c.Shape.MaxSlots; i++ {
		AssertIsNBits(api, c.Priv.OutputValues[i], AmountBits)
	}

	// Process all commitments in a single pass.
	c.processCommitments(api, &state)

	// Append every active commitment into the output tree in one batch.
	c.applyBatchAppend(api, &state)

	// Bind the final tree state to public outputs.
	c.assertFinalState(api, state)

	return nil
}

// =============================================================================
// Validation helpers
// =============================================================================

// validateInputs performs basic range/bounds checks and builds cached selectors used by later helpers.
func (c *DepositEpochCircuit) validateInputs(api frontend.API) depositInternalState {
	currentCount, currentFrontier := c.validatePublicInputsAndInitTreeState(api)

	// Cache selectors used throughout the circuit.
	requestActive := make([]Bool, c.Shape.MaxSlots)
	commitmentActive := make([]Bool, c.Shape.MaxSlots)
	for i := 0; i < c.Shape.MaxSlots; i++ {
		requestActive[i] = isGreaterThanConst(api, c.Pub.NRequests, uint64(i), CountBits)
		commitmentActive[i] = isGreaterThanConst(api, c.Pub.NTotalCommitments, uint64(i), CountBits)
	}

	return depositInternalState{
		currentCount:     currentCount,
		currentFrontier:  currentFrontier,
		requestActive:    requestActive,
		commitmentActive: commitmentActive,
	}
}

// validatePublicInputsAndInitTreeState enforces public bounds, rollover semantics, and binds the provided
// `NoteFrontierOld` witness to the selected active tree root (when not rolling over).
func (c *DepositEpochCircuit) validatePublicInputsAndInitTreeState(api frontend.API) (currentCount frontend.Variable, currentFrontier []frontend.Variable) {
	// Range-check and bound-check public tree inputs.
	AssertIsNBits(api, c.Pub.CountOld, CountBits)
	AssertIsNBits(api, c.Pub.CountNew, CountBits)

	// 1 <= NRequests <= MaxSlots
	AssertIsNonZero(api, c.Pub.NRequests)
	AssertIsLessOrEqual(api, c.Pub.NRequests, uint64(c.Shape.MaxSlots), CountBits)

	// 1 <= NTotalCommitments <= MaxSlots
	AssertIsNonZero(api, c.Pub.NTotalCommitments)
	AssertIsLessOrEqual(api, c.Pub.NTotalCommitments, uint64(c.Shape.MaxSlots), CountBits)

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

// assertTotalCommitmentCount enforces that the request headers are structurally consistent:
// - active requests have CommitmentCounts[r] >= 1,
// - inactive requests are zero padded,
// - sum(CommitmentCounts for active requests) == NTotalCommitments.
func (c *DepositEpochCircuit) assertTotalCommitmentCount(api frontend.API, state depositInternalState) {
	// CommitmentCounts has active-first semantics. Active requests must have CommitmentCounts[r] >= 1; inactive must be 0.
	totalCommitmentsFromRequests := frontend.Variable(0)
	for r := 0; r < c.Shape.MaxSlots; r++ {
		requestActive := state.requestActive[r]
		requestInactive := Not(api, requestActive)

		// Active requests must have at least 1 commitment; inactive requests must be 0.
		AssertIsNBits(api, c.Pub.CommitmentCounts[r], CountBits)
		AssertIsNonZeroIf(api, requestActive, c.Pub.CommitmentCounts[r])
		AssertIsZeroIf(api, Not(api, requestActive), c.Pub.CommitmentCounts[r])

		// Zero padding for inactive request slots.
		AssertIsZeroIf(api, requestInactive, c.Pub.DepositRequestIds[r])
		AssertIsZeroIf(api, requestInactive, c.Pub.TotalAmounts[r])
		AssertIsZeroIf(api, requestInactive, c.Priv.Depositors[r])
		AssertIsZeroIf(api, requestInactive, c.Priv.TokenIDs[r])
		AssertIsZeroIf(api, requestInactive, c.Priv.Nonces[r])

		// Accumulate the total across active requests only.
		totalCommitmentsFromRequests = AddIf(api, requestActive, totalCommitmentsFromRequests, c.Pub.CommitmentCounts[r])
	}
	AssertEqual(api, totalCommitmentsFromRequests, c.Pub.NTotalCommitments)
}

// =============================================================================
// Core processing
// =============================================================================

// processCommitments processes commitments in a single outer loop over MaxSlots.
func (c *DepositEpochCircuit) processCommitments(api frontend.API, state *depositInternalState) {
	// Running state for the current request (all are circuit variables).
	// `requestIndex` must be a circuit variable because it indexes per-request arrays via SelectByIndex.
	requestIndex := frontend.Variable(0)
	requestValueSum := frontend.Variable(0)
	requestCommitmentsHash := frontend.Variable(0)
	requestCommitmentIndex := frontend.Variable(0)

	for i := 0; i < c.Shape.MaxSlots; i++ {
		commitmentActive := state.commitmentActive[i]
		commitmentInactive := Not(api, commitmentActive)

		// Zero padding for inactive commitment slots.
		AssertIsZeroIf(api, commitmentInactive, c.Pub.CommitmentsOut[i])
		AssertIsZeroIf(api, commitmentInactive, c.Priv.OutputNPKs[i])
		AssertIsZeroIf(api, commitmentInactive, c.Priv.OutputValues[i])

		// Enforce positive values for active commitments (prevents zero-value leaves consuming tree capacity).
		AssertIsNonZeroIf(api, commitmentActive, c.Priv.OutputValues[i])

		// A deposit key is chosen by the depositor and never derived in-circuit, so an unchecked
		// slot could mint a note that no spend relation will ever open. Inactive slots are already
		// pinned to zero above, which is inside the reserved range, so the gate is required here.
		AssertSpendableNPKIf(api, commitmentActive, c.Priv.OutputNPKs[i])

		// TokenID is per-request, so we look it up by the requestIndex.
		tokenId := SelectByIndex(api, c.Priv.TokenIDs, requestIndex)

		// Compute and bind the commitment for this slot (gated by commitmentActive).
		expectedCommitment := Poseidon2T4(api, domainNote, c.Priv.OutputNPKs[i], tokenId, c.Priv.OutputValues[i])
		AssertEqualIf(api, commitmentActive, expectedCommitment, c.Pub.CommitmentsOut[i])
		AssertIsNonZeroIf(api, commitmentActive, c.Pub.CommitmentsOut[i])

		// Accumulate per-request sum (only for active commitments).
		requestValueSum = AddIf(api, commitmentActive, requestValueSum, c.Priv.OutputValues[i])

		// Update commitmentsHash as a sequential Poseidon chain.
		newHash := Poseidon2T4(api, requestCommitmentsHash, c.Pub.CommitmentsOut[i])
		requestCommitmentsHash = Select(api, commitmentActive, newHash, requestCommitmentsHash)

		// Increment the commitment counter within the current request.
		requestCommitmentIndex = AddIf(api, commitmentActive, requestCommitmentIndex, 1)

		// Finalize the request when we've consumed its expected number of commitments.
		requestExpectedCommitmentCount := SelectByIndex(api, c.Pub.CommitmentCounts, requestIndex)
		requestCompleted := IsEqual(api, requestCommitmentIndex, requestExpectedCommitmentCount)
		shouldFinalizeRequest := And(api, commitmentActive, requestCompleted)

		// Finalization checks (gated): sum and request id.
		expectedTotal := SelectByIndex(api, c.Pub.TotalAmounts, requestIndex)
		AssertEqualIf(api, shouldFinalizeRequest, requestValueSum, expectedTotal)

		expectedRequestId := SelectByIndex(api, c.Pub.DepositRequestIds, requestIndex)
		depositor := SelectByIndex(api, c.Priv.Depositors, requestIndex)
		nonce := SelectByIndex(api, c.Priv.Nonces, requestIndex)
		// computedRequestId = Hash(domainDepositRequest, ChainId, PoolAddress, Depositor, TokenID, ExpectedTotal, Nonce, RequestCommitmentsHash)
		computedRequestId := Poseidon2T4(
			api,
			domainDepositRequest,
			c.Pub.ChainId,
			c.Pub.PoolAddress,
			depositor,
			tokenId,
			expectedTotal,
			nonce,
			requestCommitmentsHash,
		)
		AssertEqualIf(api, shouldFinalizeRequest, computedRequestId, expectedRequestId)

		// Reset running state and advance request index when finalizing.
		requestIndex = AddIf(api, shouldFinalizeRequest, requestIndex, 1)
		requestValueSum = Select(api, shouldFinalizeRequest, 0, requestValueSum)
		requestCommitmentsHash = Select(api, shouldFinalizeRequest, 0, requestCommitmentsHash)
		requestCommitmentIndex = Select(api, shouldFinalizeRequest, 0, requestCommitmentIndex)

	}

	// All requests must be finalized by the end.
	AssertEqual(api, requestIndex, c.Pub.NRequests)
}

// applyBatchAppend appends every active commitment into the output tree in one batch.
//
// commitmentActive[i] := (i < NTotalCommitments), so the live commitments already occupy a
// prefix of the slot array and no routing is needed — a single packed block goes straight
// into the batched append. That costs ~MaxSlots + MerkleDepth Poseidon permutations where
// appending one leaf at a time cost ~MaxSlots * MerkleDepth.
func (c *DepositEpochCircuit) applyBatchAppend(api frontend.API, state *depositInternalState) {
	batch := newPrefixPackedList(api, c.Pub.CommitmentsOut, state.commitmentActive)

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
func (c *DepositEpochCircuit) assertFinalState(api frontend.API, state depositInternalState) {
	// When tree is full, computeRootFromFrontier returns incorrect result (handled internally),
	// so we use fullTreeRoot from the batch append's final carry instead.
	maxCount := uint64(1) << c.Shape.MerkleDepth
	isFull := IsEqual(api, state.currentCount, maxCount)

	computedRoot := computeRootFromFrontier(api, state.currentFrontier, state.currentCount, c.Shape.MerkleDepth)
	rootNew := api.Select(isFull.AsField(), state.fullTreeRoot, computedRoot)

	AssertEqual(api, rootNew, c.Pub.RootNew)
	AssertEqual(api, state.currentCount, c.Pub.CountNew)
}
