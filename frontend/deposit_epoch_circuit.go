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
// - `commitmentActive[i] := (i < Pub.NAppends)` and inactive commitment slots are zero padded.
//
// What this circuit does NOT prove:
//   - It does not prove that `NoteKnownRoots` corresponds to the contract's root history; the contract verifies that.
//   - It does not prove uniqueness of commitments across batches; uniqueness/deduplication is handled elsewhere.
//   - It does not enforce any offchain semantics about "who is allowed to deposit"; it only binds the witness to the
//     provided public request ids and tree transition.
//
// Witness author notes:
// - Arrays are fixed-size. Only the first `Pub.NRequests` / `Pub.NAppends` entries are active; all others MUST be zero.
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
	// Requests and commitments intentionally share one capacity in this witness schema.
	// Splitting them changes the public vector and requires a separately versioned circuit.
}

// DepositEpochPublicInputs is the deposit circuit's public vector, in verifier order.
// Field order is shared with LibPublicInputs.buildDepositInputs in Solidity. Reordering
// fields changes the verifier's public vector and requires new proving keys.
// Exported field spelling is frozen for witness-builder compatibility. New identifiers use Go initialisms.
type DepositEpochPublicInputs struct {
	// Digest domain separation.
	ChainId     frontend.Variable `gnark:",public"` // chain id included in request id digest
	PoolAddress frontend.Variable `gnark:",public"` // pool address included in request id digest

	// The shared append relation, including its own NAppends leaf count. NAppends is the
	// number of commitments this batch writes, so it is the commitment-side activity prefix.
	NoteAppend

	// Batch sizing that is specific to deposits, because only this circuit fans a single
	// request out into several commitments.
	NRequests frontend.Variable `gnark:",public"` // number of active requests (1..MaxSlots)

	// Per-request arrays (active first, then zero padded).
	DepositRequestIds []frontend.Variable `gnark:",public"` // [MaxSlots] request ids for active requests; zero for inactive
	TotalAmounts      []frontend.Variable `gnark:",public"` // [MaxSlots] total amounts for active requests; zero for inactive
	CommitmentCounts  []frontend.Variable `gnark:",public"` // [MaxSlots] commitment count per request; zero for inactive

	// Per-commitment array (active first, then zero padded).
	CommitmentsOut []frontend.Variable `gnark:",public"` // [MaxSlots] commitments for active slots; zero for inactive
}

// Exported field spelling is frozen for witness-builder compatibility. New identifiers use Go initialisms.
type DepositEpochPrivateInputs struct {
	// Per-request witness (active first, then zero padded).
	Depositors     []frontend.Variable // [MaxSlots] depositor addresses (for request id digest)
	TokenAddresses []frontend.Variable // [MaxSlots] token address per request (for request id digest)
	Nonces         []frontend.Variable // [MaxSlots] nonce per request (for request id digest)

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
	noteAppendState        // evolving output-tree state and the commitment-side activity selector
	requestActive   []Bool // requestActive[r] := (r < NRequests)
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
			NoteAppend:        NoteAppend{NoteKnownRoots: make([]frontend.Variable, maxNoteRootsPerProof)},
			DepositRequestIds: make([]frontend.Variable, maxSlots),
			TotalAmounts:      make([]frontend.Variable, maxSlots),
			CommitmentCounts:  make([]frontend.Variable, maxSlots),
			CommitmentsOut:    make([]frontend.Variable, maxSlots),
		},
		Priv: DepositEpochPrivateInputs{
			Depositors:      make([]frontend.Variable, maxSlots),
			TokenAddresses:  make([]frontend.Variable, maxSlots),
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

	// Process all commitments in a single pass.
	c.processCommitments(api, &state)

	// Append every active commitment into the output tree in one batch.
	c.Pub.applyBatchAppend(api, c.Shape.MerkleDepth, c.Pub.CommitmentsOut, &state.noteAppendState)

	// Bind the final tree state to public outputs.
	c.Pub.assertFinalState(api, c.Shape.MerkleDepth, state.noteAppendState)

	return nil
}

// =============================================================================
// Validation helpers
// =============================================================================

// validateInputs is this circuit's single validation entry point: it bounds every input the
// circuit later hashes or sums, and returns the selectors the processing helpers consume.
// The shared append relation validates its own public tree inputs and builds the
// commitment-side selector; everything added here is deposit-specific.
func (c *DepositEpochCircuit) validateInputs(api frontend.API) depositInternalState {
	appendState := c.Pub.validateAndInitTreeState(api, c.Shape.MaxSlots, c.Shape.MerkleDepth, c.Priv.NoteFrontierOld)

	// 1 <= NRequests <= MaxSlots. NAppends carries the same bound inside the append relation.
	AssertIsNonZero(api, c.Pub.NRequests)
	AssertIsLessOrEqual(api, c.Pub.NRequests, uint64(c.Shape.MaxSlots), CountBits)

	// Request and commitment slots are allocated to the same capacity, so one pass applies both
	// sets of checks. The two gates stay separate because a single request can carry several
	// commitments, which makes the two active prefixes differ.
	requestActive := make([]Bool, c.Shape.MaxSlots)
	for i := 0; i < c.Shape.MaxSlots; i++ {
		requestActive[i] = isGreaterThanConst(api, c.Pub.NRequests, uint64(i), CountBits)
		requestInactive := Not(api, requestActive[i])
		commitmentInactive := Not(api, appendState.commitmentActive[i])

		// Request preimages must fit their on-chain address and nonce encodings.
		AssertIsNBits(api, c.Priv.TokenAddresses[i], AddressBits)
		AssertIsNonZeroIf(api, requestActive[i], c.Priv.TokenAddresses[i])
		AssertIsNBits(api, c.Priv.Depositors[i], AddressBits)
		AssertIsNBits(api, c.Priv.Nonces[i], DepositNonceBits)

		// Canonical zero padding for inactive request slots.
		AssertIsZeroIf(api, requestInactive, c.Pub.DepositRequestIds[i])
		AssertIsZeroIf(api, requestInactive, c.Pub.TotalAmounts[i])
		AssertIsZeroIf(api, requestInactive, c.Priv.Depositors[i])
		AssertIsZeroIf(api, requestInactive, c.Priv.TokenAddresses[i])
		AssertIsZeroIf(api, requestInactive, c.Priv.Nonces[i])

		// Per-recipient output values, range-checked so the running sums cannot overflow.
		AssertIsNBits(api, c.Priv.OutputValues[i], AmountBits)

		// Canonical zero padding for inactive commitment slots.
		AssertIsZeroIf(api, commitmentInactive, c.Pub.CommitmentsOut[i])
		AssertIsZeroIf(api, commitmentInactive, c.Priv.OutputNPKs[i])
		AssertIsZeroIf(api, commitmentInactive, c.Priv.OutputValues[i])

		// Active commitments must carry value, so a zero-value leaf cannot consume tree capacity.
		AssertIsNonZeroIf(api, appendState.commitmentActive[i], c.Priv.OutputValues[i])
	}

	return depositInternalState{noteAppendState: appendState, requestActive: requestActive}
}

// assertTotalCommitmentCount enforces that the request headers are structurally consistent:
// - active requests have CommitmentCounts[r] >= 1,
// - inactive requests are zero padded,
// - sum(CommitmentCounts for active requests) == NAppends.
func (c *DepositEpochCircuit) assertTotalCommitmentCount(api frontend.API, state depositInternalState) {
	// CommitmentCounts has active-first semantics. Active requests must have CommitmentCounts[r] >= 1; inactive must be 0.
	totalCommitmentsFromRequests := frontend.Variable(0)
	for r := 0; r < c.Shape.MaxSlots; r++ {
		requestActive := state.requestActive[r]

		// Active requests must have at least 1 commitment; inactive requests must be 0.
		AssertIsNBits(api, c.Pub.CommitmentCounts[r], CountBits)
		AssertIsNonZeroIf(api, requestActive, c.Pub.CommitmentCounts[r])
		AssertIsZeroIf(api, Not(api, requestActive), c.Pub.CommitmentCounts[r])

		// Accumulate the total across active requests only.
		totalCommitmentsFromRequests = AddIf(api, requestActive, totalCommitmentsFromRequests, c.Pub.CommitmentCounts[r])
	}
	AssertEqual(api, totalCommitmentsFromRequests, c.Pub.NAppends)
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

		// A deposit key is chosen by the depositor and never derived in-circuit, so an unchecked
		// slot could mint a note that no spend relation will ever open. Inactive slots are already
		// pinned to zero by validateInputs, which is inside the reserved range, so the gate
		// is required here.
		AssertSpendableNPKIf(api, commitmentActive, c.Priv.OutputNPKs[i])

		// TokenAddress is per-request, so we look it up by the requestIndex.
		tokenAddress := SelectByIndex(api, c.Priv.TokenAddresses, requestIndex)

		// Compute and bind the commitment for this slot (gated by commitmentActive).
		expectedCommitment := Poseidon2T4(api, domainNoteCommitmentV2, c.Priv.OutputNPKs[i], tokenAddress, c.Priv.OutputValues[i])
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

		// computedRequestId = Hash(domainDepositRequestV2, ChainId, PoolAddress,
		// Depositor, TokenAddress, ExpectedTotal, Nonce, RequestCommitmentsHash)
		computedRequestId := Poseidon2T4(
			api,
			domainDepositRequestV2,
			c.Pub.ChainId,
			c.Pub.PoolAddress,
			depositor,
			tokenAddress,
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
