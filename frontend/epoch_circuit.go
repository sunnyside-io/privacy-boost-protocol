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
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// =============================================================================
// EpochCircuit
// =============================================================================
//
// This circuit proves the validity of an "epoch" batch of private note transfers and
// withdrawals, updating a Poseidon-based Merkle tree of note commitments.
//
// What this circuit enforces (high level):
// - **Auth**: each active slot uses exactly one auth-registry membership path: either a registered
//   EdDSA key plus signature, or a Safe spend-approval leaf bound to the same digest.
// - **Spend**: each active input note exists in a selected historical commitment tree (Merkle
//   membership proof) and produces a public nullifier derived from a secret nullifying key.
// - **Output**: each active slot outputs a commitment consistent with the private output note.
// - **Fees**: per-slot fees are verified via conservation (outputValue = inputValue - fee) and
//   accumulated per fee-token id; fee commitments are emitted and appended to the output tree.
//   Fee calculation is done off-chain; the circuit only enforces the balance equation.
// - **Tree update**: outputs and fee notes are appended to the active tree (with optional
//   rollover) and the resulting `(RootNew, CountNew)` matches public outputs.
//
// Multi-tree support:
// - `Pub.NoteKnownRoots` provides roots of historical commitment trees (size `Shape.MaxNoteRootsPerProof`).
// - Each transfer input selects which tree it spends from via `Priv.InputNoteTreeNumber[t]`.
// - Outputs (including fee outputs) are appended to the current active tree.
//
// Rollover semantics:
// - `Pub.Rollover = 0`: start from `(CountOld, NoteFrontierOld)`.
// - `Pub.Rollover = 1`: require `CountOld == 2^NoteDepth` and start appending from an empty
//   tree state (count = 0, frontier = all-zero).
//
// Readability invariants used throughout:
// - `transferActive[t] := (t < Pub.NTransfers)` where `Pub.NTransfers` is in `[1, Shape.MaxTransfers]`.
// - `feeActive[j] := (j < Pub.FeeTokenCount)` where `Pub.FeeTokenCount` is in `[1, Shape.MaxFeeTokens]`.
// - Constraints for inactive slots are gated by `transferActive[t]` / `feeActive[j]`.
//
// What this circuit does NOT prove:
// - It does not "interpret" auth leaf fields (expiry/flags) beyond hashing them into the auth
//   registry leaf and proving membership. Semantics must be enforced by the contract/offchain logic
//   that defines what an auth leaf means.
// - It does not prove uniqueness of nullifiers across transfers within the circuit; uniqueness is
//   enforced on-chain by checking a nullifier mapping.
// - It does not prove that a given (NoteKnownRoots/AuthKnownRoots) array is consistent with the
//   contract's root histories/snapshots; the contract enforces that separately before verifying
//   the proof.
//
// Witness author notes:
// - Inactive slots MUST still provide well-formed witnesses (correct length arrays), but their
//   constraints are gated by `transferActive[t]` / `feeActive[j]`.
// - Merkle paths must match the tree hash convention (see `computeRoot` / `computeDomainRoot`).

// =============================================================================
// Types
// =============================================================================
type EpochCircuit struct {
	// Shape holds fixed sizing parameters (compile-time circuit shape, not constrained).
	Shape EpochShape

	// Public inputs are verified by the verifier/contract.
	Pub EpochPublicInputs

	// Private inputs are provided by the prover as witness-only values.
	Priv EpochPrivateInputs
}

// EpochShape defines fixed sizing parameters for this circuit instance.
// These values affect circuit allocation/structure but do not add constraints by themselves.
type EpochShape struct {
	MaxTransfers          int // number of transfer slots in the circuit instance
	MaxInputsPerTransfer  int // maximum inputs per single transfer
	MaxOutputsPerTransfer int // maximum outputs per single transfer
	MaxFeeTokens          int // maximum distinct fee token ids supported
	NoteDepth             int // depth of note commitment trees (leaf capacity = 2^NoteDepth)
	AuthDepth             int // depth of auth registry trees
	MaxNoteRootsPerProof  int // number of note roots provided in a proof
	MaxAuthRootsPerProof  int // number of auth roots provided in a proof
}

type EpochPublicInputs struct {
	// Commitment tree roots (multi-tree input support).
	NoteKnownRoots             []frontend.Variable `gnark:",public"` // [MaxNoteRootsPerProof] historical note commitment tree roots
	NoteKnownTreeNumbersPacked frontend.Variable   `gnark:",public"` // packed tree numbers (15 bits each)
	ProvingTimestamp           frontend.Variable   `gnark:",public"` // timestamp used for auth expiry checks
	ActiveNoteTreeNumber       frontend.Variable   `gnark:",public"` // selects which NoteKnownRoots is the active output tree
	ActiveNoteTreeRoot         frontend.Variable   `gnark:",public"` // current root of the active tree (for frontier binding)

	// Packed counts for tree state transitions.
	CountsPacked frontend.Variable `gnark:",public"` // CountOld|(CountNew<<32)|(Rollover<<64)|(NTransfers<<96)|(FeeTokenCount<<128)
	RootNew      frontend.Variable `gnark:",public"` // root after appending transfer outputs and fee outputs

	// Auth registry roots.
	AuthKnownRoots             []frontend.Variable `gnark:",public"` // [MaxAuthRootsPerProof] auth registry roots (snapshotted)
	AuthKnownTreeNumbersPacked frontend.Variable   `gnark:",public"` // packed auth tree numbers (15 bits each)

	// Per-transfer outputs.
	Nullifiers      [][]frontend.Variable `gnark:",public"` // [MaxTransfers][MaxInputsPerTransfer] nullifiers for active input notes
	CommitmentsOut  [][]frontend.Variable `gnark:",public"` // [MaxTransfers][MaxOutputsPerTransfer] output commitments for active transfers
	ApproveDigestHi []frontend.Variable   `gnark:",public"` // [MaxTransfers] one digest per transfer
	ApproveDigestLo []frontend.Variable   `gnark:",public"` // [MaxTransfers] one digest per transfer

	// Fee public outputs.
	FeeNPK              frontend.Variable   `gnark:",public"` // fee recipient's Note Public Key
	FeeCommitmentsOut   []frontend.Variable `gnark:",public"` // [MaxFeeTokens] fee note commitments
	FeeTransferDigestHi frontend.Variable   `gnark:",public"` // high 128 bits of the fee-transfer metadata digest
	FeeTransferDigestLo frontend.Variable   `gnark:",public"` // low 128 bits of the fee-transfer metadata digest

	// WithdrawalMaskPacked marks which transfer slots pay out publicly, one bit per slot packed
	// WithdrawalMaskBitsPerWord to a field element, least-significant bit first. The contract packs
	// it from the withdrawalSlots array it has already validated, so the circuit can treat it as
	// authoritative. Declared last so adding it leaves every existing public-input index in place.
	WithdrawalMaskPacked []frontend.Variable `gnark:",public"` // [EpochWithdrawalMaskWords(MaxTransfers)]
}

type EpochPrivateInputs struct {
	// Per-transfer input/output counts.
	InputsPerTransfer  []frontend.Variable // [MaxTransfers] how many inputs for transfer t
	OutputsPerTransfer []frontend.Variable // [MaxTransfers] how many outputs for transfer t

	// Per-transfer auth/signature witness.
	AuthTreeNumber   []frontend.Variable // [MaxTransfers] which auth tree contains the auth key (15-bit global id)
	SpenderAccountId []frontend.Variable // [MaxTransfers] used for MPK derivation and auth leaf hashing
	TransferTokenID  []frontend.Variable // [MaxTransfers] slot token id; all input/output token ids must match it
	NullifyingKey    []frontend.Variable // [MaxTransfers] secret; used for MPK and nullifier derivation

	AuthPkX            []frontend.Variable   // [MaxTransfers] auth pubkey X
	AuthPkY            []frontend.Variable   // [MaxTransfers] auth pubkey Y
	AuthSigR8x         []frontend.Variable   // [MaxTransfers] signature R8.x
	AuthSigR8y         []frontend.Variable   // [MaxTransfers] signature R8.y
	AuthSigS           []frontend.Variable   // [MaxTransfers] signature scalar S
	UseApproval        []frontend.Variable   // [MaxTransfers] bool: consume approval leaf instead of auth key leaf
	Blinding           []frontend.Variable   // [MaxTransfers] Safe approval commitment blinding
	DisplayBindingSalt []frontend.Variable   // [MaxTransfers] salt binding blinding to account/token/fee/sender MPK
	BatchIndex         []frontend.Variable   // [MaxTransfers] slot of the consumed commitment inside its approval batch
	BatchSiblings      [][]frontend.Variable // [MaxTransfers][SpendApprovalBatchDepth] approval batch sub-tree siblings

	// Per-transfer auth registry membership proof.
	AuthExpiry       []frontend.Variable   // [MaxTransfers] expiry used in leaf hash
	AuthLeafIndex    []frontend.Variable   // [MaxTransfers] leaf index in auth tree
	AuthPathElements [][]frontend.Variable // [MaxTransfers][AuthDepth] Merkle path elements for auth proof

	// Per-transfer fee witness.
	FeePerTransfer []frontend.Variable // [MaxTransfers] fee amount (token-denominated)

	// Per-transfer input note witness.
	InputNoteTreeNumber [][]frontend.Variable   // [MaxTransfers][MaxInputsPerTransfer] which tree each input spends from
	InputValue          [][]frontend.Variable   // [MaxTransfers][MaxInputsPerTransfer]
	InputNoteRnd        [][]frontend.Variable   // [MaxTransfers][MaxInputsPerTransfer] randomness used for input NPK
	InputNoteLeafIndex  [][]frontend.Variable   // [MaxTransfers][MaxInputsPerTransfer] leaf index in the selected input note tree
	InputNotePath       [][][]frontend.Variable // [MaxTransfers][MaxInputsPerTransfer][NoteDepth] Merkle path elements

	// Per-transfer output note witness.
	OutputNPK   [][]frontend.Variable // [MaxTransfers][MaxOutputsPerTransfer] recipient NPK (pre-computed)
	OutputValue [][]frontend.Variable // [MaxTransfers][MaxOutputsPerTransfer]

	// Active output tree witness (before appending).
	NoteFrontierOld []frontend.Variable // [NoteDepth] frontier witness for active output tree

	// Fee outputs witness.
	FeeTokenID []frontend.Variable // [MaxFeeTokens] fee token ids (active first, then zero)
	FeeValue   []frontend.Variable // [MaxFeeTokens] total fee per token (active first, then zero)
}

// =============================================================================
// Constructor
// =============================================================================

// NewEpochCircuit allocates a sized circuit instance (all slices are allocated to fixed sizes).
//
// Notes:
//   - These sizing parameters define the circuit *shape* at compile time.
//   - They do not directly add constraints, but they determine how many constraints will exist
//     once `Define` is executed (e.g., more slots/greater depth => larger circuit).
func NewEpochCircuit(maxTransfers, maxInputsPerTransfer, maxOutputsPerTransfer, noteDepth, authDepth, maxFeeTokens, maxNoteRootsPerProof, maxAuthRootsPerProof int) *EpochCircuit {
	// Allocate 2D arrays for public inputs.
	nullifiers := make([][]frontend.Variable, maxTransfers)
	commitmentsOut := make([][]frontend.Variable, maxTransfers)
	for t := 0; t < maxTransfers; t++ {
		nullifiers[t] = make([]frontend.Variable, maxInputsPerTransfer)
		commitmentsOut[t] = make([]frontend.Variable, maxOutputsPerTransfer)
	}

	// Allocate 2D/3D arrays for private inputs.
	inputNoteTreeNumber := make([][]frontend.Variable, maxTransfers)
	inputValue := make([][]frontend.Variable, maxTransfers)
	inputNoteRnd := make([][]frontend.Variable, maxTransfers)
	inputNoteLeafIndex := make([][]frontend.Variable, maxTransfers)
	inputNotePath := make([][][]frontend.Variable, maxTransfers)
	outputNPK := make([][]frontend.Variable, maxTransfers)
	outputValue := make([][]frontend.Variable, maxTransfers)

	for t := 0; t < maxTransfers; t++ {
		inputNoteTreeNumber[t] = make([]frontend.Variable, maxInputsPerTransfer)
		inputValue[t] = make([]frontend.Variable, maxInputsPerTransfer)
		inputNoteRnd[t] = make([]frontend.Variable, maxInputsPerTransfer)
		inputNoteLeafIndex[t] = make([]frontend.Variable, maxInputsPerTransfer)
		inputNotePath[t] = make([][]frontend.Variable, maxInputsPerTransfer)
		for i := 0; i < maxInputsPerTransfer; i++ {
			inputNotePath[t][i] = make([]frontend.Variable, noteDepth)
		}
		outputNPK[t] = make([]frontend.Variable, maxOutputsPerTransfer)
		outputValue[t] = make([]frontend.Variable, maxOutputsPerTransfer)
	}

	// Allocate fixed-size slices for all inputs and outputs.
	c := &EpochCircuit{
		Shape: EpochShape{
			MaxTransfers:          maxTransfers,
			MaxInputsPerTransfer:  maxInputsPerTransfer,
			MaxOutputsPerTransfer: maxOutputsPerTransfer,
			MaxFeeTokens:          maxFeeTokens,
			NoteDepth:             noteDepth,
			AuthDepth:             authDepth,
			MaxNoteRootsPerProof:  maxNoteRootsPerProof,
			MaxAuthRootsPerProof:  maxAuthRootsPerProof,
		},
		Pub: EpochPublicInputs{
			NoteKnownRoots:       make([]frontend.Variable, maxNoteRootsPerProof),
			AuthKnownRoots:       make([]frontend.Variable, maxAuthRootsPerProof),
			Nullifiers:           nullifiers,
			CommitmentsOut:       commitmentsOut,
			FeeCommitmentsOut:    make([]frontend.Variable, maxFeeTokens),
			FeeTransferDigestHi:  big.NewInt(0),
			FeeTransferDigestLo:  big.NewInt(0),
			ApproveDigestHi:      make([]frontend.Variable, maxTransfers),
			ApproveDigestLo:      make([]frontend.Variable, maxTransfers),
			WithdrawalMaskPacked: newZeroedMaskWords(EpochWithdrawalMaskWords(maxTransfers)),
		},
		Priv: EpochPrivateInputs{
			InputsPerTransfer:   make([]frontend.Variable, maxTransfers),
			OutputsPerTransfer:  make([]frontend.Variable, maxTransfers),
			AuthTreeNumber:      make([]frontend.Variable, maxTransfers),
			SpenderAccountId:    make([]frontend.Variable, maxTransfers),
			TransferTokenID:     make([]frontend.Variable, maxTransfers),
			NullifyingKey:       make([]frontend.Variable, maxTransfers),
			AuthPkX:             make([]frontend.Variable, maxTransfers),
			AuthPkY:             make([]frontend.Variable, maxTransfers),
			AuthSigR8x:          make([]frontend.Variable, maxTransfers),
			AuthSigR8y:          make([]frontend.Variable, maxTransfers),
			AuthSigS:            make([]frontend.Variable, maxTransfers),
			UseApproval:         make([]frontend.Variable, maxTransfers),
			Blinding:            make([]frontend.Variable, maxTransfers),
			DisplayBindingSalt:  make([]frontend.Variable, maxTransfers),
			BatchIndex:          make([]frontend.Variable, maxTransfers),
			BatchSiblings:       make([][]frontend.Variable, maxTransfers),
			AuthExpiry:          make([]frontend.Variable, maxTransfers),
			AuthLeafIndex:       make([]frontend.Variable, maxTransfers),
			AuthPathElements:    make([][]frontend.Variable, maxTransfers),
			FeePerTransfer:      make([]frontend.Variable, maxTransfers),
			InputNoteTreeNumber: inputNoteTreeNumber,
			InputValue:          inputValue,
			InputNoteRnd:        inputNoteRnd,
			InputNoteLeafIndex:  inputNoteLeafIndex,
			InputNotePath:       inputNotePath,
			OutputNPK:           outputNPK,
			OutputValue:         outputValue,
			NoteFrontierOld:     make([]frontend.Variable, noteDepth),
			FeeTokenID:          make([]frontend.Variable, maxFeeTokens),
			FeeValue:            make([]frontend.Variable, maxFeeTokens),
		},
	}

	// Allocate per-transfer auth Merkle paths and approval batch paths.
	for t := 0; t < maxTransfers; t++ {
		c.Priv.AuthPathElements[t] = make([]frontend.Variable, authDepth)
		c.Priv.BatchSiblings[t] = make([]frontend.Variable, SpendApprovalBatchDepth)
	}
	return c
}

// newZeroedMaskWords allocates the withdrawal-mask words pre-set to zero, the same way the fee
// digest limbs are. Compilation replaces these values with wires, so the only thing the zeroing
// affects is witness building: an assignment that never touches the mask describes a batch with no
// withdrawals rather than failing to serialize.
func newZeroedMaskWords(n int) []frontend.Variable {
	words := make([]frontend.Variable, n)
	for i := range words {
		words[i] = big.NewInt(0)
	}
	return words
}

// epochInternalState carries cached selectors and the evolving output tree state used while
// constructing constraints in `Define`.
//
// This is not a structure for input witnesses; it groups intermediate variables (selectors and
// evolving Merkle state) derived while building constraints.
type epochInternalState struct {
	currentCount    frontend.Variable   // leaf count for the active output tree before appends
	currentFrontier []frontend.Variable // frontier for the active output tree before appends
	fullTreeRoot    frontend.Variable   // root of the full tree, set by applyBatchAppend; read only when currentCount == 2^depth
	feeActive       []Bool              // feeActive[j] := (j < FeeTokenCount)
	transferActive  []Bool              // transferActive[t] := (t < NTransfers)
	isWithdrawal    []Bool              // isWithdrawal[t] := bit t of the public withdrawal mask
	provingTimeBits []frontend.Variable // little-endian bits of Pub.ProvingTimestamp

	// pendingLeaves collects the commitments to append, in tree order: one packed block per
	// transfer slot (its active outputs), then one for the active fee commitments. They are
	// appended in a single batch by `applyBatchAppend` rather than one leaf at a time.
	pendingLeaves []packedList

	// Unpacked count values from CountsPacked.
	countOld      frontend.Variable // leaf count before this epoch
	countNew      frontend.Variable // expected leaf count after this epoch
	rollover      Bool              // true if starting a new tree (previous tree was full)
	nTransfers    frontend.Variable // number of active transfer slots (1..MaxTransfers)
	feeTokenCount frontend.Variable // number of active fee token buckets (1..MaxFeeTokens)
}

// =============================================================================
// Define
// =============================================================================
func (c *EpochCircuit) Define(api frontend.API) error {
	// Build all sizing-dependent selectors and perform basic range/bounds validation.
	state := c.validateInputs(api)

	// Accumulate per-token fees across all active transfers.
	feeSums := make([]frontend.Variable, c.Shape.MaxFeeTokens)
	for j := 0; j < c.Shape.MaxFeeTokens; j++ {
		feeSums[j] = 0
	}

	// Verify authorization signature and registry membership for each active transfer slot.
	c.verifyAuth(api, state)
	// Apply per-transfer constraints and collect transfer outputs for the tree append.
	// Also enforces canonical NoteKnownRoots coverage based on input membership usage.
	c.processTransfers(api, &state, feeSums)
	// Emit fee commitments and collect them for the tree append.
	c.processFeeCommitments(api, &state, feeSums)
	// Append every collected commitment to the output tree in one batch.
	c.applyBatchAppend(api, &state)
	// Bind the final tree state to public outputs.
	c.assertFinalState(api, state)

	return nil
}

// =============================================================================
// Validation and cached selectors
// =============================================================================

// validateInputs performs basic range/bounds checks and builds cached selectors used by later
// passes. It should stay "validation-only": i.e. no signature checks, no Merkle membership
// checks, and no core spend/output constraints.
func (c *EpochCircuit) validateInputs(api frontend.API) epochInternalState {
	// Validate inputs and initialize the working output tree state.
	currentCount, currentFrontier, countOld, countNew, nTransfers, feeTokenCount, rollover, provingTimeBits :=
		c.validatePublicInputsAndInitTreeState(api)

	// Validate the fee token bucket structure and derive feeActive selectors.
	feeActive := c.validateFeeTokenInputs(api, feeTokenCount)

	// Derive transferActive selectors and validate per-transfer bounds.
	transferActive := c.computeTransferActiveFlags(api, nTransfers)
	c.validatePerTransferInputs(api, transferActive)

	// Decode the public withdrawal mask into per-slot selectors.
	isWithdrawal := c.decodeWithdrawalMask(api, transferActive)

	// Range-check fee output values (active/inactive semantics are enforced later).
	c.validateFeeOutputValues(api)

	return epochInternalState{
		currentCount:    currentCount,
		currentFrontier: currentFrontier,
		feeActive:       feeActive,
		transferActive:  transferActive,
		isWithdrawal:    isWithdrawal,
		provingTimeBits: provingTimeBits,
		countOld:        countOld,
		countNew:        countNew,
		rollover:        rollover,
		nTransfers:      nTransfers,
		feeTokenCount:   feeTokenCount,
	}
}

// validatePublicInputsAndInitTreeState validates public inputs that define the initial and final
// tree state, and returns the working `(count, frontier)` state to be used for appends.
//
// This is where rollover semantics are enforced and where `NoteFrontierOld` is checked against the
// selected active tree root (when not rolling over).
func (c *EpochCircuit) validatePublicInputsAndInitTreeState(api frontend.API) (
	currentCount frontend.Variable,
	currentFrontier []frontend.Variable,
	countOld, countNew, nTransfers, feeTokenCount frontend.Variable,
	rollover Bool,
	provingTimeBits []frontend.Variable,
) {
	// Unpack counts from packed field.
	// Layout: CountOld | (CountNew << 32) | (Rollover << 64) | (NTransfers << 96) | (FeeTokenCount << 128)
	counts := unpackSlots(api, c.Pub.CountsPacked, CountsPackedSlots, CountsPackedBitsPerSlot)
	countOld = counts[0]
	countNew = counts[1]
	rolloverField := counts[2]
	nTransfers = counts[3]
	feeTokenCount = counts[4]

	// Range checks are implicit from unpackSlots (32-bit decomposition).
	// But we still need semantic validation.

	// Enforce 1 <= FeeTokenCount <= MaxFeeTokens.
	AssertIsNonZero(api, feeTokenCount)
	AssertIsLessOrEqual(api, feeTokenCount, uint64(c.Shape.MaxFeeTokens), CountBits)

	// Enforce 1 <= NTransfers <= MaxTransfers.
	AssertIsLessOrEqual(api, nTransfers, uint64(c.Shape.MaxTransfers), CountBits)
	AssertIsNonZero(api, nTransfers)

	// Enforce ActiveNoteTreeNumber is within [0, MaxNoteTreeNumber].
	AssertIsLess(api, c.Pub.ActiveNoteTreeNumber, uint64(MaxNoteTreeNumber)+1, NoteTreeNumberBits+1)

	provingTimeBits = api.ToBinary(c.Pub.ProvingTimestamp, TimestampBits)
	AssertIsNBits(api, c.Pub.FeeTransferDigestHi, DigestHalfBits)
	AssertIsNBits(api, c.Pub.FeeTransferDigestLo, DigestHalfBits)

	// Enforce tree counts are within [0, 2^NoteDepth].
	maxNoteLeaves := uint64(1) << c.Shape.NoteDepth
	AssertIsLessOrEqual(api, countOld, maxNoteLeaves, CountBits)
	AssertIsLessOrEqual(api, countNew, maxNoteLeaves, CountBits)

	// Enforce rollover semantics for the starting tree state.
	rollover = AsBool(rolloverField)
	AssertIsBool(api, rollover)
	notRollover := Not(api, rollover)
	// If not rolling over, the active tree must not be full.
	AssertIsLessIf(api, notRollover, countOld, maxNoteLeaves, CountBits)
	// If rolling over, the active tree must be full.
	AssertEqualIfU64(api, rollover, countOld, maxNoteLeaves)

	// Bind the provided frontier witness to the active tree root (when not rolling over).
	// ActiveNoteTreeRoot is the current on-chain root, independent of NoteKnownRoots
	// which may contain past roots for input spending.
	rootFromFrontier := computeRootFromFrontier(api, c.Priv.NoteFrontierOld, countOld, c.Shape.NoteDepth)
	AssertEqualIf(api, notRollover, rootFromFrontier, c.Pub.ActiveNoteTreeRoot)

	// Initialize the working tree state for subsequent appends.
	// Rollover starts from an empty state; otherwise from the old state. `Select` keeps append constraints uniform.
	currentCount = Select(api, rollover, 0, countOld)
	currentFrontier = make([]frontend.Variable, c.Shape.NoteDepth)
	for i := 0; i < c.Shape.NoteDepth; i++ {
		currentFrontier[i] = Select(api, rollover, 0, c.Priv.NoteFrontierOld[i])
	}
	return currentCount, currentFrontier, countOld, countNew, nTransfers, feeTokenCount, rollover, provingTimeBits
}

// validateFeeTokenInputs validates the fee token id list:
// - The first `feeTokenCount` entries are active, non-zero, and pairwise distinct.
// - The remaining entries are zero.
// It returns `feeActive[j] := (j < feeTokenCount)` selectors used for gating later constraints.
func (c *EpochCircuit) validateFeeTokenInputs(api frontend.API, feeTokenCount frontend.Variable) []Bool {
	// Determine which fee slots are active and enforce FeeTokenID semantics for each slot.
	feeActive := make([]Bool, c.Shape.MaxFeeTokens)
	for j := 0; j < c.Shape.MaxFeeTokens; j++ {
		feeSlotActive := isGreaterThanConst(api, feeTokenCount, uint64(j), CountBits)
		feeActive[j] = feeSlotActive

		// Active fee slots must have non-zero token ids; inactive slots must be zero.
		AssertIsNBits(api, c.Priv.FeeTokenID[j], TokenIDBits)
		AssertIsNonZeroIf(api, feeSlotActive, c.Priv.FeeTokenID[j])
		AssertIsZeroIf(api, Not(api, feeSlotActive), c.Priv.FeeTokenID[j])
	}

	// Active fee token ids must be pairwise distinct.
	for j := 0; j < c.Shape.MaxFeeTokens; j++ {
		for k := j + 1; k < c.Shape.MaxFeeTokens; k++ {
			bothActive := And(api, feeActive[j], feeActive[k])
			AssertIsDifferentIf(api, bothActive, c.Priv.FeeTokenID[j], c.Priv.FeeTokenID[k])
		}
	}

	return feeActive
}

// computeTransferActiveFlags returns `transferActive[t] := (t < nTransfers)` selectors.
func (c *EpochCircuit) computeTransferActiveFlags(api frontend.API, nTransfers frontend.Variable) []Bool {
	transferActive := make([]Bool, c.Shape.MaxTransfers)

	// Build selectors once and reuse them across all passes to avoid recomputation.
	for t := 0; t < c.Shape.MaxTransfers; t++ {
		transferActive[t] = isGreaterThanConst(api, nTransfers, uint64(t), CountBits)
	}
	return transferActive
}

// decodeWithdrawalMask unpacks the public withdrawal mask into one selector per transfer slot.
//
// Two shapes are enforced here so the mask cannot be used to hide a leaf: bits past the circuit's
// transfer capacity must be zero, and a bit may only be set on an active slot. Everything else the
// mask asserts about the batch (that a marked slot really carries a marker in output zero, and
// that the marked slots match the withdrawals being paid) is the contract's job, which is why the
// mask is a public input rather than a witness.
func (c *EpochCircuit) decodeWithdrawalMask(api frontend.API, transferActive []Bool) []Bool {
	// The packed mask must reach every transfer slot. NewEpochCircuit sizes it with
	// EpochWithdrawalMaskWords, so a short array means the struct was assembled some other way, and
	// the loop below would leave the uncovered slots reading as ordinary transfers instead of
	// failing. Every production shape fits in one word today, which is precisely why nothing else
	// would notice the day MaxTransfers passes WithdrawalMaskBitsPerWord.
	if len(c.Pub.WithdrawalMaskPacked)*WithdrawalMaskBitsPerWord < c.Shape.MaxTransfers {
		panic("decodeWithdrawalMask: WithdrawalMaskPacked does not cover MaxTransfers slots")
	}

	isWithdrawal := make([]Bool, c.Shape.MaxTransfers)
	for w := range c.Pub.WithdrawalMaskPacked {
		// Decompose only the slots this word actually carries. ToBinary below the field width
		// constrains the value under 2^width through its own recomposition, so bounding the width
		// rejects a word with bits set past the circuit's transfer capacity by construction.
		width := WithdrawalMaskBitsPerWord
		if remaining := c.Shape.MaxTransfers - w*WithdrawalMaskBitsPerWord; remaining < width {
			width = remaining
		}
		bits := api.ToBinary(c.Pub.WithdrawalMaskPacked[w], width)
		for b := 0; b < width; b++ {
			slot := w*WithdrawalMaskBitsPerWord + b
			AssertIsZeroIf(api, Not(api, transferActive[slot]), bits[b])
			isWithdrawal[slot] = AsBool(bits[b])
		}
	}
	return isWithdrawal
}

// validatePerTransferInputs performs cheap, per-transfer sanity checks that do not depend on
// hashing/Merkle membership. All constraints are gated by `transferActive[t]`.
func (c *EpochCircuit) validatePerTransferInputs(api frontend.API, transferActive []Bool) {
	for t := 0; t < c.Shape.MaxTransfers; t++ {
		transferActiveT := transferActive[t]

		// Validate InputsPerTransfer and OutputsPerTransfer counts.
		AssertIsLessOrEqualIf(api, transferActiveT, c.Priv.InputsPerTransfer[t], uint64(c.Shape.MaxInputsPerTransfer), CountBits)
		AssertIsLessOrEqualIf(api, transferActiveT, c.Priv.OutputsPerTransfer[t], uint64(c.Shape.MaxOutputsPerTransfer), CountBits)
		AssertIsNonZeroIf(api, transferActiveT, c.Priv.InputsPerTransfer[t])
		AssertIsNonZeroIf(api, transferActiveT, c.Priv.OutputsPerTransfer[t])

		// Validate AuthTreeNumber is within [0, MaxAuthTreeNumber], gated by transferActive.
		AssertIsLessIf(api, transferActiveT, c.Priv.AuthTreeNumber[t], uint64(MaxAuthTreeNumber)+1, AuthTreeNumberBits+1)

		// Range-check per-input note fields.
		for i := 0; i < c.Shape.MaxInputsPerTransfer; i++ {
			AssertIsNBits(api, c.Priv.InputValue[t][i], AmountBits)
			// Validate InputTreeNumber is within [0, MaxNoteTreeNumber].
			inputActive := And(api, transferActiveT, isGreaterThanConst(api, c.Priv.InputsPerTransfer[t], uint64(i), CountBits))
			AssertIsLessIf(api, inputActive, c.Priv.InputNoteTreeNumber[t][i], uint64(MaxNoteTreeNumber)+1, NoteTreeNumberBits+1)
		}

		// Range-check per-output note fields.
		for j := 0; j < c.Shape.MaxOutputsPerTransfer; j++ {
			AssertIsNBits(api, c.Priv.OutputValue[t][j], AmountBits)
		}
	}
}

// validateFeeOutputValues range-checks the fee output values. Semantic checks (active vs inactive)
// are enforced later via `feeActive`.
func (c *EpochCircuit) validateFeeOutputValues(api frontend.API) {
	for j := 0; j < c.Shape.MaxFeeTokens; j++ {
		AssertIsNBits(api, c.Priv.FeeValue[j], AmountBits)
	}
}

// =============================================================================
// Core logic passes
// =============================================================================

// verifyAuth enforces one of two authorization paths for each active transfer slot:
// a registered key leaf plus EdDSA signature, or a Safe approval leaf whose
// batch member commits to the same approval digest.
func (c *EpochCircuit) verifyAuth(api frontend.API, state epochInternalState) {
	for t := 0; t < c.Shape.MaxTransfers; t++ {
		transferActive := state.transferActive[t]

		useApproval := AsBool(c.Priv.UseApproval[t])
		AssertIsBool(api, useApproval)
		approvalActive := And(api, transferActive, useApproval)

		// Bind the owner-visible token, fee, and sender MPK to the same approval
		// secret the circuit consumes. The sender MPK is derived from the actual
		// account witness so an owner-package proposer cannot label an arbitrary
		// recipient as change. Output recipients/amounts are authenticated by the
		// digest-committed ciphertext openings in the owner package.
		senderMPK := Poseidon2T4(
			api,
			domainMPK,
			c.Priv.SpenderAccountId[t],
			c.Priv.NullifyingKey[t],
		)
		displayBlinding := Poseidon2T4(
			api,
			domainApprovalDisplay,
			c.Priv.DisplayBindingSalt[t],
			c.Priv.SpenderAccountId[t],
			c.Priv.AuthExpiry[t],
			c.Priv.TransferTokenID[t],
			c.Priv.FeePerTransfer[t],
			senderMPK,
		)
		AssertEqualIf(api, approvalActive, displayBlinding, c.Priv.Blinding[t])
		AssertIsNonZeroIf(api, approvalActive, c.Priv.DisplayBindingSalt[t])

		// Verify approval signature only for auth-key leaves.
		approveMsg := Poseidon2T4(api, domainApprove, c.Pub.ApproveDigestHi[t], c.Pub.ApproveDigestLo[t])
		pk := AffinePoint{X: c.Priv.AuthPkX[t], Y: c.Priv.AuthPkY[t]}
		sig := EdDSASignature{
			R8: AffinePoint{X: c.Priv.AuthSigR8x[t], Y: c.Priv.AuthSigR8y[t]},
			S:  c.Priv.AuthSigS[t],
		}
		VerifyEdDSAIf(api, And(api, transferActive, Not(api, useApproval)), pk, sig, approveMsg)

		keyLeaf := Poseidon2T4(
			api,
			domainRegLeaf,
			c.Priv.SpenderAccountId[t],
			c.Priv.AuthPkX[t],
			c.Priv.AuthPkY[t],
			c.Priv.AuthExpiry[t],
		)
		commitment := Poseidon2T4(
			api,
			domainApproveCommit,
			c.Pub.ApproveDigestHi[t],
			c.Pub.ApproveDigestLo[t],
			c.Priv.Blinding[t],
		)
		// Walk the fixed-depth approval batch sub-tree from the consumed
		// commitment to the batch root the quorum signed. Path A slots carry
		// dummy batch witnesses; the result is discarded by the select below.
		batchRoot := computeRoot(api, commitment, c.Priv.BatchIndex[t], c.Priv.BatchSiblings[t], SpendApprovalBatchDepth)
		approvalLeaf := Poseidon2T4(
			api,
			domainApprovalLeaf,
			c.Priv.SpenderAccountId[t],
			batchRoot,
			c.Priv.AuthExpiry[t],
		)
		authLeaf := Select(api, useApproval, approvalLeaf, keyLeaf)
		authRoot := computeDomainRoot(api, authLeaf, c.Priv.AuthLeafIndex[t], c.Priv.AuthPathElements[t], c.Shape.AuthDepth, domainRegNode)

		// Prove membership: computed auth root must match a known root AND tree number must match.
		AssertRootWithTreeNumberIf(api, transferActive, authRoot, c.Priv.AuthTreeNumber[t], c.Pub.AuthKnownRoots, c.Pub.AuthKnownTreeNumbersPacked)

		authExpiryBits := api.ToBinary(c.Priv.AuthExpiry[t], TimestampBits)
		useKeyNoExpiry := And(api, Not(api, useApproval), IsEqual(api, c.Priv.AuthExpiry[t], 0))
		notExpired := isLessOrEqualBits(api, state.provingTimeBits, authExpiryBits)
		AssertIsTrueIf(api, transferActive, Or(api, useKeyNoExpiry, notExpired))
		AssertIsNonZeroIf(api, approvalActive, c.Priv.AuthExpiry[t])
	}
}

// processTransfers applies the per-transfer core logic for each slot:
// - N input note membership and nullifier constraints,
// - M output commitment constraints,
// - fee conservation (sum(inputs) = sum(outputs) + fee) and fee accumulation,
// - collect the M output commitments for the batched tree append.
func (c *EpochCircuit) processTransfers(
	api frontend.API,
	state *epochInternalState,
	feeSums []frontend.Variable,
) {
	noteKnownTreeNumbers := unpackSlots(
		api,
		c.Pub.NoteKnownTreeNumbersPacked,
		len(c.Pub.NoteKnownRoots),
		TreeNumberBitsPerSlot,
	)

	// Track which NoteKnownRoots slots are referenced by active input notes.
	slotUsedByInputs := make([]Bool, c.Shape.MaxNoteRootsPerProof)
	for s := 0; s < c.Shape.MaxNoteRootsPerProof; s++ {
		slotUsedByInputs[s] = False()
	}

	// Process each transfer slot. Inactive slots are gated by transferActive[t].
	for t := 0; t < c.Shape.MaxTransfers; t++ {
		transferActive := state.transferActive[t]
		nInputs := c.Priv.InputsPerTransfer[t]
		nOutputs := c.Priv.OutputsPerTransfer[t]

		// Process N inputs: enforce input-note validity, membership, and nullifier.
		inputValueSum := frontend.Variable(0)
		for i := 0; i < c.Shape.MaxInputsPerTransfer; i++ {
			inputActive := And(api, transferActive, isGreaterThanConst(api, nInputs, uint64(i), CountBits))
			c.assertInputNotes(api, inputActive, t, i, noteKnownTreeNumbers, slotUsedByInputs)
			c.assertNullifier(api, inputActive, t, i)
			inputValueSum = api.Add(inputValueSum, api.Mul(inputActive.AsField(), c.Priv.InputValue[t][i]))
		}
		AssertIsNBits(api, inputValueSum, AmountBits)

		// Process M outputs: enforce output commitment and queue it for the tree append.
		outputValueSum := frontend.Variable(0)
		outputActiveFlags := make([]Bool, c.Shape.MaxOutputsPerTransfer)
		for j := 0; j < c.Shape.MaxOutputsPerTransfer; j++ {
			outputActive := And(api, transferActive, isGreaterThanConst(api, nOutputs, uint64(j), CountBits))
			outputActiveFlags[j] = outputActive
			c.assertOutputNotes(api, outputActive, state.isWithdrawal[t], t, j)
			outputValueSum = api.Add(outputValueSum, api.Mul(outputActive.AsField(), c.Priv.OutputValue[t][j]))
		}
		AssertIsNBits(api, outputValueSum, AmountBits)

		// Slot j is active iff j < nOutputs (and the transfer itself is active), so the live
		// outputs of this transfer are already a prefix of the slot array — no reordering
		// needed, only the gaps between transfers have to be closed, which the merge does.
		// A withdrawal slot is the one exception: its output zero is the marker for a public
		// payout, so it is dropped here and the rest of the slot shifts left by one.
		leafValues, leafActive := c.treeLeavesForTransfer(api, state.isWithdrawal[t], t, outputActiveFlags)
		state.pendingLeaves = append(state.pendingLeaves,
			newPrefixPackedList(api, leafValues, leafActive))

		// Enforce conservation: sum(inputs) = sum(outputs) + fee, and accumulate fees.
		c.applyFeeAndAccumulate(api, transferActive, t, inputValueSum, outputValueSum, feeSums)
	}

	// Enforce canonical NoteKnownRoots coverage (every non-zero root must be consumed by an input).
	c.assertNoteKnownRootsCoverage(api, slotUsedByInputs)
}

// processFeeCommitments enforces fee bucket correctness and queues fee commitments for the
// tree append:
// - `FeeValue[j]` must equal the accumulated sum for that token id (when active),
// - the public fee commitment must match the computed commitment (when active),
// - active fee commitments are collected as the last block of leaves to append.
func (c *EpochCircuit) processFeeCommitments(api frontend.API, state *epochInternalState, feeSums []frontend.Variable) {
	// One public key serves every fee bucket, so the reserved range costs one refusal for the whole
	// batch rather than one per slot. The refusal is unconditional because
	// validatePublicInputsAndInitTreeState already requires 1 <= FeeTokenCount, so every satisfying
	// witness mints a fee note and there is no shape for which a gate would legitimately skip it.
	// See the policy block in spendable_npk.go for why this site is refused and the per-output-slot
	// sites are not.
	AssertSpendableNPK(api, c.Pub.FeeNPK)

	for j := 0; j < c.Shape.MaxFeeTokens; j++ {
		// Bind the fee totals to the accumulated per-token sums (active slots) and enforce zero padding (inactive slots).
		AssertEqualIf(api, state.feeActive[j], c.Priv.FeeValue[j], feeSums[j])
		AssertIsZeroIf(api, Not(api, state.feeActive[j]), c.Priv.FeeValue[j])

		// Fee commitment = Hash(domainNote, FeeNPK, FeeTokenID, FeeValue)
		// Compute and bind the fee commitment for this fee bucket (active slots) and enforce zero padding (inactive slots).
		feeCommitment := Poseidon2T4(
			api,
			domainNote,
			c.Pub.FeeNPK,
			c.Priv.FeeTokenID[j],
			c.Priv.FeeValue[j],
		)
		AssertEqualIf(api, state.feeActive[j], feeCommitment, c.Pub.FeeCommitmentsOut[j])
		AssertIsNonZeroIf(api, state.feeActive[j], feeCommitment)
		AssertIsZeroIf(api, Not(api, state.feeActive[j]), c.Pub.FeeCommitmentsOut[j])
	}

	// Fee commitments are appended after every transfer output, so they form the last block.
	// feeActive[j] := (j < FeeTokenCount) is already a prefix.
	state.pendingLeaves = append(state.pendingLeaves,
		newPrefixPackedList(api, c.Pub.FeeCommitmentsOut, state.feeActive))
}

// applyBatchAppend appends every queued commitment into the output tree in a single batch.
//
// The queued blocks are in tree order (transfer outputs by slot, then fee commitments), so
// merging them yields exactly the leaf sequence the per-leaf append path would have produced.
// Doing it in one batch costs ~K+NoteDepth Poseidon permutations instead of ~K*NoteDepth,
// where K is the total number of leaf slots.
func (c *EpochCircuit) applyBatchAppend(api frontend.API, state *epochInternalState) {
	batch := mergePackedLists(api, state.pendingLeaves)

	// currentCount is < 2^NoteDepth here: rollover forces it to 0, and without rollover
	// validatePublicInputsAndInitTreeState already required countOld < 2^NoteDepth.
	// appendFrontierBatch re-checks that, plus that the batch fits in the remaining capacity.
	nextFrontier, nextCount, finalCarry := appendFrontierBatch(
		api,
		state.currentFrontier,
		state.currentCount,
		batch,
		c.Shape.NoteDepth,
	)
	state.currentFrontier = nextFrontier
	state.currentCount = nextCount
	state.fullTreeRoot = finalCarry
}

// assertFinalState binds the internal working tree state to public outputs.
func (c *EpochCircuit) assertFinalState(api frontend.API, state epochInternalState) {
	// When tree is full, computeRootFromFrontier returns incorrect result (handled internally),
	// so we use fullTreeRoot from the batch append's final carry instead.
	maxCount := uint64(1) << c.Shape.NoteDepth
	isFull := IsEqual(api, state.currentCount, maxCount)

	computedRoot := computeRootFromFrontier(api, state.currentFrontier, state.currentCount, c.Shape.NoteDepth)
	rootNew := api.Select(isFull.AsField(), state.fullTreeRoot, computedRoot)

	AssertEqual(api, rootNew, c.Pub.RootNew)
	AssertEqual(api, state.currentCount, state.countNew)
}

// =============================================================================
// Per-transfer helpers
// =============================================================================

// assertNoteKnownRootsCoverage enforces canonical coverage of NoteKnownRoots:
// every non-zero (treeNumber, root) slot must be referenced by at least one active input note
// membership proof.
func (c *EpochCircuit) assertNoteKnownRootsCoverage(
	api frontend.API,
	slotUsedByInputs []Bool,
) {
	for s := 0; s < c.Shape.MaxNoteRootsPerProof; s++ {
		slotActive := isNonZero(api, c.Pub.NoteKnownRoots[s])
		AssertIsTrueIf(api, slotActive, slotUsedByInputs[s])
	}
}

// assertInputNotes enforces that the input note at index [transferIdx][inputIdx] exists in the selected
// commitment tree.
func (c *EpochCircuit) assertInputNotes(
	api frontend.API,
	inputActive Bool,
	transferIdx, inputIdx int,
	noteKnownTreeNumbers []frontend.Variable,
	slotUsedByInputs []Bool,
) {
	AssertIsNonZeroIf(api, inputActive, c.Priv.TransferTokenID[transferIdx])

	// Compute MPK = Hash(domainMPK, SpenderAccountId, NullifyingKey)
	mpk := Poseidon2T4(api, domainMPK, c.Priv.SpenderAccountId[transferIdx], c.Priv.NullifyingKey[transferIdx])
	// InputNPK = Hash(domainNote, MPK, InputNoteRnd)
	inputNPK := Poseidon2T4(api, domainNote, mpk, c.Priv.InputNoteRnd[transferIdx][inputIdx])

	// Refuse the reserved low range. Markers no longer enter new trees, but they are still leaves
	// of every root minted before this change, so the range is what keeps a historical marker
	// unopenable rather than merely absent.
	AssertSpendableNPKIf(api, inputActive, inputNPK)
	// inputCommitment = Hash(domainNote, InputNPK, TokenID, InputValue)
	inputCommitment := Poseidon2T4(
		api,
		domainNote,
		inputNPK,
		c.Priv.TransferTokenID[transferIdx],
		c.Priv.InputValue[transferIdx][inputIdx],
	)
	AssertIsNonZeroIf(api, inputActive, inputCommitment)

	// Prove membership: computed root must match a known root AND tree number must match.
	rootComputed := computeRoot(api, inputCommitment, c.Priv.InputNoteLeafIndex[transferIdx][inputIdx], c.Priv.InputNotePath[transferIdx][inputIdx], c.Shape.NoteDepth)
	AssertRootWithTreeNumberIf(api, inputActive, rootComputed, c.Priv.InputNoteTreeNumber[transferIdx][inputIdx], c.Pub.NoteKnownRoots, c.Pub.NoteKnownTreeNumbersPacked)

	// Track slot usage for canonical NoteKnownRoots coverage.
	// A slot is "used by inputs" if any active input proves membership against the same (treeNumber, root) pair.
	for s := 0; s < c.Shape.MaxNoteRootsPerProof; s++ {
		eqRoot := IsEqual(api, rootComputed, c.Pub.NoteKnownRoots[s])
		eqTree := IsEqual(api, c.Priv.InputNoteTreeNumber[transferIdx][inputIdx], noteKnownTreeNumbers[s])
		pairMatch := And(api, eqRoot, eqTree)
		slotUsedByInputs[s] = Or(api, slotUsedByInputs[s], And(api, inputActive, pairMatch))
	}
}

// assertNullifier enforces that the public nullifier at index [transferIdx][inputIdx] matches the expected
// nullifier for the spent note.
func (c *EpochCircuit) assertNullifier(api frontend.API, inputActive Bool, transferIdx, inputIdx int) {
	combinedDomain := api.Add(domainNullifier, api.Mul(c.Priv.InputNoteTreeNumber[transferIdx][inputIdx], NullifierTreeNumberMultiplier))
	nullifier := Poseidon2T4(api, combinedDomain, c.Priv.NullifyingKey[transferIdx], c.Priv.InputNoteLeafIndex[transferIdx][inputIdx])
	AssertEqualIf(api, inputActive, nullifier, c.Pub.Nullifiers[transferIdx][inputIdx])
	// Zero/non-zero invariant: binds per-transfer input counts between circuit and contract.
	AssertIsNonZeroIf(api, inputActive, c.Pub.Nullifiers[transferIdx][inputIdx])
	AssertIsZeroIf(api, Not(api, inputActive), c.Pub.Nullifiers[transferIdx][inputIdx])
}

// assertOutputNotes enforces that the public output commitment at index [transferIdx][outputIdx] matches the
// expected commitment, and that the key it is built over is spendable.
//
// Output zero of a withdrawal is the one slot exempt from the range, because it is not a note at
// all: it is the public payout marker Poseidon(domainNote, uint160(to), tokenId, amount), whose key
// position holds the recipient address and therefore always sits inside the reserved range by
// construction. treeLeavesForTransfer drops that slot before the tree append, so no reserved-range
// leaf is ever created. Every other output slot is a real note and is refused, which means a
// recipient can no longer be handed a commitment no spend relation will open.
func (c *EpochCircuit) assertOutputNotes(api frontend.API, outputActive, isWithdrawal Bool, transferIdx, outputIdx int) {
	// The marker exemption is a compile-time slot position combined with a witness flag, so for
	// every slot past zero the gate collapses to outputActive and costs nothing extra.
	npkChecked := outputActive
	if outputIdx == 0 {
		npkChecked = And(api, outputActive, Not(api, isWithdrawal))
	}
	AssertSpendableNPKIf(api, npkChecked, c.Priv.OutputNPK[transferIdx][outputIdx])

	// Compute and bind the public output commitment.
	outputCommitment := Poseidon2T4(
		api,
		domainNote,
		c.Priv.OutputNPK[transferIdx][outputIdx],
		c.Priv.TransferTokenID[transferIdx],
		c.Priv.OutputValue[transferIdx][outputIdx],
	)
	AssertEqualIf(api, outputActive, outputCommitment, c.Pub.CommitmentsOut[transferIdx][outputIdx])
	AssertIsNonZeroIf(api, outputActive, outputCommitment)
	// Zero-padding invariant: binds per-transfer output counts between circuit and contract.
	AssertIsZeroIf(api, Not(api, outputActive), c.Pub.CommitmentsOut[transferIdx][outputIdx])
}

// treeLeavesForTransfer returns the commitments of one transfer slot in tree order, together with
// their liveness flags.
//
// For an ordinary transfer this is the slot unchanged. For a withdrawal the marker in output zero
// is removed and every later output shifts down one slot, which keeps the change note's position
// relative to the other appends and shortens the block by exactly one leaf. Both outputs stay
// bound and summed by the caller either way, so removing the marker changes what the tree holds,
// not what the batch is allowed to move.
//
// Shifting a prefix left by one leaves a prefix, so the caller's cheap prefix packing still
// applies. An exact withdrawal (one output, no change) yields an empty block, which the packing
// and merge handle as a zero-length list.
func (c *EpochCircuit) treeLeavesForTransfer(
	api frontend.API,
	isWithdrawal Bool,
	transferIdx int,
	outputActive []Bool,
) ([]frontend.Variable, []Bool) {
	values := make([]frontend.Variable, c.Shape.MaxOutputsPerTransfer)
	active := make([]Bool, c.Shape.MaxOutputsPerTransfer)
	for j := 0; j < c.Shape.MaxOutputsPerTransfer; j++ {
		// The last slot has nothing to shift into it, so a withdrawal empties it.
		shiftedValue := frontend.Variable(0)
		shiftedActive := frontend.Variable(0)
		if j+1 < c.Shape.MaxOutputsPerTransfer {
			shiftedValue = c.Pub.CommitmentsOut[transferIdx][j+1]
			shiftedActive = outputActive[j+1].AsField()
		}
		values[j] = Select(api, isWithdrawal, shiftedValue, c.Pub.CommitmentsOut[transferIdx][j])
		active[j] = AsBool(Select(api, isWithdrawal, shiftedActive, outputActive[j].AsField()))
	}
	return values, active
}

// applyFeeAndAccumulate enforces fee conservation: sum(inputs) = sum(outputs) + fee.
// Also accumulates fees into per-token buckets.
func (c *EpochCircuit) applyFeeAndAccumulate(
	api frontend.API,
	transferActive Bool,
	transferIdx int,
	inputValueSum, outputValueSum frontend.Variable,
	feeSums []frontend.Variable,
) {
	fee := c.Priv.FeePerTransfer[transferIdx]
	AssertIsNBits(api, fee, AmountBits)

	// Enforce conservation: sum(inputs) = sum(outputs) + fee.
	expectedInput := api.Add(outputValueSum, fee)
	AssertIsNBits(api, expectedInput, AmountBits)
	AssertEqualIf(api, transferActive, inputValueSum, expectedInput)

	// Route this transfer's fee into exactly one fee-token bucket.
	matchCount := frontend.Variable(0)
	for j := 0; j < c.Shape.MaxFeeTokens; j++ {
		match := IsEqual(api, c.Priv.TransferTokenID[transferIdx], c.Priv.FeeTokenID[j])
		matchCount = api.Add(matchCount, match.AsField())

		// Accumulate fee into the matching bucket.
		enabled := And(api, transferActive, match)
		feeSums[j] = api.Add(feeSums[j], api.Mul(enabled.AsField(), fee))
	}

	// Active transfers must match exactly one bucket.
	AssertIsTrueIf(api, transferActive, IsEqual(api, matchCount, 1))
}
