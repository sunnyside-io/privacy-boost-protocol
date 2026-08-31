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
// ForcedWithdrawCircuit
// =============================================================================
//
// This circuit proves a manual exit ("forced withdrawal") that spends up to MaxInputs input notes.
//
// What this circuit enforces (high level):
//   - **Auth**: a single EdDSA signature or dedicated size-1 Safe approval authorizes the digest, and
//     the resulting auth leaf equals the live leaf supplied by the pool as a public input.
//   - **Spend**: each active input note exists in a selected historical commitment tree (Merkle
//     membership proof), matches a public `InputCommitments[i]`, and produces a public nullifier.
//   - **Withdrawal binding**: the withdrawal token id matches the transfer token id, and the withdrawal
//     amount equals the sum of active input values.
//
// Multi-tree support:
// - `Pub.NoteKnownRoots` provides roots of historical commitment trees (size `Shape.MaxNoteRootsPerProof`).
// - Each input selects which tree it spends from via `Priv.InputNoteTreeNumber[i]`.
//
// Readability invariants used throughout:
// - `inputActive[i] := (i < Pub.NIn)` and inactive input slots are zero padded.
//
// What this circuit does NOT prove:
//   - It does not prove auth Merkle membership. Forced withdrawal deliberately exposes an auth locator;
//     PrivacyBoost reads that exact AuthRegistry leaf once, when accepting the request.
//   - It does not prove uniqueness of nullifiers; uniqueness is enforced on-chain.
//   - It does not prove that NoteKnownRoots correspond to contract history; the contract verifies that.
//
// Witness author notes:
// - Arrays are fixed-size. Only the first `NIn` entries are active; all others MUST be zero.
// - Merkle paths must match the tree hash convention (see `computeRoot` / `computeDomainRoot`).
type ForcedWithdrawCircuit struct {
	// Shape holds fixed sizing parameters (compile-time circuit shape, not constrained).
	Shape ForcedWithdrawShape

	// Public inputs are verified by the verifier/contract.
	Pub ForcedWithdrawPublicInputs

	// Private inputs are provided by the prover as witness-only values.
	Priv ForcedWithdrawPrivateInputs
}

// ForcedWithdrawShape defines fixed sizing parameters for this circuit instance.
// These values affect circuit allocation/structure but do not add constraints by themselves.
type ForcedWithdrawShape struct {
	MaxInputs            int // maximum number of input notes
	MerkleDepth          int // depth of note commitment trees (leaf capacity = 2^MerkleDepth)
	MaxNoteRootsPerProof int // number of note roots provided in a proof
}

type ForcedWithdrawPublicInputs struct {
	// Note tree roots (multi-tree input support).
	NoteKnownRoots             []frontend.Variable `gnark:",public"` // [MaxNoteRootsPerProof] historical note commitment tree roots
	NoteKnownTreeNumbersPacked frontend.Variable   `gnark:",public"` // packed tree numbers (15 bits each)

	NIn              frontend.Variable   `gnark:",public"` // number of active inputs (1..MaxInputs)
	SpenderAccountId frontend.Variable   `gnark:",public"` // account id for owner lookup on-chain
	Nullifiers       []frontend.Variable `gnark:",public"` // [MaxInputs] nullifiers for active inputs; zero padded
	InputCommitments []frontend.Variable `gnark:",public"` // [MaxInputs] input commitments for active inputs; zero padded

	ApproveDigestHi frontend.Variable `gnark:",public"` // approval digest part (high)
	ApproveDigestLo frontend.Variable `gnark:",public"` // approval digest part (low)

	WithdrawalTo      frontend.Variable `gnark:",public"` // withdrawal recipient (contract-defined encoding)
	WithdrawalTokenID frontend.Variable `gnark:",public"` // token id of the withdrawal
	WithdrawalAmount  frontend.Variable `gnark:",public"` // gross amount (total input value; fee deducted by contract)
	AuthLeaf          frontend.Variable `gnark:",public"` // live AuthRegistry leaf read by PrivacyBoost
	AuthContext       frontend.Variable `gnark:",public"` // packed expiry/mode/leaf-index/tree/version context
}

type ForcedWithdrawPrivateInputs struct {
	InputNoteTreeNumber []frontend.Variable // [MaxInputs] which note tree each input spends from (15-bit global id)

	TransferTokenID frontend.Variable // token id expected for all inputs
	NullifyingKey   frontend.Variable // secret; used for MPK and nullifier derivation

	AuthPkX    frontend.Variable // auth pubkey X
	AuthPkY    frontend.Variable // auth pubkey Y
	AuthSigR8x frontend.Variable // signature R8.x
	AuthSigR8y frontend.Variable // signature R8.y
	AuthSigS   frontend.Variable // signature scalar S
	Blinding   frontend.Variable // Safe approval commitment blinding

	InputTokenID       []frontend.Variable   // [MaxInputs] token id for each input note
	InputValue         []frontend.Variable   // [MaxInputs] value for each input note
	InputNoteRnd       []frontend.Variable   // [MaxInputs] randomness used for input NPK
	InputNoteLeafIndex []frontend.Variable   // [MaxInputs] leaf index in the selected input tree
	InputNotePath      [][]frontend.Variable // [MaxInputs][MerkleDepth] Merkle path elements for input membership
}

type forcedWithdrawInternalState struct {
	inputActive []Bool // inputActive[i] := (i < Pub.NIn)
}

// =============================================================================
// Constructor
// =============================================================================
//
// NewForcedWithdrawCircuit allocates a sized circuit instance (all slices are allocated to fixed sizes).
//
// Notes:
//   - These sizing parameters define the circuit shape at compile time.
//   - They do not add constraints by themselves, but they determine how many constraints exist once
//     `Define` is executed (more inputs/depth => larger circuit).
func NewForcedWithdrawCircuit(maxInputs, merkleDepth, _ int, maxNoteRootsPerProof, _ int) *ForcedWithdrawCircuit {
	c := &ForcedWithdrawCircuit{
		Shape: ForcedWithdrawShape{
			MaxInputs:            maxInputs,
			MerkleDepth:          merkleDepth,
			MaxNoteRootsPerProof: maxNoteRootsPerProof,
		},
		Pub: ForcedWithdrawPublicInputs{
			NoteKnownRoots:   make([]frontend.Variable, maxNoteRootsPerProof),
			Nullifiers:       make([]frontend.Variable, maxInputs),
			InputCommitments: make([]frontend.Variable, maxInputs),
		},
		Priv: ForcedWithdrawPrivateInputs{
			InputNoteTreeNumber: make([]frontend.Variable, maxInputs),
			InputTokenID:        make([]frontend.Variable, maxInputs),
			InputValue:          make([]frontend.Variable, maxInputs),
			InputNoteRnd:        make([]frontend.Variable, maxInputs),
			InputNoteLeafIndex:  make([]frontend.Variable, maxInputs),
			InputNotePath:       make([][]frontend.Variable, maxInputs),
		},
	}
	for i := 0; i < maxInputs; i++ {
		c.Priv.InputNotePath[i] = make([]frontend.Variable, merkleDepth)
	}
	return c
}

// =============================================================================
// Define
// =============================================================================
//
// Define builds the constraint system for the forced withdrawal proof.
func (c *ForcedWithdrawCircuit) Define(api frontend.API) error {
	// Build all sizing-dependent selectors and perform basic range/bounds validation.
	state := c.validateInputs(api)

	// Verify approval signature and bind it to the live registry leaf supplied by the pool.
	c.verifyAuth(api)

	// Process each input note.
	inputValueSum := c.processInputs(api, state)

	// Bind public withdrawal outputs.
	c.assertFinalState(api, inputValueSum)
	return nil
}

// =============================================================================
// Validation and cached selectors
// =============================================================================

func (c *ForcedWithdrawCircuit) validateInputs(api frontend.API) forcedWithdrawInternalState {
	// Basic range checks for public inputs.
	AssertIsNBits(api, c.Pub.NIn, CountBits)
	AssertIsNBits(api, c.Pub.WithdrawalAmount, AmountBits)
	AssertIsNBits(api, c.Pub.WithdrawalTokenID, TokenIDBits)
	// WithdrawalTo arrives as the pool's uint256(uint160(withdrawal.to)) encoding, so this range
	// check is redundant for the on-chain caller and exists for callers that build the public
	// vector themselves. The recipient's real binding is the approval digest, which the pool
	// recomputes over the same withdrawal struct, so changing the recipient invalidates the proof
	// with or without this check.
	AssertIsNBits(api, c.Pub.WithdrawalTo, AddressBits)

	// Enforce 1 <= NIn <= MaxInputs (a forced withdrawal with 0 inputs is semantically invalid).
	AssertIsNonZero(api, c.Pub.NIn)
	AssertIsLessOrEqual(api, c.Pub.NIn, uint64(c.Shape.MaxInputs), CountBits)

	// Cache inputActive selectors.
	inputActive := make([]Bool, c.Shape.MaxInputs)
	for i := 0; i < c.Shape.MaxInputs; i++ {
		inputActive[i] = isGreaterThanConst(api, c.Pub.NIn, uint64(i), CountBits)
	}
	return forcedWithdrawInternalState{inputActive: inputActive}
}

// =============================================================================
// Core logic
// =============================================================================

func (c *ForcedWithdrawCircuit) verifyAuth(api frontend.API) {
	// ToBinary returns least-significant bits first and binds the complete public AuthContext:
	// [0,64) expiry, bit 64 mode, [65,85) leaf index, [85,100) tree number,
	// [100,108) version, and [108,128) reserved zero bits.
	// The locator ranges are protocol data, not padding. LibForced._resolveLiveAuth decodes
	// them and compares both values with the live AuthRegistry record before verification.
	contextBits := api.ToBinary(c.Pub.AuthContext, ForcedAuthContextTotalBits)
	authExpiry := api.FromBinary(contextBits[ForcedAuthContextExpiryStart:ForcedAuthContextExpiryEnd]...)
	useApproval := AsBool(contextBits[ForcedAuthContextModeBit])
	AssertIsBool(api, useApproval)
	version := api.FromBinary(contextBits[ForcedAuthContextVersionStart:ForcedAuthContextVersionEnd]...)
	AssertEqual(api, version, ForcedAuthContextVersion)
	for i := ForcedAuthContextUsedBits; i < ForcedAuthContextTotalBits; i++ {
		AssertEqual(api, contextBits[i], 0)
	}

	approveMsg := Poseidon2T4(api, domainApprove, c.Pub.ApproveDigestHi, c.Pub.ApproveDigestLo)
	pk := AffinePoint{X: c.Priv.AuthPkX, Y: c.Priv.AuthPkY}
	sig := EdDSASignature{
		R8: AffinePoint{X: c.Priv.AuthSigR8x, Y: c.Priv.AuthSigR8y},
		S:  c.Priv.AuthSigS,
	}
	VerifyEdDSAIf(api, Not(api, useApproval), pk, sig, approveMsg)

	keyLeaf := Poseidon2T4(
		api,
		domainRegLeaf,
		c.Pub.SpenderAccountId,
		c.Priv.AuthPkX,
		c.Priv.AuthPkY,
		authExpiry,
	)
	commitment := Poseidon2T4(
		api,
		domainApproveCommit,
		c.Pub.ApproveDigestHi,
		c.Pub.ApproveDigestLo,
		c.Priv.Blinding,
	)
	// Forced approvals are deliberately isolated from routine batches. Fold a
	// single commitment with the fixed empty-subtree constants, matching
	// AuthRegistry.approveSpend (a size-1 batch).
	batchRoot := frontend.Variable(commitment)
	zeroHashes := computeZeroHashes(SpendApprovalBatchDepth)
	for level := 0; level < SpendApprovalBatchDepth; level++ {
		batchRoot = Poseidon2T4(api, batchRoot, zeroHashes[level])
	}
	approvalLeaf := Poseidon2T4(
		api,
		domainApprovalLeaf,
		c.Pub.SpenderAccountId,
		batchRoot,
		authExpiry,
	)
	authLeaf := Select(api, useApproval, approvalLeaf, keyLeaf)
	AssertEqual(api, authLeaf, c.Pub.AuthLeaf)
	AssertIsNonZeroIf(api, useApproval, authExpiry)
}

func (c *ForcedWithdrawCircuit) processInputs(api frontend.API, state forcedWithdrawInternalState) frontend.Variable {
	// Compute MPK = Hash(domainMPK, accountId, nullifyingKey) once for all inputs.
	masterPublicKey := Poseidon2T4(api, domainMPK, c.Pub.SpenderAccountId, c.Priv.NullifyingKey)

	inputValueSum := frontend.Variable(0)
	for i := 0; i < c.Shape.MaxInputs; i++ {
		inputActive := state.inputActive[i]
		inputInactive := Not(api, inputActive)

		// Zero padding for inactive inputs (B: enforce inactive semantics).
		AssertIsZeroIf(api, inputInactive, c.Priv.InputNoteTreeNumber[i])
		AssertIsZeroIf(api, inputInactive, c.Priv.InputTokenID[i])
		AssertIsZeroIf(api, inputInactive, c.Priv.InputValue[i])
		AssertIsZeroIf(api, inputInactive, c.Priv.InputNoteRnd[i])
		AssertIsZeroIf(api, inputInactive, c.Priv.InputNoteLeafIndex[i])
		AssertIsZeroIf(api, inputInactive, c.Pub.Nullifiers[i])
		AssertIsZeroIf(api, inputInactive, c.Pub.InputCommitments[i])
		for d := 0; d < c.Shape.MerkleDepth; d++ {
			AssertIsZeroIf(api, inputInactive, c.Priv.InputNotePath[i][d])
		}

		AssertIsNBits(api, c.Priv.InputValue[i], AmountBits)
		AssertIsNBits(api, c.Priv.InputTokenID[i], TokenIDBits)

		// Bounds check for input note tree number (defense-in-depth).
		AssertIsLessIf(api, inputActive, c.Priv.InputNoteTreeNumber[i], uint64(MaxNoteTreeNumber)+1, NoteTreeNumberBits+1)

		// All active inputs must be for the same token id.
		AssertEqualIf(api, inputActive, c.Priv.InputTokenID[i], c.Priv.TransferTokenID)

		// Compute input NPK = Hash(domainNote, MPK, noteRnd).
		inputNPK := Poseidon2T4(api, domainNote, masterPublicKey, c.Priv.InputNoteRnd[i])

		// Refuse the reserved low range. A withdrawal marker is a note commitment whose key slot
		// holds a 160-bit recipient address, and the input key below is a Poseidon output, so
		// reaching a marker costs a preimage search rather than a choice of witness. This is
		// defense in depth behind the tree fix, not the thing standing between a forced request
		// and already-paid-out value.
		AssertSpendableNPKIf(api, inputActive, inputNPK)

		// Compute input commitment = Hash(domainNote, NPK, tokenId, value) and bind to public InputCommitments.
		commitment := Poseidon2T4(api, domainNote, inputNPK, c.Priv.InputTokenID[i], c.Priv.InputValue[i])
		AssertIsNonZeroIf(api, inputActive, commitment)
		AssertEqualIf(api, inputActive, commitment, c.Pub.InputCommitments[i])

		// Prove membership: computed root must match a known root AND tree number must match.
		// This binds InputNoteTreeNumber to the actual tree, preventing double-spend attacks.
		rootComputed := computeRoot(api, commitment, c.Priv.InputNoteLeafIndex[i], c.Priv.InputNotePath[i], c.Shape.MerkleDepth)
		AssertRootWithTreeNumberIf(api, inputActive, rootComputed, c.Priv.InputNoteTreeNumber[i], c.Pub.NoteKnownRoots, c.Pub.NoteKnownTreeNumbersPacked)

		// Bind the public nullifier.
		combinedDomain := api.Add(domainNullifier, api.Mul(c.Priv.InputNoteTreeNumber[i], NullifierTreeNumberMultiplier))
		nullifier := Poseidon2T4(api, combinedDomain, c.Priv.NullifyingKey, c.Priv.InputNoteLeafIndex[i])
		AssertEqualIf(api, inputActive, nullifier, c.Pub.Nullifiers[i])

		// Accumulate the gross withdrawal amount.
		inputValueSum = AddIf(api, inputActive, inputValueSum, c.Priv.InputValue[i])
	}
	return inputValueSum
}

func (c *ForcedWithdrawCircuit) assertFinalState(api frontend.API, inputValueSum frontend.Variable) {
	AssertEqual(api, c.Priv.TransferTokenID, c.Pub.WithdrawalTokenID)
	AssertEqual(api, c.Pub.WithdrawalAmount, inputValueSum)
}
