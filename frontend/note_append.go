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
// NoteAppend: the shared batch-append relation
// =============================================================================

// NoteAppend is the public half of the note-tree batch append: the admitted root table the
// append starts from, the tree it advances, the leaf counts either side of it, and how many
// leaves it writes. A circuit that appends note commitments embeds this struct rather than
// redeclaring the fields, so one relation is stated once and every embedding circuit proves
// the same thing about its tree transition.
//
// Field order here IS the on-chain public-input order for this span, because gnark derives the
// public vector from struct traversal order. Reordering these fields changes the vector of
// every embedding circuit at once and requires new verifying keys plus matching edits to each
// circuit's Solidity public-input builder.
//
// The leaves themselves are deliberately NOT a field here. Each embedding circuit places its
// commitment array at whatever position its own vector needs, and passes it to the append
// methods below.
type NoteAppend struct {
	NoteKnownRoots             []frontend.Variable `gnark:",public"` // [MaxNoteRootsPerProof] admitted note roots, zero padded
	NoteKnownTreeNumbersPacked frontend.Variable   `gnark:",public"` // one 15-bit tree number per root slot, packed low to high
	ActiveNoteTreeNumber       frontend.Variable   `gnark:",public"` // tree the append starts from, before any rollover
	RootNew                    frontend.Variable   `gnark:",public"` // root after the batch append
	CountOld                   frontend.Variable   `gnark:",public"` // leaf count before the append
	CountNew                   frontend.Variable   `gnark:",public"` // leaf count after the append
	Rollover                   frontend.Variable   `gnark:",public"` // 1 when the append starts a fresh tree
	NAppends                   frontend.Variable   `gnark:",public"` // number of leaves appended (1..maxAppends)
}

// noteAppendState carries the evolving output-tree state and the activity selector that the
// append methods below read and write while building constraints. It is not a witness struct:
// every field is an intermediate value derived during `Define`.
type noteAppendState struct {
	currentCount     frontend.Variable   // evolving leaf count for the active output tree
	currentFrontier  []frontend.Variable // evolving frontier for the active output tree
	fullTreeRoot     frontend.Variable   // root of the full tree, set by applyBatchAppend; read only when currentCount == 2^depth
	commitmentActive []Bool              // commitmentActive[i] := (i < NAppends)
}

// =============================================================================
// Validation helpers
// =============================================================================

// validateAndInitTreeState enforces the append relation's public bounds and rollover semantics,
// binds the caller's frontier witness to the selected active tree root when not rolling over,
// and returns the tree state the append starts from plus the per-leaf activity selector.
//
// frontierOld stays a caller-supplied argument rather than a field of NoteAppend, because
// NoteAppend mirrors the public vector exactly and the frontier is witness-only. maxAppends and
// merkleDepth are compile-time shape: they bound NAppends and fix tree capacity, and add no
// constraints of their own.
func (a *NoteAppend) validateAndInitTreeState(
	api frontend.API,
	maxAppends, merkleDepth int,
	frontierOld []frontend.Variable,
) noteAppendState {
	// Range-check and bound-check public tree inputs.
	AssertIsNBits(api, a.CountOld, CountBits)
	AssertIsNBits(api, a.CountNew, CountBits)

	// 1 <= NAppends <= maxAppends
	AssertIsNonZero(api, a.NAppends)
	AssertIsLessOrEqual(api, a.NAppends, uint64(maxAppends), CountBits)

	// ActiveNoteTreeNumber is within [0, MaxNoteTreeNumber].
	AssertIsLess(api, a.ActiveNoteTreeNumber, uint64(MaxNoteTreeNumber)+1, NoteTreeNumberBits+1)

	// Tree capacity checks.
	noteTreeCapacityLeaves := uint64(1) << merkleDepth
	AssertIsLessOrEqual(api, a.CountOld, noteTreeCapacityLeaves, CountBits)
	AssertIsLessOrEqual(api, a.CountNew, noteTreeCapacityLeaves, CountBits)

	// Rollover semantics: non-rollover requires CountOld < capacity; rollover requires CountOld == capacity.
	rollover := AsBool(a.Rollover)
	AssertIsBool(api, rollover)
	notRollover := Not(api, rollover)
	AssertIsLessIf(api, notRollover, a.CountOld, noteTreeCapacityLeaves, CountBits)
	AssertEqualIfU64(api, rollover, a.CountOld, noteTreeCapacityLeaves)

	// Bind frontier witness to the selected active tree root when not rolling over.
	knownTreeNumbers := unpackSlots(
		api,
		a.NoteKnownTreeNumbersPacked,
		len(a.NoteKnownRoots),
		TreeNumberBitsPerSlot,
	)
	AssertSingleActiveRootForTreeNumber(
		api,
		a.NoteKnownRoots,
		knownTreeNumbers,
		a.ActiveNoteTreeNumber,
	)
	activeTreeRoot := selectByTreeNumber(
		api,
		a.NoteKnownRoots,
		knownTreeNumbers,
		a.ActiveNoteTreeNumber,
	)
	rootFromFrontier := computeRootFromFrontier(api, frontierOld, a.CountOld, merkleDepth)
	AssertEqualIf(api, notRollover, rootFromFrontier, activeTreeRoot)

	// Rollover starts from an empty state; otherwise from the old state. Select keeps append constraints uniform.
	state := noteAppendState{
		currentCount:     Select(api, rollover, 0, a.CountOld),
		currentFrontier:  make([]frontend.Variable, merkleDepth),
		commitmentActive: make([]Bool, maxAppends),
	}
	for i := 0; i < merkleDepth; i++ {
		state.currentFrontier[i] = Select(api, rollover, 0, frontierOld[i])
	}
	for i := 0; i < maxAppends; i++ {
		state.commitmentActive[i] = isGreaterThanConst(api, a.NAppends, uint64(i), CountBits)
	}
	return state
}

// =============================================================================
// Core processing
// =============================================================================

// applyBatchAppend appends every active leaf of `commitments` into the output tree in one batch.
//
// commitmentActive[i] := (i < NAppends), so the live leaves already occupy a prefix of the slot
// array and no routing is needed — a single packed block goes straight into the batched append.
// That costs ~len(commitments) + merkleDepth Poseidon permutations where appending one leaf at a
// time cost ~len(commitments) * merkleDepth.
func (a *NoteAppend) applyBatchAppend(
	api frontend.API,
	merkleDepth int,
	commitments []frontend.Variable,
	state *noteAppendState,
) {
	batch := newPrefixPackedList(api, commitments, state.commitmentActive)

	// currentCount is < 2^merkleDepth here: rollover forces it to 0, and without rollover
	// validateAndInitTreeState already required CountOld < 2^merkleDepth. appendFrontierBatch
	// re-checks that, plus that the batch fits in the remaining capacity.
	nextFrontier, nextCount, finalCarry := appendFrontierBatch(
		api,
		state.currentFrontier,
		state.currentCount,
		batch,
		merkleDepth,
	)
	state.currentFrontier = nextFrontier
	state.currentCount = nextCount
	state.fullTreeRoot = finalCarry
}

// assertFinalState binds the internal working tree state to the public outputs.
func (a *NoteAppend) assertFinalState(api frontend.API, merkleDepth int, state noteAppendState) {
	// When tree is full, computeRootFromFrontier returns incorrect result (handled internally),
	// so we use fullTreeRoot from the batch append's final carry instead.
	maxCount := uint64(1) << merkleDepth
	isFull := IsEqual(api, state.currentCount, maxCount)

	computedRoot := computeRootFromFrontier(api, state.currentFrontier, state.currentCount, merkleDepth)
	rootNew := api.Select(isFull.AsField(), state.fullTreeRoot, computedRoot)

	AssertEqual(api, rootNew, a.RootNew)
	AssertEqual(api, state.currentCount, a.CountNew)
}
