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
	"sync"

	"github.com/consensys/gnark/frontend"
	phash "github.com/testinprod-io/privacy-boost-protocol/prover/hash"
)

// =============================================================================
// Circuit helpers
// =============================================================================
//
// This file contains small reusable helpers used across circuits:
// - Constant comparison helpers (value < bound, etc.)
// - Assertion wrappers (equalities, conditional constraints)
// - Small arithmetic helpers (e.g. AddIf) and array multiplexers (SelectByIndex)
// - Merkle tree utilities (root computation, frontier append)
//
// Notes:
// - Many helpers assume certain inputs are already range-checked or boolean. Those assumptions are
//   documented at the call sites, and enforced with the `Assert*` wrappers where necessary.
// - Helpers are organized top-down by "how they are typically used" in circuit `Define` methods.

// =============================================================================
// Constant comparison helpers
// =============================================================================

// isLessThanConst returns true if value < bound, else false.
func isLessThanConst(api frontend.API, value frontend.Variable, bound uint64, bitLen int) Bool {
	bits := api.ToBinary(value, bitLen)

	// Standard MSB->LSB comparison:
	// - eq means "all higher bits are equal so far"
	// - lt becomes 1 if we ever see (valueBit=0, constBit=1) while eq==1
	var lt frontend.Variable = 0
	var eq frontend.Variable = 1
	for i := bitLen - 1; i >= 0; i-- {
		cBit := (bound >> uint(i)) & 1
		if cBit == 1 {
			// If equal so far and we see 0 where const has 1, then value<const.
			lt = api.MulAcc(lt, eq, api.Sub(1, bits[i]))
		}
		// Update eq: eq &= (bits[i] == cBit)
		eq = api.Mul(eq, IsEqual(api, bits[i], cBit).AsField())
	}
	return AsBool(lt)
}

// isGreaterOrEqualConst returns true if value >= bound, else false.
func isGreaterOrEqualConst(api frontend.API, value frontend.Variable, bound uint64, bitLen int) Bool {
	// value >= bound  <=>  NOT(value < bound)
	return Not(api, isLessThanConst(api, value, bound, bitLen))
}

// isLessOrEqualConst returns true if value <= bound, else false.
func isLessOrEqualConst(api frontend.API, value frontend.Variable, bound uint64, bitLen int) Bool {
	// If bound covers the entire bitLen domain, this reduces to a pure range check.
	// This avoids the edge case where (bound+1) would require one extra bit.
	if bitLen <= 0 {
		panic("isLessOrEqualConst: bitLen must be > 0")
	}
	if bitLen < 64 && bound >= (uint64(1)<<uint(bitLen))-1 {
		_ = api.ToBinary(value, bitLen)
		return True()
	}
	if bitLen == 64 && bound == ^uint64(0) {
		_ = api.ToBinary(value, bitLen)
		return True()
	}

	// General case: (value <= bound) <=> (value < bound) OR (value == bound).
	lt := isLessThanConst(api, value, bound, bitLen)
	eq := IsEqual(api, value, bound)
	return Or(api, lt, eq)
}

// isLessOrEqualBits returns true if a <= b, where both operands are already
// little-endian bit decompositions of the same length.
func isLessOrEqualBits(api frontend.API, aBits, bBits []frontend.Variable) Bool {
	if len(aBits) != len(bBits) {
		panic("isLessOrEqualBits: operands must have same bit length")
	}

	var lt frontend.Variable = 0
	var eq frontend.Variable = 1
	for i := len(aBits) - 1; i >= 0; i-- {
		lessAtBit := api.Mul(eq, api.Mul(api.Sub(1, aBits[i]), bBits[i]))
		lt = Or(api, AsBool(lt), AsBool(lessAtBit)).AsField()
		eq = api.Mul(eq, IsEqual(api, aBits[i], bBits[i]).AsField())
	}
	return Or(api, AsBool(lt), AsBool(eq))
}

// isGreaterThanConst returns true if value > bound, else false.
//
// Implemented as NOT(value <= bound).
func isGreaterThanConst(api frontend.API, value frontend.Variable, bound uint64, bitLen int) Bool {
	return Not(api, isLessOrEqualConst(api, value, bound, bitLen))
}

// isLessThanVar returns true if a < b for two circuit variables, comparing over `bitLen` bits.
//
// Both operands are range-checked to `bitLen` bits via ToBinary; callers must size `bitLen` to fit
// the larger operand or the comparison is unsound. The MSB->LSB scan mirrors `isLessThanConst`, but
// here the "constant" side is itself a witness so each per-bit branch is a circuit comparison.
func isLessThanVar(api frontend.API, a, b frontend.Variable, bitLen int) Bool {
	aBits := api.ToBinary(a, bitLen)
	bBits := api.ToBinary(b, bitLen)

	// lt becomes 1 the first time (while all higher bits are equal) we see aBit=0, bBit=1.
	var lt frontend.Variable = 0
	var eq frontend.Variable = 1
	for i := bitLen - 1; i >= 0; i-- {
		// aLtBit := (aBit == 0) AND (bBit == 1) == (1 - aBit) * bBit.
		aLtBit := api.Mul(api.Sub(1, aBits[i]), bBits[i])
		lt = api.MulAcc(lt, eq, aLtBit)

		// Update eq: eq &= (aBit == bBit).
		eq = api.Mul(eq, IsEqual(api, aBits[i], bBits[i]).AsField())
	}
	return AsBool(lt)
}

// =============================================================================
// Assertion helpers
// =============================================================================

// -----------------------------------------------------------------------------
// Predicates (Bool-returning helpers)
// -----------------------------------------------------------------------------

// IsEqual returns true if a == b, else false.
func IsEqual(api frontend.API, a, b frontend.Variable) Bool {
	return AsBool(api.IsZero(api.Sub(a, b)))
}

// isNonZero returns true if value != 0, else false.
func isNonZero(api frontend.API, value frontend.Variable) Bool {
	return AsBool(api.Sub(1, api.IsZero(value)))
}

// -----------------------------------------------------------------------------
// Range checks
// -----------------------------------------------------------------------------

// AssertIsNBits enforces that value fits in n bits (i.e., 0 <= value < 2^n).
//
// This is a "range check" wrapper around ToBinary when you don't need the bits.
func AssertIsNBits(api frontend.API, value frontend.Variable, n int) {
	_ = api.ToBinary(value, n)
}

// AssertIsNBitsIf enforces enabled => value fits in n bits.
func AssertIsNBitsIf(api frontend.API, enabled Bool, value frontend.Variable, n int) {
	_ = api.ToBinary(Select(api, enabled, value, 0), n)
}

// -----------------------------------------------------------------------------
// Ordering asserts
// -----------------------------------------------------------------------------

// AssertIsLess enforces value < bound.
func AssertIsLess(api frontend.API, value frontend.Variable, bound uint64, bitLen int) {
	AssertIsTrue(api, isLessThanConst(api, value, bound, bitLen))
}

// AssertIsLessOrEqual enforces value <= bound for a constant bound and a fixed bit-length.
func AssertIsLessOrEqual(api frontend.API, value frontend.Variable, bound uint64, bitLen int) {
	AssertIsTrue(api, isLessOrEqualConst(api, value, bound, bitLen))
}

// AssertIsLessIf enforces (enabled == 1) => (value < bound).
//
// enabled is expected to be boolean (0/1).
func AssertIsLessIf(api frontend.API, enabled Bool, value frontend.Variable, bound uint64, bitLen int) {
	lt := isLessThanConst(api, value, bound, bitLen)
	AssertIsTrueIf(api, enabled, lt)
}

// AssertIsLessOrEqualIf enforces (enabled == 1) => (value <= bound).
//
// enabled is expected to be boolean (0/1).
func AssertIsLessOrEqualIf(api frontend.API, enabled Bool, value frontend.Variable, bound uint64, bitLen int) {
	le := isLessOrEqualConst(api, value, bound, bitLen)
	AssertIsTrueIf(api, enabled, le)
}

// -----------------------------------------------------------------------------
// Boolean asserts
// -----------------------------------------------------------------------------

// AssertIsTrue enforces b == 1.
func AssertIsTrue(api frontend.API, b Bool) {
	AssertEqual(api, b.AsField(), 1)
}

// AssertIsFalse enforces b == 0.
func AssertIsFalse(api frontend.API, b Bool) {
	AssertEqual(api, b.AsField(), 0)
}

// AssertIsTrueIf enforces (enabled == 1) => (b == 1).
func AssertIsTrueIf(api frontend.API, enabled Bool, b Bool) {
	AssertEqualIf(api, enabled, b.AsField(), 1)
}

// AssertIsFalseIf enforces (enabled == 1) => (b == 0).
func AssertIsFalseIf(api frontend.API, enabled Bool, b Bool) {
	AssertEqualIf(api, enabled, b.AsField(), 0)
}

// -----------------------------------------------------------------------------
// Zero/non-zero asserts
// -----------------------------------------------------------------------------

// AssertIsNonZero enforces value != 0.
func AssertIsNonZero(api frontend.API, value frontend.Variable) {
	api.AssertIsDifferent(value, 0)
}

// AssertIsZeroIf enforces (enabled == 1) => (value == 0).
//
// enabled is expected to be boolean (0/1).
func AssertIsZeroIf(api frontend.API, enabled Bool, value frontend.Variable) {
	AssertEqualIf(api, enabled, value, 0)
}

// AssertIsNonZeroIf enforces (enabled == 1) => (value != 0).
//
// enabled is expected to be boolean (0/1).
func AssertIsNonZeroIf(api frontend.API, enabled Bool, value frontend.Variable) {
	// enabled=1 => value != 0
	AssertIsTrueIf(api, enabled, isNonZero(api, value))
}

// -----------------------------------------------------------------------------
// Equality asserts
// -----------------------------------------------------------------------------

// AssertEqual enforces a == b.
func AssertEqual(api frontend.API, a, b frontend.Variable) {
	api.AssertIsEqual(a, b)
}

// AssertEqualIf enforces (enabled == 1) => (a == b).
//
// enabled is expected to be boolean (0/1).
func AssertEqualIf(api frontend.API, enabled Bool, a, b frontend.Variable) {
	api.AssertIsEqual(api.Mul(enabled.AsField(), api.Sub(a, b)), 0)
}

// AssertEqualIfU64 enforces (enabled == 1) => (a == b) where b is a uint64 constant.
func AssertEqualIfU64(api frontend.API, enabled Bool, a frontend.Variable, b uint64) {
	AssertEqualIf(api, enabled, a, b)
}

// AssertIsDifferentIf enforces (enabled == 1) => (a != b).
//
// enabled is expected to be boolean (0/1).
func AssertIsDifferentIf(api frontend.API, enabled Bool, a, b frontend.Variable) {
	// enabled=1 => IsZero(a-b)=0
	api.AssertIsEqual(api.Mul(enabled.AsField(), IsEqual(api, a, b).AsField()), 0)
}

// =============================================================================
// Small arithmetic helpers
// =============================================================================

// AddIf returns acc + (enabled ? x : 0).
//
// enabled is expected to be boolean (0/1).
func AddIf(api frontend.API, enabled Bool, acc, x frontend.Variable) frontend.Variable {
	return api.Add(acc, api.Mul(enabled.AsField(), x))
}

// =============================================================================
// Multiplexers
// =============================================================================

// SelectByIndex selects values[idx] where idx is a circuit variable.
//
// This is a circuit "array getter" implemented as an O(n) multiplexer:
// it computes isMatch(idx == i) for each i and returns Σ values[i]*isMatch.
//
// NOTE: callers must separately constrain idx to be in range [0, len(values)-1].
func SelectByIndex(api frontend.API, values []frontend.Variable, idx frontend.Variable) frontend.Variable {
	// A straightforward O(n) mux:
	// result = Σ values[i] * isMatch(idx == i)
	result := frontend.Variable(0)
	for i := 0; i < len(values); i++ {
		isMatch := IsEqual(api, idx, i).AsField()
		result = api.Add(result, api.Mul(isMatch, values[i]))
	}
	return result
}

// AssertSingleActiveRootForTreeNumber enforces that exactly one non-zero root slot
// matches the given tree number.
//
// Non-zero roots denote active sparse slots; zero roots are padding.
func AssertSingleActiveRootForTreeNumber(
	api frontend.API,
	knownRoots []frontend.Variable,
	knownTreeNumbers []frontend.Variable,
	treeNumber frontend.Variable,
) {
	if len(knownRoots) != len(knownTreeNumbers) {
		panic("AssertSingleActiveRootForTreeNumber: arrays must have the same length")
	}

	matchCount := frontend.Variable(0)
	for i := 0; i < len(knownRoots); i++ {
		// Ignore zero-padded inactive slots (contract rejects root==0 for used roots).
		// This avoids treating trailing padding (root=0, treeNum=0) as extra matches when treeNumber=0.
		slotActive := isNonZero(api, knownRoots[i])
		matchesTree := IsEqual(api, treeNumber, knownTreeNumbers[i])
		match := And(api, slotActive, matchesTree)
		matchCount = api.Add(matchCount, match.AsField())
	}

	// Enforce exactly one active slot matches the selected tree number.
	// Without this, duplicates of the same tree number would change the selected root interpretation.
	AssertEqual(api, matchCount, 1)
}

// selectByTreeNumber selects the root from knownRoots whose tree number matches treeNumber.
//
// Callers should enforce uniqueness for the selected tree number separately via
// AssertSingleActiveRootForTreeNumber.
func selectByTreeNumber(
	api frontend.API,
	knownRoots []frontend.Variable,
	knownTreeNumbers []frontend.Variable,
	treeNumber frontend.Variable,
) frontend.Variable {
	if len(knownRoots) != len(knownTreeNumbers) {
		panic("selectByTreeNumber: arrays must have the same length")
	}

	result := frontend.Variable(0)
	for i := 0; i < len(knownRoots); i++ {
		// Ignore zero-padded inactive slots (contract rejects root==0 for used roots).
		slotActive := isNonZero(api, knownRoots[i])
		matchesTree := IsEqual(api, treeNumber, knownTreeNumbers[i])
		match := And(api, slotActive, matchesTree)
		result = AddIf(api, match, result, knownRoots[i])
	}
	return result
}

// =============================================================================
// Packed tree number utilities
// unpackSlots extracts n values from a packed field element, each occupying bitsPerSlot bits.
func unpackSlots(api frontend.API, packed frontend.Variable, n int, bitsPerSlot int) []frontend.Variable {
	totalBits := n * bitsPerSlot
	allBits := api.ToBinary(packed, totalBits)

	values := make([]frontend.Variable, n)
	for i := 0; i < n; i++ {
		startBit := i * bitsPerSlot
		slotBits := allBits[startBit : startBit+bitsPerSlot]
		values[i] = api.FromBinary(slotBits...)
	}
	return values
}

// AssertRootWithTreeNumberIf enforces (enabled == 1) => (root, treeNumber) matches (knownRoots[i], knownTreeNumbers[i]) for some i.
//
// This binds the claimed tree number to the actual tree where the Merkle root was computed,
// preventing double-spend attacks where a prover claims a different tree number while using
// a valid Merkle proof from another tree.
func AssertRootWithTreeNumberIf(
	api frontend.API,
	enabled Bool,
	root frontend.Variable,
	treeNumber frontend.Variable,
	knownRoots []frontend.Variable,
	packedTreeNumbers frontend.Variable,
) {
	knownTreeNumbers := unpackSlots(api, packedTreeNumbers, len(knownRoots), TreeNumberBitsPerSlot)
	matchFound := findPairMatch(api, root, treeNumber, knownRoots, knownTreeNumbers)
	AssertIsTrueIf(api, enabled, matchFound)
}

// findPairMatch returns true if (value1, value2) matches (arr1[i], arr2[i]) for some index i.
//
// This is a set membership check for pairs: it verifies that the given pair exists
// at the same index in both arrays.
func findPairMatch(
	api frontend.API,
	value1 frontend.Variable,
	value2 frontend.Variable,
	arr1 []frontend.Variable,
	arr2 []frontend.Variable,
) Bool {
	if len(arr1) != len(arr2) {
		panic("findPairMatch: arrays must have the same length")
	}

	// Single pass over paired slots:
	// matchFound = OR_i ((arr1[i] == value1) AND (arr2[i] == value2))
	matchFound := False()
	for i := 0; i < len(arr1); i++ {
		eq1 := IsEqual(api, value1, arr1[i])
		eq2 := IsEqual(api, value2, arr2[i])
		pairMatch := And(api, eq1, eq2)
		matchFound = Or(api, matchFound, pairMatch)
	}
	return matchFound
}

// =============================================================================
// Merkle utilities
// =============================================================================

// computeZeroHashes returns the hash chain of empty subtree roots for the given depth.
//
// zeros[d] is the root of an empty subtree of height d, with:
// zeros[0] = 0
// zeros[i] = Poseidon(zeros[i-1], zeros[i-1])
//
// These values are deterministic, so we precompute them natively and embed them as constants.
// This avoids adding in-circuit Poseidon constraints for the empty subtree chain.
var (
	zeroHashesCacheMu sync.RWMutex
	zeroHashesCache   = map[int][]frontend.Variable{}
)

func computeZeroHashes(depth int) []frontend.Variable {
	if depth < 0 {
		panic("computeZeroHashes: depth must be >= 0")
	}

	zeroHashesCacheMu.RLock()
	if cached, ok := zeroHashesCache[depth]; ok {
		zeroHashesCacheMu.RUnlock()
		return cached
	}
	zeroHashesCacheMu.RUnlock()

	zeros := make([]frontend.Variable, depth+1)
	prev := big.NewInt(0)
	zeros[0] = prev
	for i := 1; i <= depth; i++ {
		prev = phash.Hash2T4(prev, prev)
		zeros[i] = prev
	}

	zeroHashesCacheMu.Lock()
	zeroHashesCache[depth] = zeros
	zeroHashesCacheMu.Unlock()

	return zeros
}

// computeRootFromFrontier computes the Merkle root implied by a (frontier, count) representation.
//
// frontier[i] stores the left sibling at level i for the next append position given by count.
// This is used to bind a frontier witness to a known root and to compute roots while updating a tree.
//
// Note: When count = 2^depth (tree is full), the result is incorrect (returns empty tree root).
// Callers should use fullTreeRoot from appendFrontier instead when the tree is full.
func computeRootFromFrontier(
	api frontend.API,
	frontier []frontend.Variable,
	count frontend.Variable,
	depth int,
) frontend.Variable {
	// When count = 2^depth, ToBinary(count, depth) overflows since it requires depth+1 bits.
	// Use 0 as a safe value to prevent the overflow. The result will be incorrect (zeros[depth]),
	// but callers should use fullTreeRoot instead when the tree is full.
	maxCount := uint64(1) << depth
	isFull := IsEqual(api, count, maxCount)
	safeCount := Select(api, isFull, 0, count)

	// countBits selects whether the next node at each depth is "filled" (bit=1) or "empty" (bit=0).
	bits := api.ToBinary(safeCount, depth)
	zeros := computeZeroHashes(depth)

	// current tracks the subtree root accumulated from lower levels up to level i.
	current := zeros[0]
	for i := 0; i < depth; i++ {
		bit := bits[i]

		// If bit==1, frontier[i] is the left node and current is the right; else current is the left and zeros[i] is the right.
		left := api.Select(bit, frontier[i], current)
		right := api.Select(bit, current, zeros[i])
		current = Poseidon2T4(api, left, right)
	}
	return current
}

// appendFrontier appends a leaf into a frontier-based tree state and returns (nextFrontier, nextCount, finalCarry).
//
// finalCarry is the final value of the carry after propagation.
//
// This implements the "binary carry" behavior of Merkle appends:
// - while the bit at level i is 1, we merge (hash) the existing frontier node with the carry,
// - at the first level where the bit is 0, we store the carry into the frontier and stop.
//
// Special case: when count = 2^depth - 1 (all bits set), the carry propagates through all levels
// without being stored in the frontier. This is valid - the tree becomes completely full and
// finalCarry is the Merkle root of the full tree.
func appendFrontier(
	api frontend.API,
	frontier []frontend.Variable,
	count frontend.Variable,
	leaf frontend.Variable,
	depth int,
) ([]frontend.Variable, frontend.Variable, frontend.Variable) {
	// When count = 2^depth, ToBinary(count, depth) overflows since it requires depth+1 bits.
	// Use 0 as a safe value to prevent the overflow. When count reaches 2^depth, the tree is full
	// and callers should treat the resulting state as inactive / use fullTreeRoot where applicable.
	maxCount := uint64(1) << depth
	isFull := IsEqual(api, count, maxCount)
	safeCount := Select(api, isFull, 0, count)

	// bits are little-endian: bits[i] is the i-th bit of count.
	bits := api.ToBinary(safeCount, depth)
	next := make([]frontend.Variable, depth)

	// carry is the subtree root being inserted/propagated up the tree.
	carry := leaf

	// done is 1 once we've stored the carry into the frontier (i.e., append is complete).
	done := frontend.Variable(0)

	for i := 0; i < depth; i++ {
		bit := bits[i]

		// use=1 if append is not done yet (so we should update this level).
		use := api.Sub(1, done)

		// take=1 if we should store carry at this level (first 0 bit), else 0.
		take := api.Mul(use, api.Sub(1, bit))

		// merge=1 if we should merge frontier[i] with carry (bit==1 and not done), else 0.
		merge := api.Mul(use, bit)

		// The hash output is only consumed in the merge case, so masking inputs is unnecessary.
		hashed := Poseidon2T4(api, frontier[i], carry)

		// Next frontier at level i:
		// - if take==1: set frontier[i] = carry
		// - if use==0: keep existing frontier[i]
		next[i] = api.Add(
			api.Mul(take, carry),
			api.Mul(api.Sub(1, use), frontier[i]),
		)

		// Update carry:
		// - if merge==1: carry = hash(frontier[i], carry)
		// - else: carry unchanged
		carry = api.Add(
			api.Mul(merge, hashed),
			api.Mul(api.Sub(1, merge), carry),
		)

		// done becomes 1 exactly once (when take==1 at the first 0 bit).
		done = api.Add(done, take)
	}

	return next, api.Add(count, 1), carry
}

// computeRoot computes a Merkle root for a non-domain-separated tree.
//
// This is a standard binary Merkle root with hashing `Poseidon(left, right)` at each level.
func computeRoot(api frontend.API, leaf, index frontend.Variable, path []frontend.Variable, depth int) frontend.Variable {
	bits := api.ToBinary(index, depth)
	current := leaf
	for i := 0; i < depth; i++ {
		sibling := path[i]
		bit := bits[i]

		// If bit==1, sibling is the left node; otherwise current is the left node.
		left := api.Select(bit, sibling, current)
		right := api.Select(bit, current, sibling)
		current = Poseidon2T4(api, left, right)
	}
	return current
}

// computeDomainRoot computes a Merkle root for a domain-separated tree.
//
// This is equivalent to `computeRoot`, but hashes as `Poseidon(domain, left, right)` at each level.
func computeDomainRoot(
	api frontend.API,
	leaf,
	index frontend.Variable,
	path []frontend.Variable,
	depth int,
	domain frontend.Variable,
) frontend.Variable {
	bits := api.ToBinary(index, depth)
	current := leaf
	for i := 0; i < depth; i++ {
		sibling := path[i]
		bit := bits[i]

		// If bit==1, sibling is the left node; otherwise current is the left node.
		left := api.Select(bit, sibling, current)
		right := api.Select(bit, current, sibling)

		// Domain separation makes the Merkle hash distinct from other Poseidon uses.
		h := Poseidon2T4(api, domain, left, right)
		current = h
	}
	return current
}
