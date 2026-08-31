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
	"math/bits"

	"github.com/consensys/gnark/frontend"
)

// =============================================================================
// Batch frontier append
// =============================================================================
//
// `appendFrontier` walks every tree level for every leaf, so appending K leaves into a
// depth-D tree costs ~K*D Poseidon permutations. `appendFrontierBatch` computes the same
// (root, count) transition in ~K+D permutations: it first folds the new leaves into a
// forest of perfect subtrees and only then merges that forest with the existing frontier,
// one level at a time.
//
// The two ingredients are:
//
//  1. `packedList` — the batch of new leaves compacted so the live entries occupy a prefix.
//     The circuit's leaf slots are sparse (an inactive transfer output sits between two
//     active ones), and the level-by-level pairing below only works on a contiguous run.
//     Callers build one `newPrefixPackedList` per group of slots and `mergePackedLists`
//     them, which closes the gaps between groups without any per-slot routing.
//
//  2. `appendFrontierBatch` — the level-by-level reduction. At each level the existing
//     frontier peak is prepended when the count bit is set (so the run starts on an even
//     index), adjacent nodes are hashed into parents, and an odd trailing node becomes the
//     new frontier entry for that level.
//
// Only the *final* `(frontier, count)` pair is observable by callers, and a frontier entry
// is meaningful only at levels where the corresponding bit of `count` is set. Entries at
// levels whose bit is clear are returned as zero here; the sequential path leaves stale or
// zero values there. Both are consistent with `computeRootFromFrontier`, which reads only
// the live levels.

// packedList is a variable-length list of circuit values held in a fixed-capacity array.
//
// Invariants (all maintained by the constructors and combinators in this file):
//   - `count` is the number of live entries, 0 <= count <= len(vals).
//   - `vals[i]` is zero for i >= count.
//
// Per-slot liveness is deliberately *not* a field. The list is ordered, so `count` already
// says where liveness turns off, and `appendFrontierBatch` derives the thermometer it needs
// once (see thermometerFromCount). Carrying it here instead would make every merge route a
// second array through the barrel shifter to rebuild what `count` already determines.
type packedList struct {
	vals  []frontend.Variable
	count frontend.Variable
}

// newPrefixPackedList wraps a block whose live slots are already a prefix — the common
// case in this codebase, where slot j of a group is active iff j < someCount.
//
// No routing is needed, so this is the cheap path: values are masked by their flag (which
// also normalizes whatever the witness placed in the padding slots to zero) and the prefix
// shape is asserted so a caller that passes gapped flags fails loudly instead of silently
// reordering leaves.
func newPrefixPackedList(api frontend.API, vals []frontend.Variable, active []Bool) packedList {
	if len(vals) != len(active) {
		panic("newPrefixPackedList: vals and active must have the same length")
	}
	if len(vals) == 0 {
		panic("newPrefixPackedList: block must be non-empty")
	}

	out := packedList{
		vals:  make([]frontend.Variable, len(vals)),
		count: frontend.Variable(0),
	}
	prev := frontend.Variable(0)
	for i := range vals {
		f := active[i].AsField()
		// The masking and summing below are plain multiplications, so nothing else pins the
		// flag to 0/1. Without this a single flag of, say, 5 would inflate `count` and inject
		// 5*vals[i] as a leaf, and the prefix check right after would still pass.
		AssertIsBool(api, active[i])
		if i > 0 {
			// active[i] must imply active[i-1], i.e. no gaps inside the block. Together with
			// the 0/1 check this is what makes `count` a faithful description of the block, so
			// that reconstructing liveness from it downstream is sound.
			AssertEqual(api, api.Mul(f, api.Sub(1, prev)), 0)
		}
		prev = f
		out.vals[i] = api.Mul(f, vals[i])
		out.count = api.Add(out.count, f)
	}
	return out
}

// mergePackedLists concatenates packed lists into one, preserving order.
//
// Merging is done as a balanced binary tree because the routing cost of a merge grows with
// the capacity of its left operand; folding left-to-right would make every step pay for the
// full accumulated prefix.
func mergePackedLists(api frontend.API, lists []packedList) packedList {
	if len(lists) == 0 {
		panic("mergePackedLists: need at least one list")
	}
	for len(lists) > 1 {
		merged := make([]packedList, 0, (len(lists)+1)/2)
		for i := 0; i+1 < len(lists); i += 2 {
			merged = append(merged, mergePackedPair(api, lists[i], lists[i+1]))
		}
		if len(lists)%2 == 1 {
			merged = append(merged, lists[len(lists)-1])
		}
		lists = merged
	}
	return lists[0]
}

// mergePackedPair returns the concatenation `a || b` as a packed list of capacity
// len(a.vals)+len(b.vals).
//
// Shifting b right by a.count puts its live entries at [a.count, a.count+b.count), disjoint
// from a's [0, a.count). Both operands are zero outside their live range, so overlaying a
// onto the shifted b concatenates them by plain addition. That addition is free in R1CS —
// it combines two linear expressions without a new constraint — whereas selecting between
// the operands per slot would cost one constraint each and would need a's per-slot
// liveness, which is deliberately not carried here.
func mergePackedPair(api frontend.API, a, b packedList) packedList {
	outCap := len(a.vals) + len(b.vals)

	// shiftRight allocates its result, so overlaying a in place is safe.
	vals := shiftRight(api, [][]frontend.Variable{b.vals}, outCap, a.count, bitsFor(len(a.vals)))[0]
	for j, v := range a.vals {
		vals[j] = api.Add(v, vals[j])
	}
	return packedList{vals: vals, count: api.Add(a.count, b.count)}
}

// thermometerFromCount returns the thermometer encoding of `count` over n slots:
// flags[i] == 1 iff i < count.
//
// A binary decoder over the bits of `count` yields a one-hot vector, and the thermometer is
// its suffix sum, which is a free linear combination. Cost is ~2^bitsFor(n) multiplications,
// paid once per reduction.
//
// Only one-hot positions up to n are summed, which is exact because `count` is a sum of
// constrained 0/1 flags over at most n slots (newPrefixPackedList) or a sum of such counts
// whose capacities add up (mergePackedPair), so count <= n holds by construction. A count
// above n would silently zero every flag rather than fail.
func thermometerFromCount(api frontend.API, count frontend.Variable, n int) []frontend.Variable {
	bitsLE := api.ToBinary(count, bitsFor(n))

	oneHot := []frontend.Variable{1}
	for t := range bitsLE {
		next := make([]frontend.Variable, 2*len(oneHot))
		for i, v := range oneHot {
			hi := api.Mul(v, bitsLE[t])
			next[i] = api.Sub(v, hi)
			next[i+len(oneHot)] = hi
		}
		oneHot = next
	}

	flags := make([]frontend.Variable, n)
	suffix := frontend.Variable(0)
	for i := n; i >= 1; i-- {
		if i < len(oneHot) {
			suffix = api.Add(suffix, oneHot[i])
		}
		flags[i-1] = suffix
	}
	return flags
}

// shiftRight moves each input array right by `amount` inside a zero-padded window of
// `outCap` entries: out[j] = in[j-amount] when 0 <= j-amount < len(in), else 0.
//
// It is a barrel shifter over the bits of `amount`, costing outCap*amountBits selects per
// array. All arrays share one bit decomposition, so shifting values and flags together is
// cheaper than two independent calls. `amount` must fit in `amountBits` bits; ToBinary
// enforces that.
func shiftRight(
	api frontend.API,
	ins [][]frontend.Variable,
	outCap int,
	amount frontend.Variable,
	amountBits int,
) [][]frontend.Variable {
	cur := make([][]frontend.Variable, len(ins))
	for k, in := range ins {
		cur[k] = make([]frontend.Variable, outCap)
		for j := 0; j < outCap; j++ {
			if j < len(in) {
				cur[k][j] = in[j]
			} else {
				cur[k][j] = 0
			}
		}
	}
	if amountBits == 0 {
		return cur
	}

	amountBitsLE := api.ToBinary(amount, amountBits)
	for t := 0; t < amountBits; t++ {
		step := 1 << t
		for k := range cur {
			next := make([]frontend.Variable, outCap)
			for j := 0; j < outCap; j++ {
				var shiftedIn frontend.Variable = 0
				if j-step >= 0 {
					shiftedIn = cur[k][j-step]
				}
				next[j] = api.Select(amountBitsLE[t], shiftedIn, cur[k][j])
			}
			cur[k] = next
		}
	}
	return cur
}

// bitsFor returns the number of bits needed to represent every value in [0, n].
func bitsFor(n int) int { return bits.Len(uint(n)) }

// appendFrontierBatch appends a whole batch of leaves into a frontier-based tree state and
// returns (nextFrontier, nextCount, finalCarry).
//
// It is equivalent to calling `appendFrontier` once per live leaf, in order, as far as the
// observable state goes:
//   - the resulting leaf order is `old leaves || batch.vals[0..batch.count)`,
//   - existing frontier nodes are always the left input of a Poseidon merge,
//   - nextCount == count + batch.count,
//   - finalCarry is the root when the tree ends up exactly full, and
//   - `computeRootFromFrontier(nextFrontier, nextCount, depth)` agrees with the
//     sequential path.
//
// The returned frontier is zero at levels where the corresponding bit of nextCount is
// clear. Those levels are unread by definition, and zeroing them keeps the output a
// function of (leaves, count) alone rather than of leftover intermediate state.
//
// Cost is ~len(batch.vals) + depth Poseidon permutations, against ~len(batch.vals)*depth
// for the sequential path.
//
// Preconditions, both enforced here:
//   - count < 2^depth (the tree has room; a full tree must roll over before appending),
//   - count + batch.count <= 2^depth (the batch does not overflow capacity).
func appendFrontierBatch(
	api frontend.API,
	frontier []frontend.Variable,
	count frontend.Variable,
	batch packedList,
	depth int,
) ([]frontend.Variable, frontend.Variable, frontend.Variable) {
	if depth <= 0 {
		panic("appendFrontierBatch: depth must be > 0")
	}
	// A depth-d tree holds up to 2^d leaves, and leaf counts travel through the protocol in
	// CountBits-wide slots of the packed counts field, so a full tree is only representable
	// while depth < CountBits. At depth == CountBits the capacity check below also degrades:
	// isLessOrEqualConst short-circuits to a bare range check once the bound reaches
	// 2^CountBits - 1. Fail at compile time rather than ship a circuit whose exactly-full
	// state is unreachable.
	if depth >= CountBits {
		panic("appendFrontierBatch: depth must be < CountBits; leaf counts are encoded in CountBits-wide slots")
	}
	if len(frontier) != depth {
		panic("appendFrontierBatch: frontier length must equal depth")
	}
	if len(batch.vals) == 0 {
		panic("appendFrontierBatch: batch must have capacity >= 1")
	}

	// Decomposing `count` over `depth` bits doubles as the "tree is not already full" check.
	// countBits[l] == 1 means level l of the existing frontier holds a left sibling that the
	// new nodes at that level have to merge with.
	countBits := api.ToBinary(count, depth)

	// Reject a batch that would exceed capacity. `count` is now known to be < 2^depth and
	// batch.count <= len(batch.vals), so the sum cannot wrap the field.
	maxLeaves := uint64(1) << depth
	nextCount := api.Add(count, batch.count)
	AssertIsLessOrEqual(api, nextCount, maxLeaves, CountBits)

	// nextCountBits[l] == 1 means level l of the *result* ends on an unpaired left sibling,
	// i.e. the run at level l has odd length. It needs depth+1 bits because an exactly-full
	// tree has nextCount == 2^depth.
	nextCountBits := api.ToBinary(nextCount, depth+1)

	// Per-slot liveness for the leaf level. Every level below derives its own from this one
	// by inheriting the right child's flag, so this is the only place the encoding is built.
	vals := batch.vals
	flags := thermometerFromCount(api, batch.count, len(batch.vals))
	nextFrontier := make([]frontend.Variable, depth)

	for level := 0; level < depth; level++ {
		n := len(vals)

		// 1. Prepend the existing peak when this level's count bit is set, so that the run of
		//    new nodes starts on an even index and pairs up with the correct siblings. The
		//    peak goes in front, keeping existing nodes to the left of new ones.
		peakVals := make([]frontend.Variable, n+1)
		peakFlags := make([]frontend.Variable, n+1)
		for i := 0; i <= n; i++ {
			shiftedVal, shiftedFlag := frontier[level], frontend.Variable(1)
			if i > 0 {
				shiftedVal, shiftedFlag = vals[i-1], flags[i-1]
			}
			keptVal, keptFlag := frontend.Variable(0), frontend.Variable(0)
			if i < n {
				keptVal, keptFlag = vals[i], flags[i]
			}
			peakVals[i] = api.Select(countBits[level], shiftedVal, keptVal)
			peakFlags[i] = api.Select(countBits[level], shiftedFlag, keptFlag)
		}

		// 2. The run is a prefix, so its last node sits at the single index where the
		//    thermometer flags step from 1 down to 0. That node is unpaired exactly when the
		//    run length is odd, which is exactly nextCountBits[level]; on even-length runs the
		//    same index holds a right child, and the mask drops it.
		lastInRun := frontend.Variable(0)
		for i := 0; i <= n; i++ {
			nextFlag := frontend.Variable(0)
			if i < n {
				nextFlag = peakFlags[i+1]
			}
			isLast := api.Sub(peakFlags[i], nextFlag)
			lastInRun = api.MulAcc(lastInRun, isLast, peakVals[i])
		}
		nextFrontier[level] = api.Mul(nextCountBits[level], lastInRun)

		// 3. Fold adjacent nodes into parents for the next level. Slots past the run hash zero
		//    padding; their parents inherit flag 0 and are never read.
		parents := (n + 1) / 2
		parentVals := make([]frontend.Variable, parents)
		parentFlags := make([]frontend.Variable, parents)
		for i := 0; i < parents; i++ {
			parentVals[i] = Poseidon2T4(api, peakVals[2*i], peakVals[2*i+1])
			// A parent is live only if both of its children are, and the run is a prefix, so
			// the right child's flag decides.
			parentFlags[i] = peakFlags[2*i+1]
		}
		vals, flags = parentVals, parentFlags
	}

	// At level `depth` only index 0 can exist, and it is live exactly when the tree ended up
	// full. `assertFinalState`-style callers select this only in that case; masking keeps it
	// deterministically zero otherwise.
	finalCarry := api.Mul(flags[0], vals[0])
	return nextFrontier, nextCount, finalCarry
}
