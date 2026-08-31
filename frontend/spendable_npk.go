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
// Spendable note public key range
// =============================================================================
//
// A withdrawal marker is Poseidon(domainNote, uint160(to), tokenId, amount): the same hash, the
// same domain, and the same field ordering an ordinary note commitment uses, with the recipient
// address sitting where a note public key would sit. Anything that can prove knowledge of a note
// opening for a marker can therefore spend value the pool has already paid out publicly.
//
// The separation enforced here is a range, not a new domain: a spendable note public key must lie
// at or above 2^ReservedNPKBits, which is exactly the range an address-shaped marker key can never
// reach. Keeping the marker formula untouched preserves every deployed root, every signed
// withdrawal request, and the contract's marker equality checks.
//
// The residual assumption is that no honest note public key lands in the reserved range. NPKs are
// Poseidon outputs, so that happens with probability near 2^-94 per note. That is not an
// asset-conservation invariant on its own, which is why the reserved range is enforced rather than
// relied upon, and why the cutover scans decryptable notes before deployment.
//
// Where the range is enforced, and where it deliberately is not
//
// Every spend relation refuses a reserved-range key, so no marker can ever be opened as a note:
// the epoch circuit's assertInputNotes, the forced-withdrawal circuit's processInputs, and the
// gift-claim circuit's processClaim. That is the property the pool's solvency rests on and it
// holds without exception.
//
// Every creation site where a caller rather than the circuit chooses the key refuses it too, so a
// recipient cannot be handed a commitment no spend relation will open. The epoch fee key is a
// public input the operator chooses, refused once per batch in processFeeCommitments. Epoch
// transfer outputs are chosen by the sender for the recipient, refused per slot in
// assertOutputNotes. Deposit credits are chosen by the depositor, refused per slot in
// processCommitments. The gateway receipt key arrives in calldata, refused on chain in LibGateway
// against SPENDABLE_NPK_FLOOR before the pool builds the commitment.
//
// Two sites remain unrefused, both because the key cannot reach the range rather than because the
// check is unaffordable. The portal credit hashes it in-circuit as
// Poseidon(domainNote, recipientMPK, noteRnd), and the gift-claim mint hashes it as
// Poseidon(domainNote, mintMPK, outputNoteRnd). No witness places a Poseidon output below 2^160
// without a preimage break, so a range check there constrains nothing an adversary controls.
//
// One slot is exempt for a third reason, and a reader must not generalise from it: output zero of
// an epoch withdrawal is the public payout marker, not a note. Its key position holds the recipient
// address, so it is always inside the reserved range by construction, and treeLeavesForTransfer
// drops it before the tree append. Refusing it would break every withdrawal.
//
// The per-slot refusals are not free. A full-width decomposition costs about 512 constraints, and
// the ceremony pins one phase-1 ptau per power of two, so six production shapes were resized to
// stay inside the powers already pinned: the 2-in-2-out epoch batch drops from 6 to 5 and from 26
// to 25, the widest-output rungs narrow, and the deposit rungs shrink. The two constraint budget
// tests carry the measured counts, and `go run ./tools/constraintprobe` reproduces them. Any
// future change to a per-slot cost has to be re-fitted the same way rather than resolved by
// dropping a guard.

// isSpendableNPK reports whether npk lies at or above 2^ReservedNPKBits.
//
// The decomposition is taken at the full field width so gnark emits its reducedness check
// alongside the recomposition constraint. That check is load-bearing here rather than defensive:
// without it a prover could answer the bit hint with the non-canonical representation npk + p of a
// reserved-range value, which recomposes to the same field element while setting high bits, and
// the predicate below would accept the very key it exists to reject.
func isSpendableNPK(api frontend.API, npk frontend.Variable) Bool {
	bits := api.ToBinary(npk, ScalarFieldBits)

	// At most ScalarFieldBits-ReservedNPKBits boolean terms, so the sum cannot wrap the field and
	// is zero exactly when every high bit is zero.
	highBitSum := frontend.Variable(0)
	for i := ReservedNPKBits; i < ScalarFieldBits; i++ {
		highBitSum = api.Add(highBitSum, bits[i])
	}
	return isNonZero(api, highBitSum)
}

// AssertSpendableNPK rejects a note public key inside the reserved low range unconditionally. Use
// this where the key exists on every satisfying witness, so that no gate can later be relaxed and
// silently turn the check off.
func AssertSpendableNPK(api frontend.API, npk frontend.Variable) {
	AssertIsTrue(api, isSpendableNPK(api, npk))
}

// AssertSpendableNPKIf rejects a note public key inside the reserved low range when enabled is
// true. Inactive slots stay unconstrained so padding witnesses (whose NPK is derived from zero
// randomness and can legitimately be anything) do not have to satisfy the range.
func AssertSpendableNPKIf(api frontend.API, enabled Bool, npk frontend.Variable) {
	AssertIsTrueIf(api, enabled, isSpendableNPK(api, npk))
}
