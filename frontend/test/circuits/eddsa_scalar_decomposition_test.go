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

package frontend_test

import (
	"fmt"
	"math/big"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/constraint/solver"
	gnarkfrontend "github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/stretchr/testify/require"
)

// doubleBaseScalarMulCircuit is the smallest circuit that reaches the gadget path
// the EdDSA verifier builds its whole left-hand side from: one complete
// double-base multiplication over a real base point and a negated second base.
//
// The second scalar is a compile-time constant, so the circuit holds exactly one
// hinted full-width scalar decomposition and the overrides below target it
// without ambiguity. Nothing constrains the product's coordinates, only that it
// stays on the curve, which every complete-path result satisfies. That is
// deliberate: a value assertion would reject a wrong product on its own account
// and would hide whether the decomposition bound is still doing any work.
type doubleBaseScalarMulCircuit struct {
	Scalar gnarkfrontend.Variable
}

func (c *doubleBaseScalarMulCircuit) Define(api gnarkfrontend.API) error {
	curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}

	baseX, _ := new(big.Int).SetString("15836372343211832006828833031571087401945044377577570170285606102491215895900", 10)
	baseY, _ := new(big.Int).SetString("7801528930831391612913542953849263092120765287178679640990215688947513841260", 10)
	base := twistededwards.Point{X: baseX, Y: baseY}

	product := curve.DoubleBaseScalarMul(base, curve.Neg(base), c.Scalar, 0)
	curve.AssertIsOnCurve(product)
	return nil
}

// fullWidthBitDecompositionHint locates the hint api.ToBinary calls. The gadget
// does not export it, so name matching is the only handle and the match must be
// re-checked on a gnark upgrade. A miss fails the test rather than leaving an
// override silently attached to nothing.
func fullWidthBitDecompositionHint(t *testing.T) solver.HintID {
	t.Helper()
	for _, hint := range solver.GetRegisteredHints() {
		name := solver.GetHintName(hint)
		if strings.Contains(name, "/std/math/bits.") && strings.HasSuffix(name, "nBits") {
			return solver.GetHintID(hint)
		}
	}
	t.Fatal("gnark's bit-decomposition hint is not registered, so an override would assert nothing")
	return 0
}

// decompositionOverride decomposes scalar + offset rather than scalar. At offset
// zero it reproduces the honest hint, which is what makes it usable as the
// control that the override plumbing does not itself break a solve. At offset
// equal to the field modulus it emits a non-canonical representation of the same
// field element.
//
// The counters exist because a shape drift in the upstream hint would make the
// substitution return an error, the solve would then fail for that reason
// instead, and the rejection assertion would pass without ever reaching the
// bound it exists to check.
type decompositionOverride struct {
	modulus   *big.Int
	offset    *big.Int
	calls     atomic.Int64
	shapeErrs atomic.Int64
}

func (d *decompositionOverride) hint(_ *big.Int, inputs, outputs []*big.Int) error {
	d.calls.Add(1)
	if len(inputs) != 1 || len(outputs) != d.modulus.BitLen() {
		d.shapeErrs.Add(1)
		return fmt.Errorf("bit-decomposition hint changed shape: %d inputs, %d outputs", len(inputs), len(outputs))
	}
	shifted := new(big.Int).Add(inputs[0], d.offset)
	if shifted.BitLen() > len(outputs) {
		d.shapeErrs.Add(1)
		return fmt.Errorf("scalar has no %d-bit representation at this offset", len(outputs))
	}
	for i := range outputs {
		outputs[i].SetUint64(uint64(shifted.Bit(i)))
	}
	return nil
}

func (d *decompositionOverride) option(t *testing.T) solver.Option {
	t.Helper()
	return solver.OverrideHint(fullWidthBitDecompositionHint(t), d.hint)
}

func (d *decompositionOverride) requireExercised(t *testing.T) {
	t.Helper()
	require.Positive(t, d.calls.Load(), "the override never ran, so it decided nothing about this solve")
	require.Zero(t, d.shapeErrs.Load(),
		"the override rejected the hint's shape rather than substituting bits, so the bound was never exercised")
}

// TestDoubleBaseScalarMulRejectsNonCanonicalScalarBits pins the upstream property
// the rearranged EdDSA verifier now depends on for soundness.
//
// The verifier's left-hand side comes from one complete DoubleBaseScalarMul,
// which begins by decomposing each scalar with api.ToBinary at the full field
// width. The recomposition constraint alone does not pin those bits: for any
// value below 2^254 - r the bits of v and the bits of v + r both sum to v in the
// field, while [v]P and [v+r]P are different curve points because r is not a
// multiple of the BabyJubJub subgroup order. What separates them is the
// reducedness check gnark adds when the requested width equals the field width.
// Were that check to go, a prover could witness the Poseidon challenge plus r
// and have the signature equation evaluated at the wrong point with nothing else
// objecting.
//
// A hint override is the only way to reach that state from a test, since the
// honest hint always returns the canonical decomposition. Two controls make the
// rejection meaningful: the plain solve proves the witness is valid, and the
// zero-offset override proves that attaching an override does not by itself
// break a solve, so the failure at full offset is caused by the substituted bits
// and by nothing else.
func TestDoubleBaseScalarMulRejectsNonCanonicalScalarBits(t *testing.T) {
	modulus := ecc.BN254.ScalarField()
	scalar := big.NewInt(1)

	// The alternative representation has to exist for the substitution to mean
	// anything, and it stops existing once the scalar passes 2^254 - r.
	require.LessOrEqualf(t, new(big.Int).Add(scalar, modulus).BitLen(), modulus.BitLen(),
		"scalar %s has no non-canonical %d-bit representation, so this test would pass vacuously",
		scalar, modulus.BitLen())

	ccs, err := gnarkfrontend.Compile(modulus, r1cs.NewBuilder, &doubleBaseScalarMulCircuit{})
	require.NoError(t, err)

	witness, err := gnarkfrontend.NewWitness(&doubleBaseScalarMulCircuit{Scalar: scalar}, modulus)
	require.NoError(t, err)

	require.NoError(t, ccs.IsSolved(witness), "the canonical decomposition must satisfy the circuit")

	canonical := &decompositionOverride{modulus: modulus, offset: new(big.Int)}
	require.NoError(t, ccs.IsSolved(witness, canonical.option(t)),
		"an override that reproduces the canonical bits must still solve, otherwise the rejection below proves nothing")
	canonical.requireExercised(t)

	nonCanonical := &decompositionOverride{modulus: modulus, offset: modulus}
	require.Error(t, ccs.IsSolved(witness, nonCanonical.option(t)),
		"a non-canonical scalar decomposition satisfied the double-base multiplication, "+
			"so the reducedness bound api.ToBinary relies on is gone")
	nonCanonical.requireExercised(t)
}
