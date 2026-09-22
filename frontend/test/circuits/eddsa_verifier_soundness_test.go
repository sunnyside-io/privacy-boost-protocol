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
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	gnarkfrontend "github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"

	circuits "github.com/testinprod-io/privacy-boost-protocol/frontend"
)

type eddsaSoundnessCircuit struct {
	Enabled gnarkfrontend.Variable `gnark:",public"`
	PkX     gnarkfrontend.Variable `gnark:",public"`
	PkY     gnarkfrontend.Variable `gnark:",public"`
	Msg     gnarkfrontend.Variable `gnark:",public"`
	R8X     gnarkfrontend.Variable
	R8Y     gnarkfrontend.Variable
	S       gnarkfrontend.Variable
}

func (c *eddsaSoundnessCircuit) Define(api gnarkfrontend.API) error {
	circuits.VerifyEdDSAIf(
		api,
		circuits.AsBool(c.Enabled),
		circuits.AffinePoint{X: c.PkX, Y: c.PkY},
		circuits.EdDSASignature{
			R8: circuits.AffinePoint{X: c.R8X, Y: c.R8Y},
			S:  c.S,
		},
		c.Msg,
	)
	return nil
}

type zeroScalarDoubleBaseCircuit struct {
	Scalar gnarkfrontend.Variable
}

func (c *zeroScalarDoubleBaseCircuit) Define(api gnarkfrontend.API) error {
	curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}

	baseX, _ := new(big.Int).SetString("15836372343211832006828833031571087401945044377577570170285606102491215895900", 10)
	baseY, _ := new(big.Int).SetString("7801528930831391612913542953849263092120765287178679640990215688947513841260", 10)
	base := twistededwards.Point{X: baseX, Y: baseY}
	identity := twistededwards.Point{X: 0, Y: 1}

	// This is the same complete double-base path used by the verifier. Both
	// scalars are zero, so the result must be the identity without division.
	product := curve.DoubleBaseScalarMul(base, identity, c.Scalar, c.Scalar)

	api.AssertIsEqual(c.Scalar, 0)
	api.AssertIsEqual(product.X, 0)
	api.AssertIsEqual(product.Y, 1)
	return nil
}

func invalidSignatureWitness(enabled int) *eddsaSoundnessCircuit {
	return &eddsaSoundnessCircuit{
		Enabled: enabled,
		PkX:     "15836372343211832006828833031571087401945044377577570170285606102491215895900",
		PkY:     "7801528930831391612913542953849263092120765287178679640990215688947513841260",
		Msg:     42,
		R8X:     0,
		R8Y:     1,
		S:       1,
	}
}

func compiledSoundnessCircuit(t *testing.T) constraint.ConstraintSystem {
	t.Helper()
	ccs, err := gnarkfrontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &eddsaSoundnessCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	return ccs
}

func soundnessWitness(t *testing.T, assignment *eddsaSoundnessCircuit) witness.Witness {
	t.Helper()
	w, err := gnarkfrontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestVerifyEdDSAIfRejectsInvalidSignature(t *testing.T) {
	ccs := compiledSoundnessCircuit(t)
	w := soundnessWitness(t, invalidSignatureWitness(1))
	if err := ccs.IsSolved(w); err == nil {
		t.Fatal("the deliberately invalid signature unexpectedly satisfies the circuit")
	}
}

func TestDoubleBaseScalarMulHandlesZeroScalar(t *testing.T) {
	ccs, err := gnarkfrontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &zeroScalarDoubleBaseCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	w, err := gnarkfrontend.NewWitness(&zeroScalarDoubleBaseCircuit{Scalar: 0}, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := ccs.IsSolved(w); err != nil {
		t.Fatalf("zero scalar multiplication should return the identity: %v", err)
	}
}
