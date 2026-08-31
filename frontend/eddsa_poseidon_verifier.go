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

	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

// =============================================================================
// EdDSA Poseidon verification
// =============================================================================
//
// This file provides a small, self-contained helper for verifying EdDSA signatures in-circuit.
//
// Overview:
// - `VerifyEdDSA` enforces verification unconditionally.
// - `VerifyEdDSAIf` enforces verification only when `enabled == 1` (gated constraints).
//
// Notes:
// - These helpers exist for readability at call sites; they do not change the underlying constraints
//   compared to inlining the same operations.
// - This verifier targets the BN254 BabyJubJub twisted Edwards curve and uses Poseidon for hashing.

// AffinePoint is a small wrapper for curve points represented as (X, Y) field elements.
// This improves readability compared to passing x/y as separate parameters.
type AffinePoint struct {
	X frontend.Variable
	Y frontend.Variable
}

// EdDSASignature represents an EdDSA signature (R8 point and scalar S).
type EdDSASignature struct {
	R8 AffinePoint
	S  frontend.Variable
}

// =============================================================================
// Public API
// =============================================================================

type eddsaVerifyArtifacts struct {
	// sTooLargeBit is 1 if S >= subgroup order, else 0.
	// The verifier enforces this is 0 to reject non-canonical signatures.
	sTooLargeBit frontend.Variable // 1 if S >= subgroup order, 0 otherwise

	// left and right are the two curve points compared by the signature equation:
	// left  = S*B8
	// right = R8 + h*(8*A)
	left  twistededwards.Point
	right twistededwards.Point
}

// VerifyEdDSA verifies an EdDSA Poseidon signature (always enabled).
func VerifyEdDSA(
	api frontend.API,
	pk AffinePoint,
	sig EdDSASignature,
	msg frontend.Variable,
) {
	a := computeEdDSAVerifyArtifacts(api, pk, sig, msg)
	AssertEqual(api, a.sTooLargeBit, 0)
	AssertEqual(api, a.left.X, a.right.X)
	AssertEqual(api, a.left.Y, a.right.Y)
}

// VerifyEdDSAIf verifies an EdDSA Poseidon signature if enabled.
func VerifyEdDSAIf(
	api frontend.API,
	enabled Bool,
	pk AffinePoint,
	sig EdDSASignature,
	msg frontend.Variable,
) {
	a := computeEdDSAVerifyArtifacts(api, pk, sig, msg)
	AssertEqualIf(api, enabled, a.sTooLargeBit, 0)
	AssertEqualIf(api, enabled, a.left.X, a.right.X)
	AssertEqualIf(api, enabled, a.left.Y, a.right.Y)
}

// =============================================================================
// Internal helper
// =============================================================================

func computeEdDSAVerifyArtifacts(
	api frontend.API,
	pk AffinePoint,
	sig EdDSASignature,
	msg frontend.Variable,
) eddsaVerifyArtifacts {
	// Unpack inputs into locals to make subsequent math blocks easier to read.
	ax, ay := pk.X, pk.Y
	r8x, r8y := sig.R8.X, sig.R8.Y
	s := sig.S

	// Construct the BabyJubJub curve gadget (BN254 twisted Edwards).
	curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		// This should never happen with a fixed curve choice; panic keeps call sites clean.
		panic(err)
	}

	// Enforce S < subgroup order using Circom's CompConstant algorithm.
	//
	// Subgroup order constant (BabyJubJub subgroup order):
	// 2736030358979909402780800718157159386076813972158567259200215660948447373041
	subgroupOrder, _ := new(big.Int).SetString("2736030358979909402780800718157159386076813972158567259200215660948447373041", 10)
	maxCanonicalScalar := new(big.Int).Sub(subgroupOrder, big.NewInt(1))

	// Convert S to binary (254 bits for CompConstant).
	sBits := api.ToBinary(s, 254)

	// CompConstant logic:
	// - process 2 bits at a time (127 parts)
	// - each part compares 2 bits of S with 2 bits of the constant
	// - the final MSB indicates whether S >= order (1) or S < order (0)
	var parts []frontend.Variable
	var b, a, e, one128 big.Int
	// b = (1 << 128) - 1
	one128.Lsh(big.NewInt(1), 128)
	b.Sub(&one128, big.NewInt(1))
	a.SetUint64(1) // a = 1
	e.SetUint64(1) // e = 1

	// Process 127 parts (2 bits each, covering 254 bits)
	for i := 0; i < 127; i++ {
		// Extract 2 bits from constant
		clsb := uint(maxCanonicalScalar.Bit(i * 2))
		cmsb := uint(maxCanonicalScalar.Bit(i*2 + 1))

		// Extract 2 bits from S
		slsb := sBits[i*2]
		smsb := sBits[i*2+1]

		// Convert b and a to frontend.Variable (they change each iteration)
		bVar := frontend.Variable(&b)
		aVar := frontend.Variable(&a)

		// Circom's CompConstant logic for the 4 possible constant-bit cases (cmsb, clsb).
		var part frontend.Variable
		if cmsb == 0 && clsb == 0 {
			// parts[i] = -b*smsb*slsb + b*smsb + b*slsb
			part = api.Add(
				api.Mul(api.Neg(bVar), api.Mul(smsb, slsb)),
				api.Add(api.Mul(bVar, smsb), api.Mul(bVar, slsb)),
			)
		} else if cmsb == 0 && clsb == 1 {
			// parts[i] = a*smsb*slsb - a*slsb + b*smsb - a*smsb + a
			part = api.Add(
				api.Sub(api.Mul(aVar, api.Mul(smsb, slsb)), api.Mul(aVar, slsb)),
				api.Add(api.Sub(api.Mul(bVar, smsb), api.Mul(aVar, smsb)), aVar),
			)
		} else if cmsb == 1 && clsb == 0 {
			// parts[i] = b*smsb*slsb - a*smsb + a
			part = api.Add(
				api.Sub(api.Mul(bVar, api.Mul(smsb, slsb)), api.Mul(aVar, smsb)),
				aVar,
			)
		} else { // cmsb == 1 && clsb == 1
			// parts[i] = -a*smsb*slsb + a
			part = api.Add(api.Mul(api.Neg(aVar), api.Mul(smsb, slsb)), aVar)
		}
		parts = append(parts, part)

		// Update b, a, e for next iteration
		b.Sub(&b, &e)
		a.Add(&a, &e)
		e.Lsh(&e, 1) // e = e * 2
	}

	// Sum all parts
	var sum frontend.Variable = 0
	for _, part := range parts {
		sum = api.Add(sum, part)
	}

	// Extract the MSB of the comparison result.
	// CompConstant returns 1 when S is strictly greater than its constant, so
	// comparing against order - 1 rejects every non-canonical scalar S >= order.
	// The call site enforces S < order by constraining sTooLargeBit == 0.
	sumBits := api.ToBinary(sum, 135)
	sTooLargeBit := sumBits[127]

	// Compute h = Poseidon(R8x, R8y, Ax, Ay, M).
	hValue := Poseidon2T4(api, r8x, r8y, ax, ay, msg)

	// Base point B8 (base point * 8) on BabyJubJub.
	// Calculated from actual curve base point * 8
	// B8 = (15836372343211832006828833031571087401945044377577570170285606102491215895900,
	//       7801528930831391612913542953849263092120765287178679640990215688947513841260)
	B8x, _ := new(big.Int).SetString("15836372343211832006828833031571087401945044377577570170285606102491215895900", 10)
	B8y, _ := new(big.Int).SetString("7801528930831391612913542953849263092120765287178679640990215688947513841260", 10)
	B8 := twistededwards.Point{X: frontend.Variable(B8x), Y: frontend.Variable(B8y)}

	// Public key point A
	A := twistededwards.Point{X: ax, Y: ay}

	// Signature R8 point
	R8 := twistededwards.Point{X: r8x, Y: r8y}

	// Constrain pk and sig.R8 to lie on BabyJubJub before any arithmetic.
	curve.AssertIsOnCurve(A)
	curve.AssertIsOnCurve(R8)

	// Calculate A8 = 8*A by doubling 3 times
	A8 := A
	for i := 0; i < 3; i++ {
		A8 = curve.Double(A8)
	}

	// Verify signature equation: S*B8 == R8 + h*(8*A).
	hA8 := curve.ScalarMul(A8, hValue)
	curve.AssertIsOnCurve(hA8)
	right := curve.Add(R8, hA8)

	// Calculate left = S*B8
	left := curve.ScalarMul(B8, s)
	curve.AssertIsOnCurve(left)

	return eddsaVerifyArtifacts{
		sTooLargeBit: sTooLargeBit,
		left:         left,
		right:        right,
	}
}
