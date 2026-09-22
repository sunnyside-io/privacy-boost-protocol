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
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	gnarkfrontend "github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/stretchr/testify/require"

	circuits "github.com/testinprod-io/privacy-boost-protocol/frontend"
)

// TestProductionCircuitsCompileWithoutGroth16Commitments pins the proof format that
// every deployed verifier contract and the proof serializer expect.
//
// A Groth16 proof carries eight field coordinates. When a circuit declares a
// commitment, gnark adds a ninth and tenth group element plus a knowledge-of-opening
// element, and the verifying key gains a commitment key, so both the Solidity verifier
// and the calldata encoder would have to change. Nothing in this protocol wants a
// commitment, but one can appear without any deliberate call: gnark's emulated field
// arithmetic registers range checks that are implemented as a commitment, so simply
// routing a scalar multiplication through a gadget that decomposes its scalar in an
// emulated field is enough to produce one.
//
// The signature verifier therefore uses the complete double-base multiplication rather
// than the single-base gadget. This test is the standing check that the choice survives
// dependency upgrades, since a change of upstream default would otherwise surface only
// as a rejected proof against the deployed verifier.
//
// Batch-one shapes are enough because the property is a property of the gadgets a
// circuit family instantiates, not of how many slots it repeats them across, and the
// batch-one shapes compile in well under a second each.
func TestProductionCircuitsCompileWithoutGroth16Commitments(t *testing.T) {
	for _, tc := range []struct {
		name    string
		circuit gnarkfrontend.Circuit
	}{
		{name: "epoch", circuit: circuits.NewEpochCircuit(1, 2, 2, 24, 20, 4, 16, 16)},
		{name: "deposit", circuit: circuits.NewDepositEpochCircuit(1, 24, 16)},
		{name: "portal", circuit: circuits.NewDepositPortalCircuit(1, 24, 16)},
		{name: "gift_claim", circuit: circuits.NewGiftClaimCircuit(1, 24, 16, 16, 20)},
		{name: "forced", circuit: circuits.NewForcedWithdrawCircuit(1, 24, 20, 16, 16)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ccs, err := gnarkfrontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, tc.circuit)
			require.NoError(t, err)

			commitments, ok := ccs.GetCommitments().(constraint.Groth16Commitments)
			require.Truef(t, ok, "expected Groth16 commitment info, got %T", ccs.GetCommitments())
			require.Emptyf(t, commitments,
				"%s compiled with %d Groth16 commitment(s), which the deployed eight-coordinate "+
					"verifier and the proof serializer cannot consume", tc.name, len(commitments))
		})
	}
}
