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

// FixedMerkleProof verifies a fixed-depth binary merkle proof (Poseidon2T4 hash2 mode).
type FixedMerkleProof struct {
	Depth        int
	Leaf         frontend.Variable
	LeafIndex    frontend.Variable
	PathElements []frontend.Variable
	Root         frontend.Variable `gnark:",public"`
}

func (c *FixedMerkleProof) Define(api frontend.API) error {
	bits := api.ToBinary(c.LeafIndex, c.Depth)
	current := c.Leaf
	for i := 0; i < c.Depth; i++ {
		sibling := c.PathElements[i]
		bit := bits[i]
		left := api.Select(bit, sibling, current)
		right := api.Select(bit, current, sibling)
		current = Poseidon2T4(api, left, right)
	}
	api.AssertIsEqual(current, c.Root)
	return nil
}
