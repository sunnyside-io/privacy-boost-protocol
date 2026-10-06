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

// =============================================================================
// Bool
// =============================================================================
//
// This file provides a small Go-level wrapper around `frontend.Variable` to represent booleans.
//
// Notes:
// - This is a readability/safety helper only. In the constraint system, it's still a field element.
// - Bool operations (Not/And/Or/Select) assume inputs are boolean unless otherwise stated.
// - Use `AssertIsBool` when you need to enforce the 0/1 invariant.
type Bool struct {
	v frontend.Variable
}

// =============================================================================
// Constructors and accessors
// =============================================================================

// AsBool wraps a variable that is expected to be boolean (0/1).
//
// This does not add constraints; call `AssertIsBool` when you need enforcement.
func AsBool(v frontend.Variable) Bool { return Bool{v: v} }

// AsField returns the underlying field element.
func (b Bool) AsField() frontend.Variable { return b.v }

// True returns the constant 1 as Bool.
func True() Bool { return AsBool(1) }

// False returns the constant 0 as Bool.
func False() Bool { return AsBool(0) }

// =============================================================================
// Assertions
// =============================================================================

// AssertIsBool enforces b is boolean (0/1).
func AssertIsBool(api frontend.API, b Bool) {
	// A simple range check to 1 bit.
	AssertIsNBits(api, b.v, BoolBits)
}

// =============================================================================
// Boolean algebra
// =============================================================================

// Not returns (1 - b).
func Not(api frontend.API, b Bool) Bool {
	return AsBool(api.Sub(1, b.v))
}

// And returns (a * b).
func And(api frontend.API, a, b Bool) Bool {
	return AsBool(api.Mul(a.v, b.v))
}

// Or returns a + b - a*b.
func Or(api frontend.API, a, b Bool) Bool {
	return AsBool(api.Sub(api.Add(a.v, b.v), api.Mul(a.v, b.v)))
}

// =============================================================================
// Conditional selection
// =============================================================================

// Select returns (cond ? whenTrue : whenFalse).
func Select(api frontend.API, cond Bool, whenTrue, whenFalse frontend.Variable) frontend.Variable {
	return api.Select(cond.v, whenTrue, whenFalse)
}
