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
// White-box test surface
// =============================================================================
//
// The circuit test suite lives in frontend/test/circuits/ as an external test
// package, so it cannot reach package-internal gadgets by name. Every identifier
// below is a thin alias or a one-line forwarder over an internal helper, added so
// those tests can exercise the gadgets directly instead of reaching the same code
// through a whole circuit.
//
// Nothing here carries logic of its own. A reviewer only has to confirm that each
// forwarder passes its arguments straight through, because any behaviour change
// would have to happen in the internal helper it calls, not in this file.

// Poseidon domain separators, exposed so the domain-separation tests can assert the
// exact field element each hash family prepends. The values live in constants.go.
var (
	DomainAccountId       = domainAccountId
	DomainApprovalDisplay = domainApprovalDisplay
	DomainApprovalLeaf    = domainApprovalLeaf
	DomainApprove         = domainApprove
	DomainApproveCommit   = domainApproveCommit
	DomainDepositRequest  = domainDepositRequest
	DomainGiftBind        = domainGiftBind
	DomainGiftNullifier   = domainGiftNullifier
	DomainGiftRefund      = domainGiftRefund
	DomainGiftSecret      = domainGiftSecret
	DomainMPK             = domainMPK
	DomainNoteCommitment  = domainNoteCommitment
	DomainNotePublicKey   = domainNotePublicKey
	DomainNullifier       = domainNullifier
	DomainPortalBind      = domainPortalBind
	DomainPortalNote      = domainPortalNote
	DomainPortalRequest   = domainPortalRequest
	DomainRegLeaf         = domainRegLeaf
	DomainRegNode         = domainRegNode

	DomainApprovalDisplayV2 = domainApprovalDisplayV2
	DomainAssetSnapshotLeaf = domainAssetSnapshotLeaf
	DomainAssetSnapshotNode = domainAssetSnapshotNode
	DomainDepositRequestV2  = domainDepositRequestV2
	DomainGiftNullifierV2   = domainGiftNullifierV2
	DomainNoteCommitmentV2  = domainNoteCommitmentV2
	DomainNullifierV2       = domainNullifierV2
	DomainPortalNoteV2      = domainPortalNoteV2
	DomainPortalScopeV2     = domainPortalScopeV2
	DomainPortalRequestV2   = domainPortalRequestV2
)

// PackedList aliases the internal packed-list type. An alias rather than a defined
// type, so a value produced by any forwarder below is the same type the internal
// gadgets consume and no conversion is needed at the boundary.
type PackedList = packedList

// NewPackedList builds a packed list from an explicit value slice and live count.
// The batch-append tests need this to construct adversarial shapes (gapped flags,
// over-long counts) that no production caller would ever produce, which is exactly
// what the internal prefix and merge constructors are designed to reject.
func NewPackedList(vals []frontend.Variable, count frontend.Variable) PackedList {
	return packedList{vals: vals, count: count}
}

// NewPrefixPackedList forwards to the prefix constructor used by every production
// caller, where slot j is live iff j is below the group's count.
func NewPrefixPackedList(api frontend.API, vals []frontend.Variable, active []Bool) PackedList {
	return newPrefixPackedList(api, vals, active)
}

// MergePackedLists forwards to the order-preserving concatenation of packed lists.
func MergePackedLists(api frontend.API, lists []PackedList) PackedList {
	return mergePackedLists(api, lists)
}

// AppendFrontier forwards to the single-leaf frontier append.
func AppendFrontier(
	api frontend.API,
	frontier []frontend.Variable,
	count frontend.Variable,
	leaf frontend.Variable,
	depth int,
) ([]frontend.Variable, frontend.Variable, frontend.Variable) {
	return appendFrontier(api, frontier, count, leaf, depth)
}

// AppendFrontierBatch forwards to the batched frontier append. The comparison tests
// drive this against a loop of AppendFrontier calls to prove the two agree.
func AppendFrontierBatch(
	api frontend.API,
	frontier []frontend.Variable,
	count frontend.Variable,
	batch PackedList,
	depth int,
) ([]frontend.Variable, frontend.Variable, frontend.Variable) {
	return appendFrontierBatch(api, frontier, count, batch, depth)
}

// ComputeRootFromFrontier forwards to the frontier-to-root reduction.
func ComputeRootFromFrontier(
	api frontend.API,
	frontier []frontend.Variable,
	count frontend.Variable,
	depth int,
) frontend.Variable {
	return computeRootFromFrontier(api, frontier, count, depth)
}

// IsLessThanConst forwards to the constant-bound comparison gadget.
func IsLessThanConst(api frontend.API, value frontend.Variable, bound uint64, bitLen int) Bool {
	return isLessThanConst(api, value, bound, bitLen)
}

// ValidateNoteFormatContext forwards to the context's own range validation.
func ValidateNoteFormatContext(api frontend.API, context NoteFormatContext) {
	context.validateBoundary(api)
}

// AssertNoteFormatContextV2 forwards to the activation-boundary assertion that
// a native-tree spend must sit at or above the pool's first address tree.
func AssertNoteFormatContextV2(
	api frontend.API,
	context NoteFormatContext,
	active Bool,
	tree frontend.Variable,
) {
	context.assertNative(api, active, tree)
}

// EdDSAScalarTooLargeBit returns the non-canonical-scalar flag the EdDSA verifier
// computes and then constrains to zero. The scalar-bound tests read the bit directly
// so they can assert both outcomes, which is impossible through VerifyEdDSA because
// that path rejects the signature before the bit is observable.
func EdDSAScalarTooLargeBit(
	api frontend.API,
	pk AffinePoint,
	sig EdDSASignature,
	msg frontend.Variable,
) frontend.Variable {
	return computeEdDSAVerifyArtifacts(api, pk, sig, msg).sTooLargeBit
}
