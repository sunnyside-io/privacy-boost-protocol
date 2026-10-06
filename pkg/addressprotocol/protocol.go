package addressprotocol

import (
	"errors"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/ethereum/go-ethereum/common"
)

const (
	AssetFormatV1           = "registry-id-v1"
	AssetFormat             = "erc20-address-v1"
	CiphertextFormat        = "address-v3"
	WitnessSchema           = uint32(1)
	SmallNoteMigration      = uint32(3)
	BulkNoteMigration       = uint32(16)
	MaxTreeNumber           = uint32(32767)
	OutputKeyInfo           = "pb-transfer-output-v3"
	DepositKeyInfo          = "pb-deposit-v3"
	GiftOpeningInfo         = "pb-gift-opening-v2"
	GiftLinkPrefix          = "pbgift:v2:"
	DomainNoteCommitmentV2  = 19
	DomainNullifierV2       = 20
	DomainDepositRequestV2  = 21
	DomainPortalNoteV2      = 22
	DomainPortalRequestV2   = 23
	DomainGiftNullifierV2   = 24
	DomainApprovalDisplayV2 = 25
	DomainAssetSnapshotLeaf = 26
	DomainAssetSnapshotNode = 27
	DomainPortalScopeV2     = 28
)

type Family string

const (
	Epoch         Family = "epoch"
	Deposit       Family = "deposit"
	Portal        Family = "portal"
	Forced        Family = "forced"
	GiftClaim     Family = "gift_claim"
	NoteMigration Family = "note_migration"
)

// Validate rejects circuit families outside the native protocol.
func (f Family) Validate() error {
	switch f {
	case Epoch, Deposit, Portal, Forced, GiftClaim, NoteMigration:
		return nil
	default:
		return errors.New("unknown address circuit family")
	}
}

// TaskType fits the historical queue column while keeping native intake
// distinguishable from legacy families. The full identity is in QueueConfig.
func (f Family) TaskType() string {
	switch f {
	case Epoch:
		return "addr_epoch"
	case Deposit:
		return "addr_dep"
	case Portal:
		return "addr_port"
	case Forced:
		return "addr_force"
	case GiftClaim:
		return "addr_gift"
	case NoteMigration:
		return "note_migv1"
	default:
		return ""
	}
}

// Context binds prepared payloads and worker jobs to one activated deployment.
// Values must be obtained from the pool at a canonical block, not client input.
type Context struct {
	ChainID         uint64         `json:"chainId"`
	Pool            common.Address `swaggertype:"string" json:"poolAddress" pattern:"^0x[0-9a-fA-F]{40}$"`
	ManifestHash    common.Hash    `swaggertype:"string" json:"manifestHash" pattern:"^0x[0-9a-fA-F]{64}$"`
	Snapshot        common.Address `swaggertype:"string" json:"snapshotAddress" pattern:"^0x[0-9a-fA-F]{40}$"`
	SnapshotRoot    common.Hash    `swaggertype:"string" json:"snapshotRoot" pattern:"^0x[0-9a-fA-F]{64}$"`
	FirstNoteTreeV2 uint32         `json:"firstAddressTreeNumber"`
}

// Validate checks deployment identifiers, the canonical snapshot root, and the
// first native tree number. It does not authenticate these values against a chain.
func (c Context) Validate() error {
	if c.ChainID == 0 ||
		c.Pool == (common.Address{}) ||
		c.ManifestHash == (common.Hash{}) ||
		c.Snapshot == (common.Address{}) ||
		c.SnapshotRoot == (common.Hash{}) ||
		c.SnapshotRoot.Big().Cmp(fr.Modulus()) >= 0 ||
		c.FirstNoteTreeV2 == 0 ||
		c.FirstNoteTreeV2 > MaxTreeNumber {
		return errors.New("incomplete address protocol context")
	}

	return nil
}

// Match requires the complete prepared deployment context to remain unchanged.
// A mismatch requires preparing the operation again with the current context.
func (c Context) Match(expected Context) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if c != expected {
		return errors.New("address protocol context changed; reprepare required")
	}

	return nil
}

// NativeTree checks that a tree lies within the activated native range.
func (c Context) NativeTree(tree uint32) bool {
	return c.FirstNoteTreeV2 > 0 && c.FirstNoteTreeV2 <= tree && tree <= MaxTreeNumber
}

// NoteMigrationCapacity selects the smallest supported circuit for 1 to 16 notes.
// The witness builder pads the unused capacity to three or sixteen slots.
func NoteMigrationCapacity(active int) (uint32, error) {
	if active < 1 || active > int(BulkNoteMigration) {
		return 0, errors.New("NoteMigration must contain 1 to 16 notes")
	}
	if active <= int(SmallNoteMigration) {
		return SmallNoteMigration, nil
	}

	return BulkNoteMigration, nil
}

// Shape is part of a key's identity even when public-input lengths coincide.
type Shape struct {
	Family    Family `json:"family"`
	Batch     uint32 `json:"batch"`
	Inputs    uint32 `json:"inputs"`
	Outputs   uint32 `json:"outputs"`
	Depth     uint32 `json:"depth"`
	AuthDepth uint32 `json:"authDepth"`
	FeeTokens uint32 `json:"feeTokens"`
}

// Validate enforces each family's supported dimensions and requires unused
// dimensions to be zero so equivalent circuits cannot acquire different identities.
func (s Shape) Validate() error {
	if err := s.Family.Validate(); err != nil {
		return err
	}
	if s.Batch == 0 || s.Batch > 65535 || s.Depth == 0 || s.Depth > 24 || s.AuthDepth > 20 || s.FeeTokens > 4 {
		return errors.New("invalid address circuit dimensions")
	}
	if s.Family == Epoch && (s.Inputs == 0 || s.Inputs > 255 || s.Outputs == 0 || s.Outputs > 255 || s.AuthDepth == 0 || s.FeeTokens == 0) {
		return errors.New("invalid address epoch dimensions")
	}
	if (s.Family == Forced || s.Family == GiftClaim) && s.AuthDepth == 0 {
		return errors.New("missing authorization depth")
	}
	if s.Family == Forced && (s.Inputs == 0 || s.Inputs > 255) {
		return errors.New("invalid forced input count")
	}
	if s.Family == NoteMigration && s.Batch != SmallNoteMigration && s.Batch != BulkNoteMigration {
		return errors.New("unsupported NoteMigration capacity")
	}
	if s.Family != Epoch && (s.Outputs != 0 || s.FeeTokens != 0) {
		return errors.New("unused native dimensions must be zero")
	}
	if s.Family != Epoch && s.Family != Forced && s.Inputs != 0 {
		return errors.New("unused input dimension must be zero")
	}
	if (s.Family == Deposit || s.Family == Portal || s.Family == NoteMigration) && s.AuthDepth != 0 {
		return errors.New("unused authorization dimension must be zero")
	}
	if s.Family == Forced && s.Batch != 1 {
		return errors.New("forced withdrawals are not batched")
	}

	return nil
}

// PublicInputs returns the flattened public-input count for a validated shape,
// excluding the constant-one wire used by the verifier's IC vector.
func (s Shape) PublicInputs() (uint32, error) {
	if err := s.Validate(); err != nil {
		return 0, err
	}

	switch s.Family {
	case Epoch:
		// The fixed 41 covers the note roots, their packed tree numbers, the proving timestamp,
		// the active tree selector and root, the packed counts, the new root, the auth roots and
		// their packed tree numbers, and the two fee-transfer digest halves. The fee recipient's
		// note public key is a private witness, so it is deliberately not counted here.
		return 41 + s.Batch*(s.Inputs+s.Outputs+2) + s.FeeTokens + (s.Batch+127)/128, nil
	case Deposit:
		return 26 + 4*s.Batch, nil
	case Portal:
		return 25 + 6*s.Batch, nil
	case Forced:
		// The trailing constant carries the note-format selector alongside the roots, auth and payout
		// fields, so one relation serves both the native and the pre-migration note formats.
		return 27 + 2*s.Inputs, nil
	case GiftClaim:
		return 43 + 7*s.Batch, nil
	case NoteMigration:
		return 25 + 2*s.Batch, nil
	default:
		return 0, fmt.Errorf("unsupported family %q", s.Family)
	}
}
