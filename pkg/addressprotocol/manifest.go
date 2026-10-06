package addressprotocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const CompilerVersion uint32 = 17

// Artifact hashes pin the exact serialized CCS, proving key and verifying key.
// Equal dimensions or IC lengths do not authorize another artifact.
type Artifact struct {
	Shape           Shape       `json:"shape"`
	WitnessSchema   uint32      `json:"witnessSchema"`
	CompilerVersion uint32      `json:"compilerVersion"`
	PublicInputs    uint32      `json:"publicInputs"`
	CCSHash         common.Hash `swaggertype:"string" json:"ccsSha256" pattern:"^0x[0-9a-fA-F]{64}$"`
	PKHash          common.Hash `swaggertype:"string" json:"pkSha256" pattern:"^0x[0-9a-fA-F]{64}$"`
	VKHash          common.Hash `swaggertype:"string" json:"vkSha256" pattern:"^0x[0-9a-fA-F]{64}$"`
}

// Validate checks shape-derived input counts, supported versions, and nonzero
// artifact hashes. File contents are verified when the artifacts are loaded.
func (a Artifact) Validate() error {
	n, err := a.Shape.PublicInputs()
	if err != nil {
		return err
	}
	if a.WitnessSchema != WitnessSchema ||
		a.CompilerVersion != CompilerVersion ||
		a.PublicInputs != n ||
		a.CCSHash == (common.Hash{}) ||
		a.PKHash == (common.Hash{}) ||
		a.VKHash == (common.Hash{}) {
		return errors.New("unsupported or incomplete address circuit artifact")
	}

	return nil
}

// Key names include every dimension, even dimensions not represented by IC length.
func (s Shape) Key() string {
	return fmt.Sprintf(
		"address_%s_b%d_i%d_o%d_d%d_a%d_f%d",
		s.Family,
		s.Batch,
		s.Inputs,
		s.Outputs,
		s.Depth,
		s.AuthDepth,
		s.FeeTokens,
	)
}

// QueueConfig includes the entire deployment identity to keep stale workers
// from claiming jobs for a different upgrade with dimension-compatible keys.
func QueueConfig(context Context, shape Shape) string {
	return fmt.Sprintf("address_v%d_%x_%s", WitnessSchema, context.ManifestHash[:], shape.Key())
}

// Manifest binds a deployment and its sealed asset snapshot to exact circuit artifacts.
type Manifest struct {
	Schema          uint32         `json:"schema"`
	ChainID         uint64         `json:"chainId"`
	Pool            common.Address `swaggertype:"string" json:"poolAddress" pattern:"^0x[0-9a-fA-F]{40}$"`
	Snapshot        common.Address `swaggertype:"string" json:"snapshotAddress" pattern:"^0x[0-9a-fA-F]{40}$"`
	SnapshotRoot    common.Hash    `swaggertype:"string" json:"snapshotRoot" pattern:"^0x[0-9a-fA-F]{64}$"`
	FirstNoteTreeV2 uint32         `json:"firstAddressTreeNumber"`
	Artifacts       []Artifact     `json:"artifacts"`
}

// Validate checks the deployment fields and unique artifact shapes. It accepts
// partial worker manifests; ValidateRollout enforces deployment-wide coverage.
func (m Manifest) Validate() error {
	// Validate deployment fields before the manifest has a computed hash.
	c := m.context(common.HexToHash("0x1"))
	if m.Schema != 1 || len(m.Artifacts) == 0 || len(m.Artifacts) > 1024 || c.Validate() != nil {
		return errors.New("invalid address protocol manifest")
	}

	seen := make(map[Shape]bool)
	for _, a := range m.Artifacts {
		if err := a.Validate(); err != nil {
			return err
		}
		if seen[a.Shape] {
			return errors.New("duplicate circuit shape in manifest")
		}

		seen[a.Shape] = true
	}

	return nil
}

// ValidateRollout additionally requires all families and both chosen NoteMigration
// capacities. A partial worker manifest may validate without being deployable.
func (m Manifest) ValidateRollout() error {
	if err := m.Validate(); err != nil {
		return err
	}

	families := make(map[Family]bool)
	migrations := make(map[uint32]bool)
	publicGift := false
	for _, a := range m.Artifacts {
		families[a.Shape.Family] = true
		if a.Shape.Family == GiftClaim && a.Shape.Batch == 1 {
			publicGift = true
		}
		if a.Shape.Family == NoteMigration {
			migrations[a.Shape.Batch] = true
		}
	}

	for _, f := range []Family{Epoch, Deposit, Portal, Forced, GiftClaim, NoteMigration} {
		if !families[f] {
			return fmt.Errorf("manifest missing %s family", f)
		}
	}
	if !migrations[SmallNoteMigration] || !migrations[BulkNoteMigration] {
		return errors.New("rollout requires NoteMigration capacities 3 and 16")
	}
	if !publicGift {
		return errors.New("rollout requires single-slot public gift recovery")
	}

	return nil
}

func (m Manifest) context(hash common.Hash) Context {
	return Context{
		ChainID:         m.ChainID,
		Pool:            m.Pool,
		Snapshot:        m.Snapshot,
		SnapshotRoot:    m.SnapshotRoot,
		FirstNoteTreeV2: m.FirstNoteTreeV2,
		ManifestHash:    hash,
	}
}

// Hash uses an explicit binary encoding shared with the SDK. All integers are
// big-endian, family codes are fixed (not string/enum ordinals), and artifacts
// are sorted by Shape.Key. It is independent of JSON whitespace and field order.
func (m Manifest) Hash() (common.Hash, error) {
	if err := m.Validate(); err != nil {
		return common.Hash{}, err
	}

	var b bytes.Buffer
	b.WriteString("PB:ADDRESS_MANIFEST:v1")
	b.Write(binary.BigEndian.AppendUint32(nil, m.Schema))
	b.Write(binary.BigEndian.AppendUint64(nil, m.ChainID))
	b.Write(m.Pool[:])
	b.Write(m.Snapshot[:])
	b.Write(m.SnapshotRoot[:])
	b.Write(binary.BigEndian.AppendUint32(nil, m.FirstNoteTreeV2))
	b.Write(binary.BigEndian.AppendUint32(nil, uint32(len(m.Artifacts))))

	// Canonicalize artifact order without mutating the caller's manifest.
	as := append([]Artifact(nil), m.Artifacts...)
	sort.Slice(as, func(i, j int) bool { return as[i].Shape.Key() < as[j].Shape.Key() })
	codes := map[Family]uint32{Epoch: 1, Deposit: 2, Portal: 3, Forced: 4, GiftClaim: 5, NoteMigration: 6}
	for _, a := range as {
		s := a.Shape
		for _, v := range []uint32{
			codes[s.Family],
			s.Batch,
			s.Inputs,
			s.Outputs,
			s.Depth,
			s.AuthDepth,
			s.FeeTokens,
			a.WitnessSchema,
			a.CompilerVersion,
			a.PublicInputs,
		} {
			b.Write(binary.BigEndian.AppendUint32(nil, v))
		}

		b.Write(a.CCSHash[:])
		b.Write(a.PKHash[:])
		b.Write(a.VKHash[:])
	}

	return crypto.Keccak256Hash(b.Bytes()), nil
}

// Context derives the deployment identity using the validated manifest's
// canonical binary hash, independent of its JSON representation.
func (m Manifest) Context() (Context, error) {
	h, err := m.Hash()
	if err != nil {
		return Context{}, err
	}

	return m.context(h), nil
}

// Artifact looks up the exact shape and validates its pinned metadata.
func (m Manifest) Artifact(shape Shape) (Artifact, error) {
	for _, a := range m.Artifacts {
		if a.Shape == shape {
			return a, a.Validate()
		}
	}

	return Artifact{}, errors.New("address circuit shape absent from manifest")
}
