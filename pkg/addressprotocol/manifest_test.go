package addressprotocol

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

func manifestFixture() Manifest {
	m := Manifest{Schema: 1, ChainID: 31337, Pool: common.HexToAddress("0x1234567890123456789012345678901234567890"), Snapshot: common.HexToAddress("0x2234567890123456789012345678901234567890"), SnapshotRoot: common.HexToHash("0xabcdef"), FirstNoteTreeV2: 300}
	shapes := []Shape{
		{Family: Epoch, Batch: 5, Inputs: 2, Outputs: 2, Depth: 24, AuthDepth: 20, FeeTokens: 4},
		{Family: Deposit, Batch: 4, Depth: 24}, {Family: Portal, Batch: 6, Depth: 24},
		{Family: Forced, Batch: 1, Inputs: 13, Depth: 24, AuthDepth: 20}, {Family: GiftClaim, Batch: 3, Depth: 24, AuthDepth: 20},
		{Family: GiftClaim, Batch: 1, Depth: 24, AuthDepth: 20},
		{Family: NoteMigration, Batch: 3, Depth: 24}, {Family: NoteMigration, Batch: 16, Depth: 24},
	}
	for i, s := range shapes {
		count, _ := s.PublicInputs()
		m.Artifacts = append(m.Artifacts, Artifact{Shape: s, WitnessSchema: WitnessSchema, CompilerVersion: CompilerVersion, PublicInputs: count, CCSHash: common.BigToHash(big.NewInt(int64(i*3 + 1))), PKHash: common.BigToHash(big.NewInt(int64(i*3 + 2))), VKHash: common.BigToHash(big.NewInt(int64(i*3 + 3)))})
	}
	return m
}

func TestAddressManifestFileBoundsAndPublicGiftRecovery(t *testing.T) {
	m := manifestFixture()
	path := filepath.Join(t.TempDir(), "manifest.json")
	encoded, err := json.Marshal(m)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, encoded, 0600))
	read, err := ReadManifest(path)
	require.NoError(t, err)
	require.NoError(t, read.ValidateRollout())
	for _, data := range []string{string(encoded) + `{}`, string(encoded) + strings.Repeat(" ", 1<<20), `{"unknown":1}`} {
		require.NoError(t, os.WriteFile(path, []byte(data), 0600))
		_, err := ReadManifest(path)
		require.Error(t, err)
	}
	var artifacts []Artifact
	for _, a := range m.Artifacts {
		if a.Shape.Family != GiftClaim || a.Shape.Batch != 1 {
			artifacts = append(artifacts, a)
		}
	}
	m.Artifacts = artifacts
	require.NoError(t, m.Validate())
	require.ErrorContains(t, m.ValidateRollout(), "public gift recovery")
}

func TestAddressManifestKnownAnswerAndIdentity(t *testing.T) {
	m := manifestFixture()
	require.NoError(t, m.ValidateRollout())
	hash, err := m.Hash()
	require.NoError(t, err)
	ctx, err := m.Context()
	require.NoError(t, err)
	require.Equal(t, hash, ctx.ManifestHash)
	data, err := json.MarshalIndent(struct {
		Manifest Manifest    `json:"manifest"`
		Hash     common.Hash `json:"hash"`
	}{m, hash}, "", "  ")
	require.NoError(t, err)
	path := filepath.Join("..", "..", "testdata", "address-protocol", "manifest-v1.json")
	if os.Getenv("UPDATE_ADDRESS_VECTORS") == "1" {
		require.NoError(t, os.WriteFile(path, append(data, '\n'), 0644))
	}
	want, err := os.ReadFile(path)
	require.NoError(t, err)
	require.JSONEq(t, string(want), string(data))
	reversed := m
	reversed.Artifacts = append([]Artifact(nil), m.Artifacts...)
	for i, j := 0, len(reversed.Artifacts)-1; i < j; i, j = i+1, j-1 {
		reversed.Artifacts[i], reversed.Artifacts[j] = reversed.Artifacts[j], reversed.Artifacts[i]
	}
	other, err := reversed.Hash()
	require.NoError(t, err)
	require.Equal(t, hash, other)
	for name, mutate := range map[string]func(*Manifest){
		"chain": func(m *Manifest) { m.ChainID++ }, "pool": func(m *Manifest) { m.Pool[0]++ }, "snapshot": func(m *Manifest) { m.Snapshot[0]++ }, "root": func(m *Manifest) { m.SnapshotRoot[31]++ }, "boundary": func(m *Manifest) { m.FirstNoteTreeV2++ },
		"ccs": func(m *Manifest) { m.Artifacts[0].CCSHash[0]++ }, "pk": func(m *Manifest) { m.Artifacts[0].PKHash[0]++ }, "vk": func(m *Manifest) { m.Artifacts[0].VKHash[0]++ }, "same public count": func(m *Manifest) { m.Artifacts[0].Shape.AuthDepth-- },
	} {
		t.Run(name, func(t *testing.T) {
			changed := manifestFixture()
			mutate(&changed)
			got, err := changed.Hash()
			require.NoError(t, err)
			require.NotEqual(t, hash, got)
		})
	}
	for _, a := range m.Artifacts {
		require.LessOrEqual(t, len(QueueConfig(ctx, a.Shape)), 192)
		require.LessOrEqual(t, len(a.Shape.Family.TaskType()), 10)
	}
	m.Artifacts = m.Artifacts[:len(m.Artifacts)-1]
	require.ErrorContains(t, m.ValidateRollout(), "3 and 16")
	m.Artifacts = append(m.Artifacts, m.Artifacts[0])
	require.ErrorContains(t, m.Validate(), "duplicate")
}
