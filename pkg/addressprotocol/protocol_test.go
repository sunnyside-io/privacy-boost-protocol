package addressprotocol

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

func TestAssetCanonicalBoundaries(t *testing.T) {
	for _, s := range []string{"0x0000000000000000000000000000000000000001", "0x000000000000000000000000000000000000ffff", "0xffffffffffffffffffffffffffffffffffffffff", "0x52908400098527886E0F7030069857D2E4169EE7"} {
		a, err := ParseAsset(s)
		require.NoError(t, err)
		require.Equal(t, common.HexToAddress(s).Hex(), a.String())
		field, err := AssetFromField(a.Field())
		require.NoError(t, err)
		require.Equal(t, a, field)
		b, err := json.Marshal(a)
		require.NoError(t, err)
		var again Asset
		require.NoError(t, json.Unmarshal(b, &again))
		require.Equal(t, a, again)
	}
	for _, s := range []string{"0x1", "1", "0x0000000000000000000000000000000000000000", "0X0000000000000000000000000000000000000001", "0x52908400098527886e0F7030069857D2E4169EE7", "0x" + strings.Repeat("f", 41)} {
		_, err := ParseAsset(s)
		require.Error(t, err, s)
	}
	for _, v := range []*big.Int{nil, big.NewInt(0), big.NewInt(-1), new(big.Int).Lsh(big.NewInt(1), 160), fr.Modulus()} {
		_, err := AssetFromField(v)
		require.Error(t, err)
	}
	for _, b := range [][]byte{nil, make([]byte, 19), make([]byte, 21), make([]byte, 20)} {
		_, err := AssetFromBytes(b)
		require.Error(t, err)
	}
	var zero Asset
	require.Error(t, json.Unmarshal([]byte(`1`), &zero))
	_, err := json.Marshal(zero)
	require.Error(t, err)
}

func TestNoteMigrationShapesAndPublicVectors(t *testing.T) {
	for n := 1; n <= 16; n++ {
		shape, err := NoteMigrationCapacity(n)
		require.NoError(t, err)
		if n <= 3 {
			require.Equal(t, uint32(3), shape)
		} else {
			require.Equal(t, uint32(16), shape)
		}
	}
	for _, n := range []int{-1, 0, 17} {
		_, err := NoteMigrationCapacity(n)
		require.Error(t, err)
	}
	for _, tc := range []struct {
		family                     Family
		batch, in, out, fees, want uint32
	}{
		{Epoch, 1, 1, 1, 4, 50}, {Epoch, 129, 1, 1, 4, 563}, {Deposit, 1, 0, 0, 0, 30}, {Portal, 1, 0, 0, 0, 31},
		{Forced, 1, 4, 0, 0, 35}, {GiftClaim, 1, 0, 0, 0, 50}, {NoteMigration, 3, 0, 0, 0, 31}, {NoteMigration, 16, 0, 0, 0, 57},
	} {
		s := Shape{Family: tc.family, Batch: tc.batch, Inputs: tc.in, Outputs: tc.out, FeeTokens: tc.fees, Depth: 24, AuthDepth: 20}
		if tc.family == Deposit || tc.family == Portal || tc.family == NoteMigration {
			s.AuthDepth = 0
		}
		n, err := s.PublicInputs()
		require.NoError(t, err)
		require.Equal(t, tc.want, n)
	}
	for _, n := range []uint32{1, 2, 4, 8, 32} {
		require.Error(t, (Shape{Family: NoteMigration, Batch: n, Depth: 24}).Validate())
	}
}

func TestDeploymentContextRejectsStaleAndNoncanonical(t *testing.T) {
	c := Context{ChainID: 1, Pool: common.HexToAddress("0x1"), ManifestHash: common.HexToHash("0x1"), Snapshot: common.HexToAddress("0x2"), SnapshotRoot: common.HexToHash("0x2"), FirstNoteTreeV2: 2}
	require.NoError(t, c.Validate())
	require.NoError(t, c.Match(c))
	require.False(t, c.NativeTree(1))
	require.True(t, c.NativeTree(2))
	require.True(t, c.NativeTree(32767))
	require.False(t, c.NativeTree(32768))
	for _, change := range []func(*Context){func(v *Context) { v.ChainID++ }, func(v *Context) { v.ManifestHash[0] = 1 }, func(v *Context) { v.Pool[0] = 1 }, func(v *Context) { v.FirstNoteTreeV2++ }, func(v *Context) { v.SnapshotRoot[0] = 1 }} {
		other := c
		change(&other)
		require.Error(t, other.Match(c))
	}
	c.SnapshotRoot = common.BigToHash(fr.Modulus())
	require.Error(t, c.Validate())
}
