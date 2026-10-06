// Package addressprotocol defines the address-native wire and artifact identities.
// Historical token IDs are never implicitly converted into native assets.
package addressprotocol

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

// Asset is a nonzero ERC-20 address. Validate it at each untrusted boundary;
// its zero value is reserved for inactive circuit slots, never an active asset.
type Asset [20]byte

var ErrInvalidAsset = errors.New("invalid ERC-20 address")

// ParseAsset accepts a nonzero, 20-byte hex address with a lowercase 0x prefix.
// Mixed-case addresses must carry a valid EIP-55 checksum.
func ParseAsset(s string) (Asset, error) {
	if len(s) != 42 || !strings.HasPrefix(s, "0x") {
		return Asset{}, ErrInvalidAsset
	}

	b, err := hex.DecodeString(s[2:])
	if err != nil {
		return Asset{}, ErrInvalidAsset
	}

	a, err := AssetFromBytes(b)
	if err != nil {
		return Asset{}, err
	}

	hexPart := s[2:]
	if hexPart != strings.ToLower(hexPart) && hexPart != strings.ToUpper(hexPart) && s != a.Address().Hex() {
		return Asset{}, fmt.Errorf("%w: checksum", ErrInvalidAsset)
	}

	return a, nil
}

// AssetFromBytes requires exactly 20 bytes and rejects the zero address.
func AssetFromBytes(b []byte) (Asset, error) {
	if len(b) != 20 {
		return Asset{}, ErrInvalidAsset
	}

	var a Asset
	copy(a[:], b)
	return a, a.Validate()
}

// AssetFromField converts a positive 160-bit integer without truncating high bits.
func AssetFromField(v *big.Int) (Asset, error) {
	if v == nil || v.Sign() <= 0 || v.BitLen() > 160 {
		return Asset{}, ErrInvalidAsset
	}

	var b [20]byte
	v.FillBytes(b[:])
	return AssetFromBytes(b[:])
}

// Validate rejects the zero address reserved for inactive circuit slots.
func (a Asset) Validate() error {
	if a == (Asset{}) {
		return ErrInvalidAsset
	}

	return nil
}

func (a Asset) Address() common.Address { return common.Address(a) }
func (a Asset) Field() *big.Int         { return new(big.Int).SetBytes(a[:]) }
func (a Asset) String() string          { return a.Address().Hex() }

// MarshalJSON emits a checksummed address string and rejects inactive zero assets.
func (a Asset) MarshalJSON() ([]byte, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}

	return json.Marshal(a.String())
}

// UnmarshalJSON applies the same width and checksum rules as ParseAsset.
func (a *Asset) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return ErrInvalidAsset
	}

	parsed, err := ParseAsset(s)
	if err != nil {
		return err
	}

	*a = parsed
	return nil
}
