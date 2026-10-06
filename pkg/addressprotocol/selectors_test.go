package addressprotocol

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSelectShapes(t *testing.T) {
	epoch := Shape{Family: Epoch, Batch: 1, Inputs: 1, Outputs: 1, Depth: 16, AuthDepth: 16, FeeTokens: 4}
	deposit := Shape{Family: Deposit, Batch: 1, Depth: 16}
	shapes := []Shape{epoch, deposit, epoch}
	for _, tc := range []struct {
		name, configured string
		want             []Shape
		invalid          bool
	}{
		{name: "all", want: shapes},
		{name: "whitespace", configured: " \t", want: shapes},
		{name: "family across deployments", configured: "epoch", want: []Shape{epoch, epoch}},
		{name: "exact", configured: deposit.Key(), want: []Shape{deposit}},
		{name: "union and duplicates", configured: " epoch, " + deposit.Key() + ",epoch, ", want: shapes},
		{name: "empty explicit selectors", configured: " , , ", invalid: true},
		{name: "legacy", configured: "epoch_s1", invalid: true},
		{name: "partial match", configured: "epoch,unknown", invalid: true},
		{name: "unmatched shape", configured: "address_epoch_b999_i1_o1_d16_a16_f4", invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SelectShapes(shapes, tc.configured)
			if tc.invalid {
				require.ErrorContains(t, err, "circuit_configs")
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
			got[0].Batch++
			require.Equal(t, uint32(1), shapes[0].Batch)
		})
	}
}
