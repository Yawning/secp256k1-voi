package secp256k1

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	fiat "gitlab.com/yawning/secp256k1-voi.git/internal/fiat/secp256k1montgomeryscalar"
)

func testScalarSplit(t *testing.T) {
	// Lambda = 0x5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72
	lambda := newScalarFromSaturated(0x5363ad4cc05c30e0, 0xa5261c028812645a, 0x122e22ea20816678, 0xdf02967c1b23bd72)

	for i, v := range []*Scalar{
		NewScalar(),
		scOne,
		NewScalar().MustRandomize(),

		// Test cases from libsecp256k1
		newScalarFromSaturated(0xd938a5667f479e3e, 0xb5b3c7faefdb3749, 0x3aa0585cc5ea2367, 0xe1b660db0209e6fc),
		newScalarFromSaturated(0xd938a5667f479e3e, 0xb5b3c7faefdb3749, 0x3aa0585cc5ea2367, 0xe1b660db0209e6fd),
		newScalarFromSaturated(0xd938a5667f479e3e, 0xb5b3c7faefdb3749, 0x3aa0585cc5ea2367, 0xe1b660db0209e6fe),
		newScalarFromSaturated(0xd938a5667f479e3e, 0xb5b3c7faefdb3749, 0x3aa0585cc5ea2367, 0xe1b660db0209e6ff),
		newScalarFromSaturated(0x2c9c52b33fa3cf1f, 0x5ad9e3fd77ed9ba5, 0xb294b8933722e9a5, 0x00e698ca4cf7632d),
		newScalarFromSaturated(0x2c9c52b33fa3cf1f, 0x5ad9e3fd77ed9ba5, 0xb294b8933722e9a5, 0x00e698ca4cf7632e),
		newScalarFromSaturated(0x2c9c52b33fa3cf1f, 0x5ad9e3fd77ed9ba5, 0xb294b8933722e9a5, 0x00e698ca4cf7632f),
		newScalarFromSaturated(0x2c9c52b33fa3cf1f, 0x5ad9e3fd77ed9ba5, 0xb294b8933722e9a5, 0x00e698ca4cf76330),
		newScalarFromSaturated(0x7fffffffffffffff, 0xffffffffffffffff, 0xd576e73557a4501d, 0xdfe92f46681b209f),
		newScalarFromSaturated(0x7fffffffffffffff, 0xffffffffffffffff, 0xd576e73557a4501d, 0xdfe92f46681b20a0),
		newScalarFromSaturated(0x7fffffffffffffff, 0xffffffffffffffff, 0xd576e73557a4501d, 0xdfe92f46681b20a1),
		newScalarFromSaturated(0x7fffffffffffffff, 0xffffffffffffffff, 0xd576e73557a4501d, 0xdfe92f46681b20a2),
		newScalarFromSaturated(0xd363ad4cc05c30e0, 0xa5261c0288126459, 0xf85915d77825b696, 0xbeebc5c2833ede11),
		newScalarFromSaturated(0xd363ad4cc05c30e0, 0xa5261c0288126459, 0xf85915d77825b696, 0xbeebc5c2833ede12),
		newScalarFromSaturated(0xd363ad4cc05c30e0, 0xa5261c0288126459, 0xf85915d77825b696, 0xbeebc5c2833ede13),
		newScalarFromSaturated(0xd363ad4cc05c30e0, 0xa5261c0288126459, 0xf85915d77825b696, 0xbeebc5c2833ede14),
		newScalarFromSaturated(0x26c75a9980b861c1, 0x4a4c38051024c8b4, 0x704d760ee95e7cd3, 0xde1bfdb1ce2c5a42),
		newScalarFromSaturated(0x26c75a9980b861c1, 0x4a4c38051024c8b4, 0x704d760ee95e7cd3, 0xde1bfdb1ce2c5a43),
		newScalarFromSaturated(0x26c75a9980b861c1, 0x4a4c38051024c8b4, 0x704d760ee95e7cd3, 0xde1bfdb1ce2c5a44),
		newScalarFromSaturated(0x26c75a9980b861c1, 0x4a4c38051024c8b4, 0x704d760ee95e7cd3, 0xde1bfdb1ce2c5a45),
	} {
		t.Run(fmt.Sprintf("Case %d", i), func(t *testing.T) {
			// t.Logf("Scalar: %v", v)
			k1, k2 := v.splitGLV()
			// t.Logf("k1: %v", k1)
			// t.Logf("k2: %v", k2)

			// k = k1 + k2 * lambda mod n
			k := NewScalar().Multiply(k2, lambda)
			k.Add(k, k1)
			require.EqualValues(t, 1, v.Equal(k), "k = k1 + k2 * lambda mod n")

			// The split scalars (or their negatives) are < 2^128.
			var k1Neg, k2Neg bool
			if k1.IsGreaterThanHalfN() == 1 {
				k1.Negate(k1)
				k1Neg = true
			}
			if k2.IsGreaterThanHalfN() == 1 {
				k2.Negate(k2)
				k2Neg = true
			}

			var tmp1, tmp2 fiat.NonMontgomeryDomainFieldElement
			fiat.FromMontgomery(&tmp1, &k1.m)
			fiat.FromMontgomery(&tmp2, &k2.m)

			require.Zero(t, tmp1[3], "k1 limb 3 == 0")
			require.Zero(t, tmp1[2], "k1 limb 2 == 0")

			require.Zero(t, tmp2[3], "k2 limb 3 == 0")
			require.Zero(t, tmp2[2], "k2 limb 2 == 0")

			// k * P = k1 * P + k2 * lambda * P
			p := newRcvr().MustRandomize()
			kP := newRcvr().scalarMultTrivial(v, p)

			var k1p, k2p *Point
			if !k1Neg {
				k1p = newRcvr().ScalarMult(k1, p)
			} else {
				k1p = newRcvr().ScalarMult(k1, newRcvr().Negate(p))
			}

			pPrime := newRcvr().mulBeta(p)
			if !k2Neg {
				k2p = newRcvr().ScalarMult(k2, pPrime)
			} else {
				k2p = newRcvr().ScalarMult(k2, newRcvr().Negate(pPrime))
			}

			sum := newRcvr().Add(k1p, k2p)
			requirePointEquals(t, kP, sum, "k * P = k1 * P + k2 * lambda * P")
		})
	}
}
