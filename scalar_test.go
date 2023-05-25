package secp256k1

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	fiat "gitlab.com/yawning/secp256k1-voi.git/internal/fiat/secp256k1montgomeryscalar"
	"gitlab.com/yawning/secp256k1-voi.git/internal/helpers"
)

var scOne = NewScalar().One()

func (s *Scalar) String() string {
	x := hex.EncodeToString(s.Bytes())
	return x
}

func TestScalar(t *testing.T) {
	// N = fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
	geqN := [][]byte{
		helpers.MustBytesFromHex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"), // N
		helpers.MustBytesFromHex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142"), // N+1
		helpers.MustBytesFromHex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364143"), // N+2
		helpers.MustBytesFromHex("ffffffffffffffffffffffffffffffffbaaedce6af48a03bbfd25e8cd0364141"), // N+2^128
	}
	geqNReduced := []*Scalar{
		newScalarFromSaturated(0, 0, 0, 0),
		newScalarFromSaturated(0, 0, 0, 1),
		newScalarFromSaturated(0, 0, 0, 2),
		newScalarFromSaturated(0, 1, 0, 0),
	}
	t.Run("SetBytes", func(t *testing.T) {
		for i, raw := range geqN {
			s, didReduce := NewScalar().SetBytes((*[ScalarSize]byte)(raw))
			require.EqualValues(t, 1, didReduce, "[%d]: didReduce SetBytes(largerThanN)", i)
			require.EqualValues(t, 1, geqNReduced[i].Equal(s), "[%d]: didReduce SetBytes(largerThanN)", i)
		}
	})
	t.Run("SetCanonicalBytes", func(t *testing.T) {
		for i, raw := range geqN {
			s, err := NewScalar().SetCanonicalBytes((*[ScalarSize]byte)(raw))
			require.Error(t, err, "[%d]: SetCanonicalBytes(largerThanN)", i)
			require.Nil(t, s, "[%d]: SetCanonicalBytes(largerThanN)", i)
		}
	})

	t.Run("IsGreaterThanHalfN", func(t *testing.T) {
		// N/2 = 7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0
		leqHalfN := []*Scalar{
			newScalarFromSaturated(0x7fffffffffffffff, 0xffffffffffffffff, 0x5d576e7357a4501d, 0xdfe92f46681b20a0), // N/2
			newScalarFromSaturated(0x7fffffffffffffff, 0xffffffffffffffff, 0x5d576e7357a4501d, 0xdfe92f46681b209f), // N/2-1
		}
		for i, s := range leqHalfN {
			isGt := s.IsGreaterThanHalfN()
			require.EqualValues(t, 0, isGt, "[%d]: (leq).IsGreaterThanHalfN", i)
		}

		gtHalfN := []*Scalar{
			newScalarFromSaturated(0x7fffffffffffffff, 0xffffffffffffffff, 0x5d576e7357a4501d, 0xdfe92f46681b20a1), // N/2+1
			newScalarFromSaturated(0x7fffffffffffffff, 0xffffffffffffffff, 0x5d576e7357a4501d, 0xdfe92f46681b20a2), // N/2+2
		}
		for i, s := range gtHalfN {
			isGt := s.IsGreaterThanHalfN()
			require.EqualValues(t, 1, isGt, "[%d]: (gt).IsGreaterThanHalfN", i)
		}
	})
}

func BenchmarkScalar(b *testing.B) {
	b.Run("Invert/addchain", func(b *testing.B) {
		s := NewScalar().MustRandomize()
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			s.Invert(s)
		}
	})
	b.Run("Invert/fiat", func(b *testing.B) {
		s := NewScalar().MustRandomize()
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			s.InvertFiat(s)
		}
	})
}

func (s *Scalar) MustRandomize() *Scalar {
	var b [ScalarSize]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			panic("scalar: entropy source failure")
		}
		if _, err := s.SetCanonicalBytes(&b); err == nil {
			return s
		}
	}
}

func (s *Scalar) InvertFiat(x *Scalar) *Scalar {
	fiat.Invert(&s.m, &x.m)
	return s
}

// Bits returns the bit representation of `s` in LSB->MSB order.
func (s *Scalar) Bits() [ScalarSize * 8]byte {
	var nm fiat.NonMontgomeryDomainFieldElement
	fiat.FromMontgomery(&nm, &s.m)

	// XXX: This is gross, and I'm probably overcomplicating things,
	// and MSB->LSB order is probably easier to work with, and I might
	// as well produce output that is sized for the window used.

	var dst [ScalarSize * 8]byte
	for il, l := range nm { // For each 64-bit limb, least to most significant
		lOff := il * 64
		for ib := 0; ib < 8; ib++ { // For each 8-bit bytes, least to most significant
			off := lOff + ib*8
			b := byte(l >> (ib * 8))
			for i := 0; i < 8; i++ { // For each bit, least to most significant
				dst[off+i] = (b >> (i & 7)) & 1
			}
		}
	}

	return dst
}
