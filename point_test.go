package secp256k1

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"gitlab.com/yawning/secp256k1-voi.git/internal/helpers"
)

const randomTestIters = 1000

func TestPoint(t *testing.T) {
	t.Run("S11n", testPointS11n)
	// Add
	// Double
	// Subtract
	t.Run("ScalarMult", testPointScalarMult)
	t.Run("ScalarBaseMult", testPointScalarBaseMult)
	// ConditionalSelect
	// Equal

	t.Run("GLV/Split", testScalarSplit)
}

func testPointS11n(t *testing.T) {
	t.Run("G compressed", func(t *testing.T) {
		gCompressed := helpers.MustBytesFromHex("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")

		p, err := NewPointFromBytes(gCompressed)
		require.NoError(t, err, "NewPointFromBytes(gCompressed)")
		requirePointDeepEquals(t, NewGeneratorPoint(), p, "G decompressed")

		gBytes := p.CompressedBytes()
		require.Equal(t, gCompressed, gBytes, "G re-compressed")
	})
	t.Run("G uncompressed", func(t *testing.T) {
		gUncompressed := helpers.MustBytesFromHex("0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
		p, err := NewPointFromBytes(gUncompressed)
		require.NoError(t, err, "NewPointFromBytes(gUncompressed)")
		requirePointDeepEquals(t, NewGeneratorPoint(), p, "G")

		gBytes := p.UncompressedBytes()
		require.Equal(t, gUncompressed, gBytes, "G")
	})
	t.Run("Identity", func(t *testing.T) {
		secIDBytes := []byte{prefixIdentity}

		idBytes := NewIdentityPoint().CompressedBytes()
		require.Equal(t, secIDBytes, idBytes, "Identity")
		p, err := NewPointFromBytes(idBytes)
		require.NoError(t, err, "NewPointFromBytes(idCompressed)")
		requirePointDeepEquals(t, NewIdentityPoint(), p, "NewPointFromBytes(idCompressed)")

		idBytes = NewIdentityPoint().UncompressedBytes()
		require.Equal(t, secIDBytes, idBytes, "Identity")
		p, err = NewPointFromBytes(idBytes)
		require.NoError(t, err, "NewPointFromBytes(idUncompressed)")
		requirePointDeepEquals(t, NewIdentityPoint(), p, "NewPointFromBytes(idCompressed)")
	})

	// TODO:
	// - Add more compressed point test cases.
	// - Test edge cases for good measure (eg: x >= p)
}

func testPointScalarMult(t *testing.T) {
	t.Run("0 * G", func(t *testing.T) {
		g := NewGeneratorPoint()
		s := NewScalar()

		q := newRcvr().ScalarMult(s, g)
		qv := newRcvr().scalarMultVartimeGLV(s, g) // Special case

		require.EqualValues(t, 1, q.IsIdentity(), "0 * G == id, got %+v", q)
		require.EqualValues(t, 1, qv.IsIdentity(), "0 * G == id, got %+v", q)
	})
	t.Run("1 * G", func(t *testing.T) {
		g := NewGeneratorPoint()

		q := newRcvr().ScalarMult(scOne, g)

		requirePointEquals(t, g, q, "1 * G = G")
	})
	t.Run("2 * G", func(t *testing.T) {
		g := NewGeneratorPoint()
		s := newScalarFromSaturated(0, 0, 0, 2)

		q := newRcvr().ScalarMult(s, g)
		g.Double(g)

		requirePointEquals(t, g, q, "2 * G = G + G")
	})
	t.Run("KAT/libsecp256k1", func(t *testing.T) {
		// Known answer test stolen from libsecp256k1 (`ecmult_const_random_mult`)
		aUncompressed := helpers.MustBytesFromHex("04" + "6d98654457ff52b8cf1b81265b802a5ba97f9263b1e880449335132591bc450a535c59f7325e5d2bc391fbe83c12787c337e4a98e82a90110123ba37dd769c7d")
		a, err := NewPointFromBytes(aUncompressed)
		require.NoError(t, err, "NewPointFromBytes(aUncompressed)")

		xnBytes := helpers.MustBytesFromHex("649d4f77c4242df77f2079c914530327a31b876ad2d8ce2a2236d5c6d7b2029b")
		xn, err := NewScalarFromCanonicalBytes((*[32]byte)(xnBytes))
		require.NoError(t, err, "NewScalarFromCanonicalBytes(xnBytes)")

		bUncompressed := helpers.MustBytesFromHex("04" + "237736844d209dc7098a786f20d06fcd070a38bfc11ac651030043191e2a8786ed8c3b8ec06dd57bd06ea66e45492b0fb84e4e1bfb77e21f96baae2a63dec956")
		bExpected, err := NewPointFromBytes(bUncompressed)
		require.NoError(t, err, "NewPointFromBytes(bUncompressed)")

		aXn := newRcvr().ScalarMult(xn, a)
		aXnV := newRcvr().scalarMultVartimeGLV(xn, a)

		requirePointEquals(t, bExpected, aXn, "xn * a == b")
		requirePointEquals(t, bExpected, aXnV, "xn * a (vartime) == b")
	})
	t.Run("Consistency", func(t *testing.T) {
		var s Scalar
		check := newRcvr().MustRandomize()
		p1 := NewPointFrom(check)
		p2 := NewPointFrom(check)
		for i := 0; i < randomTestIters; i++ {
			s.MustRandomize()
			check := check.scalarMultTrivial(&s, check)
			p1.ScalarMult(&s, p1)
			p2.scalarMultVartimeGLV(&s, p2)

			requirePointEquals(t, check, p1, fmt.Sprintf("[%d]: s * check (trivial) == s * p1 (ct)", i))
			requirePointEquals(t, p1, p2, fmt.Sprintf("[%d]: s * p1 (ct) == s * p2 (vartime)", i))
		}
	})
}

func testPointScalarBaseMult(t *testing.T) {
	t.Run("0 * G", func(t *testing.T) {
		s := NewScalar()

		q := newRcvr().ScalarBaseMult(s)

		require.EqualValues(t, 1, q.IsIdentity(), "0 * G == id, got %+v", q)
	})
	t.Run("1 * G", func(t *testing.T) {
		g := NewGeneratorPoint()

		q := newRcvr().ScalarBaseMult(scOne)

		requirePointEquals(t, g, q, "1 * G == G")
	})
	t.Run("2 * G", func(t *testing.T) {
		g := NewGeneratorPoint()
		s := newScalarFromSaturated(0, 0, 0, 2)

		q := newRcvr().ScalarBaseMult(s)
		g.Double(g)

		requirePointEquals(t, g, q, "2 * G = G + G")
	})
	t.Run("Consistency", func(t *testing.T) {
		var s Scalar
		check, p1, pv, g := newRcvr(), newRcvr(), newRcvr(), NewGeneratorPoint()
		for i := 0; i < randomTestIters; i++ {
			s.MustRandomize()
			check.scalarMultTrivial(&s, g)
			p1.ScalarBaseMult(&s)
			pv.scalarBaseMultVartime(&s)

			requirePointEquals(t, check, p1, fmt.Sprintf("[%d]: s * G (trivial) != s * G (ct)", i))
			requirePointEquals(t, p1, pv, fmt.Sprintf("[%d]: s * G (ct) != s * G (vartime)", i))
		}
	})
}

func (v *Point) MustRandomize() *Point {
	s := NewScalar().MustRandomize()
	return v.ScalarBaseMult(s)
}

func requirePointDeepEquals(t *testing.T, expected, actual *Point, descr string) {
	assertPointsValid(expected, actual)
	require.Equal(t, expected.x.Bytes(), actual.x.Bytes(), "%s X (%x %x)", descr, expected.x.Bytes(), expected.x.Bytes())
	require.Equal(t, expected.y.Bytes(), actual.y.Bytes(), "%s Y (%x %x)", descr, expected.y.Bytes(), expected.y.Bytes())
	require.Equal(t, expected.z.Bytes(), actual.z.Bytes(), "%s Z (%x %x)", descr, expected.z.Bytes(), expected.z.Bytes())
	require.EqualValues(t, 1, expected.Equal(actual), descr) // For good measure.
}

func requirePointEquals(t *testing.T, expected, actual *Point, descr string) {
	assertPointsValid(expected, actual)
	require.EqualValues(t, 1, expected.Equal(actual), descr)

	expectedScaled := newRcvr().rescale(expected)
	actualScaled := newRcvr().rescale(actual)
	requirePointDeepEquals(t, expectedScaled, actualScaled, descr)
}

func (v *Point) scalarMultTrivial(s *Scalar, p *Point) *Point {
	// This is slow but trivially correct, and is used for
	// cross-checking results of the more sophisticated
	// implementations.

	// Constant-time double and add (decreasing index).
	//
	// From https://bearssl.org/constanttime.html:
	// 1. Set Q = 0 (the “point at infinity”)
	// 2. Compute Q ← 2·Q
	// 3. If next bit of n is set, then add P to Q
	// 4. Loop to step 2 until end of multiplier is reached
	q, id, addend := NewIdentityPoint(), NewIdentityPoint(), newRcvr()
	sBits := s.Bits()
	for i := len(sBits) - 1; i >= 0; i-- {
		if i != len(sBits)-1 {
			q.Double(q)
		}
		addend.ConditionalSelect(id, p, uint64(sBits[i]))

		q.Add(q, addend)
	}

	return v.Set(q)
}

func BenchmarkPoint(b *testing.B) {
	// Yes, this is a scalar op, but it's sole purpose is
	// to make point multiplication faster.
	b.Run("GLV/SplitScalar", func(b *testing.B) {
		s := NewScalar().MustRandomize()
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, _ = s.splitGLV()
		}
	})
	b.Run("GLV/ScalarMult", func(b *testing.B) {
		s := newScalarFromSaturated(0, 0, 0, 42069)
		q := NewGeneratorPoint()
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			q.ScalarMult(s, q)
		}
	})
	b.Run("GLV/ScalarMultVartime", func(b *testing.B) {
		var s Scalar
		q := NewGeneratorPoint()
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			b.StopTimer()
			s.MustRandomize()
			b.StartTimer()

			q.scalarMultVartimeGLV(&s, q)
		}
	})

	b.Run("Add", func(b *testing.B) {
		p := NewGeneratorPoint()
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			p.Add(p, p)
		}
	})
	b.Run("Add/Mixed", func(b *testing.B) {
		p, g := NewGeneratorPoint(), NewGeneratorPoint()
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			p.addMixed(p, &g.x, &g.y)
		}
	})
	b.Run("Double", func(b *testing.B) {
		p := NewGeneratorPoint()
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			p.Double(p)
		}
	})
	b.Run("ScalarBaseMult", func(b *testing.B) {
		var s Scalar
		q := NewGeneratorPoint()
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			b.StopTimer()
			s.MustRandomize()
			b.StartTimer()

			q.ScalarBaseMult(&s)
		}
	})
	b.Run("ScalarBaseMult/Vartime", func(b *testing.B) {
		var s Scalar
		q := NewGeneratorPoint()
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			b.StopTimer()
			s.MustRandomize()
			b.StartTimer()

			q.scalarBaseMultVartime(&s)
		}
	})
	b.Run("ScalarBaseMult/GenTable", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			newLargeAffinePointMultTable(NewGeneratorPoint())
		}
	})
	b.Run("DoubleScalarMultBasepointVartime", func(b *testing.B) {
		var s1, s2 Scalar
		q := NewGeneratorPoint()
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			b.StopTimer()
			s1.MustRandomize()
			s2.MustRandomize()
			b.StartTimer()

			q.DoubleScalarMultBasepointVartime(&s1, &s2, q)
		}
	})
	b.Run("s11n/UncompressedBytes", func(b *testing.B) {
		p := NewGeneratorPoint()

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = p.UncompressedBytes()
		}
	})
	b.Run("s11n/CompressedBytes", func(b *testing.B) {
		p := NewGeneratorPoint()

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = p.CompressedBytes()
		}
	})
}
