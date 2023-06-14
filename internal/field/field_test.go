// Copyright (c) 2023 Yawning Angel
//
// SPDX-License-Identifier: BSD-3-Clause

package field

import (
	"testing"

	"github.com/stretchr/testify/require"

	"gitlab.com/yawning/secp256k1-voi/internal/helpers"
)

func BenchmarkField(b *testing.B) {
	b.Run("Invert/addchain", func(b *testing.B) {
		fe := NewElement().DebugMustRandomizeNonZero()
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			fe.Invert(fe)
		}
	})
}

func TestScalar(t *testing.T) {
	geqP := [][]byte{
		helpers.MustBytesFromHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"), // P
		helpers.MustBytesFromHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30"), // P+1
		helpers.MustBytesFromHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc31"), // P+2
		helpers.MustBytesFromHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc2f"), // P+2^32
	}
	t.Run("SetCanonicalBytes", func(t *testing.T) {
		for i, raw := range geqP {
			fe, err := NewElement().SetCanonicalBytes((*[ElementSize]byte)(raw))
			require.Nil(t, fe, "[%d]: SetCanonicalBytes(largerThanN)", i)
			require.Error(t, err, "[%d]: SetCanonicalBytes(largerThanN)", i)
		}
	})
	t.Run("MustSetCanonicalBytes", func(t *testing.T) {
		for i, raw := range geqP {
			require.Panics(t, func() {
				NewElement().MustSetCanonicalBytes((*[ElementSize]byte)(raw))
			},
				"[%d]: SetCanonicalBytes(largerThanN)", i,
			)
		}
	})
	t.Run("String", func(t *testing.T) {
		// This is only exposed because it was useful for debugging.
		fe := NewElement().DebugMustRandomizeNonZero()
		fe2 := NewElement().MustSetCanonicalBytes((*[ElementSize]byte)(helpers.MustBytesFromHex(fe.String())))
		require.EqualValues(t, fe, fe2, "fe.String should roundtrip")
	})

	// Interal: "Why are you doing that" assertion tests.
	require.Panics(t, func() {
		NewElementFromSaturated(0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff)
	})
	require.Panics(t, func() {
		fe := NewElementFromSaturated(69, 69, 69, 69)
		fe.Pow2k(fe, 0)
	})
}
