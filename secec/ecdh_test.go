package secec

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSecec(t *testing.T) {
	// Basic integration tests.  Wycheproof will take care of most of
	// the in-depth testing.
	t.Run("ECDH", func(t *testing.T) {
		alicePriv, err := GenerateKey(rand.Reader)
		require.NoError(t, err)
		alicePubBytes := alicePriv.PublicKey().Bytes()

		bobPriv, err := GenerateKey(rand.Reader)
		require.NoError(t, err)
		bobPubBytes := bobPriv.PublicKey().Bytes()

		bobPub, err := NewPublicKey(bobPubBytes)
		require.NoError(t, err)

		alicePub, err := NewPublicKey(alicePubBytes)
		require.NoError(t, err)

		aliceX, err := alicePriv.ECDH(bobPub)
		require.NoError(t, err)

		bobX, err := bobPriv.ECDH(alicePub)
		require.NoError(t, err)

		require.EqualValues(t, aliceX, bobX, "shared secrets should match")
	})
}

func BenchmarkSecec(b *testing.B) {
	randomPriv, err := GenerateKey(rand.Reader)
	require.NoError(b, err)
	randomPrivateBytes := randomPriv.Scalar().Bytes()

	randomPriv2, err := GenerateKey(rand.Reader)
	require.NoError(b, err)
	randomPub := randomPriv2.PublicKey()
	randomPublicBytes := randomPub.Bytes()

	b.Run("GenerateKey", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err := GenerateKey(rand.Reader)
			require.NoError(b, err)
		}
	})
	b.Run("NewPrivateKey", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err := NewPrivateKey(randomPrivateBytes)
			require.NoError(b, err)
		}
	})
	b.Run("NewPublicKey", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err := NewPublicKey(randomPublicBytes)
			require.NoError(b, err)
		}
	})
	b.Run("PrivateKey", func(b *testing.B) {
		b.Run("Bytes", func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_ = randomPriv.Bytes()
			}
		})
		b.Run("ECDH", func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, _ = randomPriv.ECDH(randomPub)
			}
		})
	})
	b.Run("PublicKey", func(b *testing.B) {
		b.Run("Bytes", func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_ = randomPub.Bytes()
			}
		})
	})
}
