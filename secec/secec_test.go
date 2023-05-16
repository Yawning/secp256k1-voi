package secec

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

const testMessage = "Most lawyers couldn’t recognize a Ponzi scheme if they were having dinner with Charles Ponzi."

var testMessageHash = hashMsgForTests([]byte(testMessage))

func hashMsgForTests(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func TestSecec(t *testing.T) {
	// Basic integration tests.  Wycheproof will take care of most of
	// the in-depth testing.
	t.Run("ECDH", func(t *testing.T) {
		alicePriv, err := GenerateKey(rand.Reader)
		require.NoError(t, err, "GenerateKey - Alice")
		alicePubBytes := alicePriv.PublicKey().Bytes()

		bobPriv, err := GenerateKey(rand.Reader)
		require.NoError(t, err, "GenerateKey - Bob")
		bobPubBytes := bobPriv.PublicKey().Bytes()

		bobPub, err := NewPublicKey(bobPubBytes)
		require.NoError(t, err, "NewPublicKey - Bob")

		alicePub, err := NewPublicKey(alicePubBytes)
		require.NoError(t, err, "NewPublicKey - Alice")

		aliceX, err := alicePriv.ECDH(bobPub)
		require.NoError(t, err, "ECDH - Alice")

		bobX, err := bobPriv.ECDH(alicePub)
		require.NoError(t, err, "ECDH - Bob")

		require.EqualValues(t, aliceX, bobX, "shared secrets should match")
	})
	t.Run("ECDSA", func(t *testing.T) {
		priv, err := GenerateKey(rand.Reader)
		require.NoError(t, err, "GenerateKey")

		pub := priv.PublicKey()

		sig, err := priv.SignASN1(rand.Reader, testMessageHash)
		require.NoError(t, err, "SignASN1")

		ok := pub.VerifyASN1(testMessageHash, sig)
		require.True(t, ok, "VerifyASN1")

		ok = pub.VerifyASN1Shitcoin(testMessageHash, sig)
		require.True(t, ok, "VerifyASN1Shitcoin")

		tmp := append([]byte{}, sig...)
		tmp[0] ^= 0x69
		ok = pub.VerifyASN1(testMessageHash, tmp)
		require.False(t, ok, "VerifyASN1 - Corrupted sig")

		tmp = append([]byte{}, testMessageHash...)
		tmp[0] ^= 0x69
		ok = pub.VerifyASN1(tmp, sig)
		require.False(t, ok, "VerifyASN1 - Corrupted h")
	})
	t.Run("ECDSA/K", testEcdsaK)
}

func BenchmarkSecec(b *testing.B) {
	randomPriv, err := GenerateKey(rand.Reader)
	require.NoError(b, err)
	randomPrivateBytes := randomPriv.Scalar().Bytes()

	randomPriv2, err := GenerateKey(rand.Reader)
	require.NoError(b, err)
	randomPub := randomPriv2.PublicKey()
	randomPublicBytes := randomPub.Bytes()

	randomSig, err := randomPriv2.SignASN1(rand.Reader, testMessageHash)
	require.NoError(b, err)

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
		b.Run("SignASN1", func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, _ = randomPriv.SignASN1(rand.Reader, testMessageHash)
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
		b.Run("VerifyASN1", func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				ok := randomPub.VerifyASN1(testMessageHash, randomSig)
				require.True(b, ok)
			}
		})
	})
}
