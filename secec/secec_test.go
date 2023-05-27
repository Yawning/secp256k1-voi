// Copyright 2023 Yawning Angel.  All Rights Reserved.
//
// secp256k1-voi can be used in non-commercial projects of any kind,
// excluding those relating to or containing non-fungible tokens
// ("NFT") or blockchain-related projects.
//
// The package can not be modified to suit your needs. You may not
// redistribute or resell it, even if modified.

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

		bipSig := append([]byte{}, sig...)
		bipSig = append(bipSig, 69)
		ok = pub.VerifyASN1BIP0066(testMessageHash, bipSig)
		require.True(t, ok, "VerifyASN1BIP0066")

		tmp := append([]byte{}, sig...)
		tmp[0] ^= 0x69
		ok = pub.VerifyASN1(testMessageHash, tmp)
		require.False(t, ok, "VerifyASN1 - Corrupted sig")

		tmp = append([]byte{}, testMessageHash...)
		tmp[0] ^= 0x69
		ok = pub.VerifyASN1(tmp, sig)
		require.False(t, ok, "VerifyASN1 - Corrupted h")
	})
	t.Run("ECDSA/Recover", func(t *testing.T) {
		// TODO: It would be nice to find test vectors for this...
		priv, err := GenerateKey(rand.Reader)
		require.NoError(t, err, "GenerateKey")

		r, s, recoveryID, err := priv.Sign(rand.Reader, testMessageHash)
		require.NoError(t, err, "Sign")

		q, err := RecoverPublicKey(testMessageHash, r, s, recoveryID)
		require.NoError(t, err, "RecoverPublicKey")

		require.True(t, priv.PublicKey().Equal(q))
	})
	t.Run("ECDSA/K", testEcdsaK)
	t.Run("Schnorr", func(t *testing.T) {
		priv, err := GenerateKey(rand.Reader)
		require.NoError(t, err, "GenerateKey")

		pub := priv.SchnorrPublicKey()

		sig, err := priv.SignSchnorr(rand.Reader, testMessageHash)
		require.NoError(t, err, "SignSchnorr")

		ok := pub.Verify(testMessageHash, sig)
		require.True(t, ok, "Verify")

		tmp := append([]byte{}, sig...)
		tmp[0] ^= 0x69
		ok = pub.Verify(testMessageHash, tmp)
		require.False(t, ok, "Verify - Corrupted sig")

		tmp = append([]byte{}, testMessageHash...)
		tmp[0] ^= 0x69
		ok = pub.Verify(tmp, sig)
		require.False(t, ok, "Verify - Corrupted msg")
	})
	t.Run("Schnorr/TestVectors", testSchnorrKAT)
}

func BenchmarkSecec(b *testing.B) {
	randomPriv, err := GenerateKey(rand.Reader)
	require.NoError(b, err)
	randomPrivateBytes := randomPriv.Scalar().Bytes()

	randomPriv2, err := GenerateKey(rand.Reader)
	require.NoError(b, err)
	randomPub := randomPriv2.PublicKey()
	randomSchnorrPub := randomPriv2.SchnorrPublicKey()
	randomPublicBytes := randomPub.Bytes()

	randomSig, err := randomPriv2.SignASN1(rand.Reader, testMessageHash)
	require.NoError(b, err)

	randomSchnorrSig, err := randomPriv2.SignSchnorr(rand.Reader, testMessageHash)
	require.NoError(b, err)

	randomR, randomS, randomRecID, err := randomPriv2.Sign(rand.Reader, testMessageHash)
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
		b.Run("SignSchnorr", func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, _ = randomPriv.SignSchnorr(rand.Reader, testMessageHash)
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
		b.Run("VerifySchnorr", func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				ok := randomSchnorrPub.Verify(testMessageHash, randomSchnorrSig)
				require.True(b, ok)
			}
		})
		b.Run("Recover", func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, err := RecoverPublicKey(testMessageHash, randomR, randomS, randomRecID)
				require.NoError(b, err)
			}
		})
	})
}
