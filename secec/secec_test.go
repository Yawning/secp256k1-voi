// Copyright (c) 2023 Yawning Angel
//
// SPDX-License-Identifier: BSD-3-Clause

package secec

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"gitlab.com/yawning/secp256k1-voi"
	"gitlab.com/yawning/secp256k1-voi/internal/helpers"
)

const testMessage = "Most lawyers couldn’t recognize a Ponzi scheme if they were having dinner with Charles Ponzi."

var testMessageHash = hashMsgForTests([]byte(testMessage))

func hashMsgForTests(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func TestSecec(t *testing.T) {
	privNist, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "GenerateKey - P256")
	pubNist := privNist.Public()

	// Basic integration tests.  Wycheproof will take care of most of
	// the in-depth testing.
	t.Run("ECDH", func(t *testing.T) {
		alicePriv, err := GenerateKey()
		require.NoError(t, err, "GenerateKey - Alice")
		alicePubBytes := alicePriv.PublicKey().Bytes()

		bobPriv, err := GenerateKey()
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
		priv, err := GenerateKey()
		require.NoError(t, err, "GenerateKey")

		pub := priv.PublicKey()

		sig, err := priv.SignASN1(rand.Reader, testMessageHash)
		require.NoError(t, err, "SignASN1")

		ok := pub.VerifyASN1(testMessageHash, sig)
		require.True(t, ok, "VerifyASN1")

		tmp := bytes.Clone(sig)
		tmp[0] ^= 0x69
		ok = pub.VerifyASN1(testMessageHash, tmp)
		require.False(t, ok, "VerifyASN1 - Corrupted sig")

		tmp = bytes.Clone(testMessageHash)
		tmp[0] ^= 0x69
		ok = pub.VerifyASN1(tmp, sig)
		require.False(t, ok, "VerifyASN1 - Corrupted h")

		ok = pub.VerifyASN1(testMessageHash[:5], sig)
		require.False(t, ok, "VerifyASN1 - Truncated h")

		r, s, _, err := priv.SignRaw(rand.Reader, testMessageHash)
		require.NoError(t, err, "SignRaw")

		ok = pub.VerifyRaw(testMessageHash, r, s)
		require.True(t, ok, "VerifyRaw")

		compactSig := BuildCompactSignature(r, s)
		compR, compS, err := ParseCompactSignature(compactSig)
		require.NoError(t, err, "ParseCompactSignature")
		require.EqualValues(t, 1, r.Equal(compR))
		require.EqualValues(t, 1, s.Equal(compS))

		// Test some pathological cases.
		var zero secp256k1.Scalar
		err = verify(pub, testMessageHash, &zero, s)
		require.ErrorIs(t, err, errInvalidRorS, "verify - Zero r")
		err = verify(pub, testMessageHash, r, &zero)
		require.ErrorIs(t, err, errInvalidRorS, "verify - Zero s")

		badSig, err := priv.SignASN1(rand.Reader, testMessageHash[:30])
		require.Nil(t, badSig, "SignASN1 - Truncated hash")
		require.ErrorIs(t, err, errInvalidDigest, "SignASN1 - Truncated hash")

		_, _, err = ParseCompactSignature(compactSig[:15])
		require.ErrorIs(t, err, errInvalidCompactSig, "ParseCompactSignature - truncated")

		badCompactSig := BuildCompactSignature(&zero, s)
		_, _, err = ParseCompactSignature(badCompactSig)
		require.ErrorIs(t, err, errInvalidScalar, "ParseCompactSignature - Zero r")
		badCompactSig = BuildCompactSignature(r, &zero)
		_, _, err = ParseCompactSignature(badCompactSig)
		require.ErrorIs(t, err, errInvalidScalar, "ParseCompactSignature - Zero s")

		require.False(t, priv.Equal(privNist), "priv.Equal(privNist)")
		require.False(t, pub.Equal(pubNist), "pub.Equal(pubNist)")

		pubUntyped := priv.Public()
		require.True(t, pub.Equal(pubUntyped), "pub.Equal(pubUntyped)")
	})
	t.Run("ECDSA/Recover", func(t *testing.T) {
		priv, err := GenerateKey()
		require.NoError(t, err, "GenerateKey")

		r, s, recoveryID, err := priv.SignRaw(rand.Reader, testMessageHash)
		require.NoError(t, err, "SignRaw")

		q, err := RecoverPublicKey(testMessageHash, r, s, recoveryID)
		require.NoError(t, err, "RecoverPublicKey")

		require.True(t, priv.PublicKey().Equal(q))

		// Test some pathological cases.
		var zero secp256k1.Scalar
		_, err = RecoverPublicKey(testMessageHash, &zero, s, recoveryID)
		require.ErrorIs(t, err, errInvalidRorS, "RecoverPublicKey - Zero r")
		_, err = RecoverPublicKey(testMessageHash, r, &zero, recoveryID)
		require.ErrorIs(t, err, errInvalidRorS, "RecoverPublicKey - Zero s")
		_, err = RecoverPublicKey(testMessageHash, r, s, recoveryID+27)
		require.Error(t, err, "RecoverPublicKey - Bad recovery ID")
		_, err = RecoverPublicKey(testMessageHash[:31], r, s, recoveryID)
		require.ErrorIs(t, err, errInvalidDigest, "RecoverPublicKey - Truncated h")
	})
	t.Run("ECDSA/K", testEcdsaK)
	t.Run("PrivateKey/Invalid", func(t *testing.T) {
		for _, v := range [][]byte{
			[]byte("trucated"),
			helpers.MustBytesFromHex("0000000000000000000000000000000000000000000000000000000000000000"), // N+1
			helpers.MustBytesFromHex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142"), // N+1
		} {
			k, err := NewPrivateKey(v)
			require.Nil(t, k, "NewPrivateKey(%x)", v)
			require.ErrorIs(t, err, errInvalidPrivateKey, "NewPrivateKey(%x)", v)
		}
	})
	t.Run("PublicKey/Invalid", func(t *testing.T) {
		k, err := NewPublicKey([]byte{0x00})
		require.Nil(t, k, "NewPublicKey - identity")
		require.ErrorIs(t, err, errAIsInfinity, "NewPublicKey - identity")

		k, err = NewPublicKeyFromPoint(secp256k1.NewIdentityPoint())
		require.Nil(t, k, "NewPublicKeyFromPoint - identity")
		require.ErrorIs(t, err, errAIsInfinity, "NewPublicKeyFromPoint - identity")

		require.PanicsWithValue(t, errAIsUninitialized, func() {
			new(PublicKey).Bytes()
		}, "uninitialized.Bytes()")
	})
	t.Run("PublicKey/Polarity", func(t *testing.T) {
		var (
			gotOdd, gotEven bool
			i               int
		)
		for gotOdd == false && gotEven == false {
			priv, err := GenerateKey()
			require.NoError(t, err, "GenerateKey")

			pub := priv.PublicKey()

			isOdd := pub.point.IsYOdd() == 1
			gotOdd = gotOdd || isOdd
			gotEven = gotEven || (!isOdd)

			require.Equal(t, isOdd, pub.IsYOdd())
			require.Equal(t, pub.Point().CompressedBytes(), pub.CompressedBytes())

			i++
		}
		t.Logf("%d iters to see both odd and even Y", i+1)

		require.Panics(t, func() {
			new(PublicKey).IsYOdd()
		}, "uninitialized.IsYOdd()")
	})
	t.Run("Internal/sampleRandomScalar", func(t *testing.T) {
		// All-zero entropy source should cause the rejection sampling
		// to give up, because it keeps generating scalars that are 0.
		sc, err := sampleRandomScalar(newZeroReader())
		require.Nil(t, sc, "sampleRandomScalar - zeroReader")
		require.ErrorIs(t, err, errRejectionSampling, "sampleRandomScalar - zeroReader")

		// Broken (non-functional) entropy source should just fail.
		sc, err = sampleRandomScalar(newBadReader(13))
		require.Nil(t, sc, "sampleRandomScalar - badReader")
		require.ErrorIs(t, err, errEntropySource, "sampleRandomScalar - badReader")
	})
}

func BenchmarkSecec(b *testing.B) {
	randomPriv, err := GenerateKey()
	require.NoError(b, err)
	randomPrivateBytes := randomPriv.Scalar().Bytes()

	randomPriv2, err := GenerateKey()
	require.NoError(b, err)
	randomPub := randomPriv2.PublicKey()
	randomPublicBytes := randomPub.Bytes()

	randomSig, err := randomPriv2.SignASN1(rand.Reader, testMessageHash)
	require.NoError(b, err)

	randomR, randomS, randomRecID, err := randomPriv2.SignRaw(rand.Reader, testMessageHash)
	require.NoError(b, err)

	b.Run("GenerateKey", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err := GenerateKey()
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
