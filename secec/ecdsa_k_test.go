package secec

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"gitlab.com/yawning/secp256k1-voi.git"
	"gitlab.com/yawning/secp256k1-voi.git/internal/helpers"
)

func testEcdsaK(t *testing.T) {
	// Test that a broken entropy source will degrade to deterministic,
	// but secure signatures.
	//
	// To be honest, this can just be done by signing 2 messages with
	// a busted RNG, and checking that r is different, but this is
	// more fun, and it helps me fill in gaps in the scalar arithmetic
	// test coverage.
	//
	// Note: There are more subtle catastrophic failure cases than the
	// one tested for here, involving bias in the distribution of k,
	// but that's also really difficult to test for.

	msg1 := []byte("This is Fail(TM). But it's not Epic(TM) yet...")
	msg1Hash := hashMsgForTests(msg1)

	msg2 := []byte("With private keys you can SIGN THINGS")
	msg2Hash := hashMsgForTests(msg2)

	t.Run("BadExample", func(t *testing.T) {
		// As a demonstration, here is a "test" key, and 2 signatures
		// generated with the same k, over 2 different messages.

		testKeyScalar := mustScalarFromHex(t, "000000000000000000000000"+"E5C4D0A8249A6F27E5E0C9D534F4DA15223F42AD")
		testKey, err := newPrivateKeyFromScalar(testKeyScalar)
		require.NoError(t, err, "newPrivateKeyFromScalar")

		badKBytes := sha256.Sum256([]byte("chosen by fair dice roll. guaranteed to be random."))

		// Signature 1 (testKey, badK, msg1)
		//
		// Note: Coincidentally generating this requires also not doing
		// the condititional negate since s > n/2.

		r1 := mustScalarFromHex(t, "317365e5fada9ddf645d224952c398b3bfa5dcb4d11803213ee6565639ad25be")
		s1 := mustScalarFromHex(t, "c69a9505efb9a417b5f59f62ad7cd8140947b2e2189fb7ef111a8206d2ed8aa5")
		sigOk := testKey.PublicKey().Verify(msg1Hash, r1, s1)
		require.True(t, sigOk, "sig1 ok")

		// Signature 2 (testKey, badK, msg2)

		r2 := mustScalarFromHex(t, "317365e5fada9ddf645d224952c398b3bfa5dcb4d11803213ee6565639ad25be")
		s2 := mustScalarFromHex(t, "14577cbf24e320e45c14efe63b4190e2e00f9936102f00d67cb5e79113ef5a9b")
		sigOk = testKey.PublicKey().Verify(msg2Hash, r2, s2)
		require.True(t, sigOk, "sig2 ok")

		// So the adversary has (msg1, r1, s2), and (msg2, r2, s2).
		//
		// Note: If k is reused, r will be the same between multiple signatures.

		require.EqualValues(t, r1.Bytes(), r2.Bytes(), "r1 == r2")
		require.NotEqualValues(t, s1.Bytes(), s2.Bytes(), "s1 != s2")

		// Convert the message hashes to scalars (z1, z2), per ECDSA.

		z1, _ := hashToScalar(msg1Hash)
		z2, _ := hashToScalar(msg2Hash)

		// Recover k via `k = (z - z')/(s - s')`

		zDiff := secp256k1.NewScalar().Subtract(z1, z2)
		sDiff := secp256k1.NewScalar().Subtract(s1, s2)
		sDiff.Invert(sDiff)
		recoveredK := secp256k1.NewScalar().Multiply(zDiff, sDiff)
		require.EqualValues(t, badKBytes[:], recoveredK.Bytes(), "k == recoveredK")

		// Recover d via `d = (sk - z)/r`

		skSubZ := secp256k1.NewScalar().Multiply(s1, recoveredK)
		skSubZ.Subtract(skSubZ, z1)
		rInv := secp256k1.NewScalar().Invert(r1)
		recoveredD := secp256k1.NewScalar().Multiply(skSubZ, rInv)
		require.EqualValues(t, testKey.Scalar().Bytes(), recoveredD.Bytes(), "d == recoveredD")
		// ... And now you're sad, because that's the private key.
	})
	t.Run("MitigateDebianAndSony", func(t *testing.T) {
		// Use a different "test" key.
		testKeyScalar := mustScalarFromHex(t, "000000000000000000000000"+"14B022E892CF8614A44557DB095C928DE9B89970")
		testKey, err := newPrivateKeyFromScalar(testKeyScalar)
		require.NoError(t, err, "newPrivateKeyFromScalar")

		// Signature 1 (testKey, all 0 entropy, msg1)
		//
		// Do it twice, to verify that signatures with no entropy are
		// deterministic.

		r1, s1, _, err := testKey.Sign(zeroReader{}, msg1Hash)
		require.NoError(t, err, "k1.Sign(zeroReader, msg1)")
		sigOk := testKey.PublicKey().Verify(msg1Hash, r1, s1)
		require.True(t, sigOk, "sig1 ok")

		r1check, s1check, _, err := testKey.Sign(zeroReader{}, msg1Hash)
		require.NoError(t, err, "Sign(zeroReader, msg1) - again")

		require.EqualValues(t, r1.Bytes(), r1check.Bytes(), "r1 != r1check")
		require.EqualValues(t, s1.Bytes(), s1check.Bytes(), "s1 != s1check")

		// Signature 2 (testKey, all 0 entropy, msg2)

		r2, s2, _, err := testKey.Sign(zeroReader{}, msg2Hash)
		require.NoError(t, err, "k1.Sign(zeroReader, msg2)")
		sigOk = testKey.PublicKey().Verify(msg2Hash, r2, s2)
		require.True(t, sigOk, "sig2 ok")

		// The mitigation used is to use a CSPRNG seeded with the
		// private key, entropy, and message digest to sample k.
		// So even with no entropy and a fixed private key, r
		// should be different.
		//
		// In theory the entropy input can be omitted all together,
		// and our construct will provide the equivalent behavior
		// to what was proposed in RFC 6979, but current thought
		// is that adding entropy is better.

		require.NotEqualValues(t, r1.Bytes(), r2.Bytes(), "r1 != r2")

		// Generate another "test" key.

		testKeyScalar2Bytes := sha256.Sum256([]byte("MD_Update(&m,buf,j);  /* purify complains */"))
		testKeyScalar2, err := secp256k1.NewScalarFromCanonicalBytes(&testKeyScalar2Bytes)
		require.NoError(t, err, "NewScalarFromCanonicalBytes")
		testKey2, err := newPrivateKeyFromScalar(testKeyScalar2)
		require.NoError(t, err, "newPrivateKeyFromScalar")

		// Signature 3 (testKey2, all 0 entropy, msg1)

		r3, s3, _, err := testKey2.Sign(zeroReader{}, msg1Hash)
		require.NoError(t, err, "k2.Sign(zeroReader, msg1)")
		sigOk = testKey2.PublicKey().Verify(msg1Hash, r3, s3)
		require.True(t, sigOk, "sig3 ok")

		// Likewise, even with no entropy, using a different private key
		// to sign the same message, r should be different.

		require.NotEqualValues(t, r1.Bytes(), r3.Bytes(), "r1 != r3")

		// Signature 4 (testKey, actual entropy, msg1)

		r4, s4, _, err := testKey.Sign(rand.Reader, msg1Hash)
		require.NoError(t, err, "k1.Sign(rand.Reader, msg1")
		sigOk = testKey.PublicKey().Verify(msg1Hash, r4, s4)
		require.True(t, sigOk, "sig4 ok")

		require.NotEqualValues(t, r1.Bytes(), r4.Bytes(), "r1 != r4")
		require.NotEqualValues(t, s1.Bytes(), s4.Bytes(), "s1 != s4")

		// Finally, with actual entropy, using the same private key
		// to sign the same message, should result in a non-deterministic
		// signature.
	})
	t.Run("MitigateDebianAndSony/DomainSep", func(t *testing.T) {
		// As we use the same nonce generation routine between ECDSA
		// and Schnorr signatures, validate that domain separation
		// works as expected, by generating 2 scalars with the
		// degraded deterministic rng, and ensuring that changing
		// the domain separator changes the scalar.
		//
		// Note: This is what the 'c' in 'cSHAKE' is for, so if this
		// test ever fails, something is very badly fucked up.

		testKeyScalarBytes := sha256.Sum256([]byte("It's a proprietary strategy. I can't go into it in great detail."))
		testKeyScalar, err := secp256k1.NewScalarFromCanonicalBytes(&testKeyScalarBytes)
		require.NoError(t, err, "NewScalarFromCanonicalBytes")
		testKey, err := newPrivateKeyFromScalar(testKeyScalar)
		require.NoError(t, err, "newPrivateKeyFromScalar")

		genScalar := func(domainSep string) *secp256k1.Scalar {
			rng, err := mitigateDebianAndSony(zeroReader{}, domainSep, testKey, msg1Hash)
			require.NoError(t, err, "mitigateDebianAndSony(%s)", domainSep)

			s, err := sampleRandomScalar(rng)
			require.NoError(t, err, "sampleRandomScalar(%s)", domainSep)
			return s
		}

		scalarEcdsa := genScalar(domainSepECDSA)
		scalarSchnorr := genScalar(domainSepSchnorr) // Only thing that changes is the domain separator.

		require.NotEqualValues(t, scalarEcdsa.Bytes(), scalarSchnorr.Bytes())
	})
}

func mustScalarFromHex(t *testing.T, x string) *secp256k1.Scalar {
	b := helpers.MustBytesFromHex(x)
	s, err := secp256k1.NewScalarFromCanonicalBytes((*[secp256k1.ScalarSize]byte)(b))
	require.NoError(t, err, "NewScalarFromCanonicalBytes")
	return s
}

type zeroReader struct{}

func (zr zeroReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 0
	}
	return len(b), nil
}
