// Copyright (c) 2023 Yawning Angel
//
// SPDX-License-Identifier: BSD-3-Clause

package secec

import (
	csrand "crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/sha3"

	"gitlab.com/yawning/secp256k1-voi"
)

const (
	wantedEntropyBytes = 256 / 8
	maxScalarResamples = 8
	domainSepECDSA     = "ECDSA-Sign"
)

var (
	errInvalidScalar = errors.New("secp256k1/secec/ecdsa: invalid scalar")
	errInvalidDigest = errors.New("secp256k1/secec/ecdsa: invalid digest")
	errInvalidRorS   = errors.New("secp256k1.secec.ecdsa: r or s is zero")
	errRIsInfinity   = errors.New("secp256k1/secec/ecdsa: R is the point at infinity")
	errVNeqR         = errors.New("secp256k1/secec/ecdsa: v does not equal r")

	errEntropySource     = errors.New("secp256k1/secec: entropy source failure")
	errRejectionSampling = errors.New("secp256k1/secec: failed rejection sampling")
)

// Sign signs signs `hash` (which should be the result of hashing a
// larger message) using the PrivateKey `k`, using the signing procedure
// as specified in SEC 1, Version 2.0, Section 4.1.3.  It returns the
// tuple `(r, s, recovery_id)`.
//
// Notes: If `rand` is nil, the [crypto/rand.Reader] will be used.
// `s` will always be less than or equal to `n / 2`.  `recovery_id`
// will always be in the range `[0, 3]`.  Adding `27`, `31`, or the
// EIP-155 nonsense is left to the caller.
func (k *PrivateKey) Sign(rand io.Reader, hash []byte) (*secp256k1.Scalar, *secp256k1.Scalar, byte, error) {
	return sign(rand, k, hash)
}

// SignASN1 signs signs `hash` (which should be the result of hashing a
// larger message) using the PrivateKey `k`, using the signing procudure
// as specified in SEC 1, Version 2.0, Section 4.1.3.  It returns the
// ASN.1 encoded signature.
//
// Note: If `rand` is nil, the [crypto/rand.Reader] will be used. `s`
// will always be less than or equal to `n / 2`.
func (k *PrivateKey) SignASN1(rand io.Reader, hash []byte) ([]byte, error) {
	r, s, _, err := k.Sign(rand, hash)
	if err != nil {
		return nil, err
	}

	return buildASN1Signature(r, s), nil
}

// Verify verifies the `(r, s)` signature of `hash`, using the PublicKey
// `k`, using the verification procedure as specifed in SEC 1,
// Version 2.0, Section 4.1.4.  Its return value records whether the
// signature is valid.
func (k *PublicKey) Verify(hash []byte, r, s *secp256k1.Scalar) bool {
	return nil == verify(k, hash, r, s)
}

// VerifyASN1 verifies the ASN.1 encoded signature `sig` of `hash`,
// using the PublicKey `k`, using the verification procedure as specifed
// in SEC 1, Version 2.0, Section 4.1.4.  Its return value records
// whether the signature is valid.
//
// Note: The signature MUST be `SEQUENCE { r INTEGER, s INTEGER }`,
// as in encoded as a `ECDSA-Sig-Value`, WITHOUT the optional `a` and
// `y` fields.
func (k *PublicKey) VerifyASN1(hash, sig []byte) bool {
	r, s, err := ParseASN1Signature(sig)
	if err != nil {
		return false
	}

	return k.Verify(hash, r, s)
}

// VerifyASN1BIP0066 verifies the BIP-0066 encoded signature `sig` of
// `hash`, using the PublicKey `k`, using the verification procedure
// as specifed in SEC 1, Version 2.0, Section 4.1.4, with the additional
// restriction that `s` MUST be less than or equal to `n / 2`.
// Its return value records whether the signature is valid.
//
// Note: The signature MUST have the trailing `sighash` byte.
func (k *PublicKey) VerifyASN1BIP0066(hash, sig []byte) bool {
	r, s, err := parseASN1SignatureShitcoin(sig)
	if err != nil {
		return false
	}

	if s.IsGreaterThanHalfN() != 0 {
		return false
	}

	return k.Verify(hash, r, s)
}

// RecoverPublicKey recovers the public key from the signature
// `(r, s, recoveryID)` over `hash`.  `recoverID` MUST be in the range
// `[0,3]`.
//
// Note: `s` in the range `[1, n)` is considered valid here.  It is the
// caller's responsibility to check `s.IsGreaterThanHalfN()` as required.
func RecoverPublicKey(hash []byte, r, s *secp256k1.Scalar, recoveryID byte) (*PublicKey, error) {
	if r.IsZero() != 0 || s.IsZero() != 0 {
		return nil, errInvalidRorS
	}

	// This roughly follows SEC 1, Version 2.0, Section 4.1.6, except
	// that instead of computing all possible R candidates from r,
	// the recoveryID explicitly encodes which point to use.

	R, err := secp256k1.RecoverPoint(r, recoveryID)
	if err != nil {
		return nil, err
	}
	if R.IsIdentity() != 0 {
		// This can NEVER happen as secp256k1.RecoverPoint always
		// returns a point that is on the curve or an error.
		panic(errRIsInfinity)
	}

	// 1.5. Compute e from M using Steps 2 and 3 of ECDSA signature verification.

	e, err := hashToScalar(hash)
	if err != nil {
		return nil, err
	}
	negE := secp256k1.NewScalar().Negate(e)

	// 1.6.1 Compute a candidate public key as: Q = r^(−1)(sR − eG).
	//
	// Rewriting this to be nicer, (-e)*r^(-1) * G + s*r^(-1) * R.

	rInv := secp256k1.NewScalar().Invert(r)
	u1 := secp256k1.NewScalar().Multiply(negE, rInv)
	u2 := secp256k1.NewScalar().Multiply(s, rInv)

	Q := secp256k1.NewIdentityPoint().DoubleScalarMultBasepointVartime(u1, u2, R)

	return NewPublicKeyFromPoint(Q)
}

func sign(rand io.Reader, d *PrivateKey, hBytes []byte) (*secp256k1.Scalar, *secp256k1.Scalar, byte, error) {
	var recoveryID byte

	// Note/yawning: `e` (derived from `hash`) in steps 4 and 5, is
	// unchanged throughout the process even if a different `k`
	// needs to be selected, thus, the value is derived first
	// before the rejection sampling loop.

	// 4. Use the hash function selected during the setup procedure
	// to compute the hash value:
	//   H = Hash(M)
	// of length hashlen octets as specified in Section 3.5. If the
	// hash function outputs “invalid”, output “invalid” and stop.

	// 5. Derive an integer e from H as follows:
	// 5.1. Convert the octet string H to a bit string H using the
	// conversion routine specified in Section 2.3.2.
	// 5.2. Set E = H if ceil(log2(n)) >= 8(hashlen), and set E equal
	// to the leftmost ceil(log2(n)) bits of H if ceil(log2(n)) <
	// 8(hashlen).
	// 5.3. Convert the bit string E to an octet string E using the
	// conversion routine specified in Section 2.3.1.
	// 5.4. Convert the octet string E to an integer e using the
	// conversion routine specified in Section 2.3.8.

	e, err := hashToScalar(hBytes)
	if err != nil {
		return nil, nil, 0, err
	}

	// While I normally will be content to let idiots compromise
	// their signing keys, past precident (eg: Sony Computer
	// Entertainment America, Inc v. Hotz) shows that "idiots"
	// are also litigatious asshats.
	//
	// Hardening the user-provided RNG is a sensible thing
	// to do, even if this wasn't something that has historically
	// been a large problem.

	fixedRng, err := mitigateDebianAndSony(rand, domainSepECDSA, d, hBytes)
	if err != nil {
		return nil, nil, 0, err
	}

	var r, s *secp256k1.Scalar
	for {
		// 1. Select an ephemeral elliptic curve key pair (k, R) with
		// R = (xR, yR) associated with the elliptic curve domain parameters
		// T established during the setup procedure using the key pair
		// generation primitive specified in Section 3.2.1.

		k, err := sampleRandomScalar(fixedRng)
		if err != nil {
			// This is essentially totally untestable, as:
			// - This is astronomically unlikely to begin with.
			// - `fixedRng` is cSHAKE, so it is hard to force it to
			//   generate pathologically bad output.
			return nil, nil, 0, fmt.Errorf("secp256k1/secec/ecdsa: failed to generate k: %w", err)
		}
		R := secp256k1.NewIdentityPoint().ScalarBaseMult(k)

		// 2. Convert the field element xR to an integer xR using the
		// conversion routine specified in Section 2.3.9.

		rXBytes, rYIsOdd := splitUncompressedPoint(R.UncompressedBytes())

		// 3. Set r = xR mod n. If r = 0, or optionally r fails to meet
		// other publicly verifiable criteria (see below), return to Step 1.

		var didReduce uint64
		r, didReduce = secp256k1.NewScalar().SetBytes((*[secp256k1.ScalarSize]byte)(rXBytes))
		if r.IsZero() != 0 {
			// This is essentially totally untestable since the odds
			// of generating `r = 0` is astronomically unlikely.
			continue
		}

		// (Steps 4/5 done prior to loop.)

		// 6. Compute: s = k^−1 (e + r * dU) mod n.
		// If s = 0, return to Step 1.

		kInv := secp256k1.NewScalar().Invert(k)
		s = secp256k1.NewScalar()
		s.Multiply(r, d.scalar).Add(s, e).Multiply(s, kInv)
		if s.IsZero() == 0 {
			recoveryID = (byte(didReduce) << 1) | byte(rYIsOdd)
			break
		}
	}

	// 7. Output S = (r, s). Optionally, output additional
	// information needed to recover R efficiently from r (see below).

	// The signer may replace (r, s) with (r, −s mod n), because this
	// is an equivalent signature.
	//
	// Note/yawning: To prevent mallability, Shitcoin enforces s <= n/2.
	// As either is valid in any other context, always produce
	// signatures of that form.

	negateS := s.IsGreaterThanHalfN()
	s.ConditionalNegate(s, negateS)
	recoveryID ^= byte(negateS)

	return r, s, recoveryID, nil
}

func verify(q *PublicKey, hBytes []byte, r, s *secp256k1.Scalar) error {
	// 1. If r and s are not both integers in the interval [1, n − 1],
	// output “invalid” and stop.
	//
	// Note/yawning: This is somewhat redundant because the various
	// ASN.1 parsing routines reject these, but we also support
	// verifying user supplied (r, s), so just check again.

	if r.IsZero() != 0 || s.IsZero() != 0 {
		return errInvalidRorS
	}

	// 2. Use the hash function established during the setup procedure
	// to compute the hash value:
	//   H = Hash(M)
	// of length hashlen octets as specified in Section 3.5. If the
	// hash function outputs “invalid”, output “invalid” and stop.

	// 3. Derive an integer e from H as follows:
	// 3.1. Convert the octet string H to a bit string H using the
	// conversion routine specified in Section 2.3.2.
	// 3.2. Set E = H if ceil(log2(n)) >= 8(hashlen), and set E equal
	// to the leftmost ceil(log2(n)) bits of H if ceil(log2(n)) <
	// 8(hashlen).
	// 3.3. Convert the bit string E to an octet string E using the
	// conversion routine specified in Section 2.3.1.
	// 3.4. Convert the octet string E to an integer e using the
	// conversion routine specified in Section 2.3.8.

	e, err := hashToScalar(hBytes)
	if err != nil {
		return err
	}

	// 4. Compute: u1 = e(s^−1) mod n and u2 = r(s^-1) mod n.

	sInv := secp256k1.NewScalar().Invert(s)
	u1 := secp256k1.NewScalar().Multiply(e, sInv)
	u2 := secp256k1.NewScalar().Multiply(r, sInv)

	// 5. Compute: R = (xR, yR) = u1 * G + u2 * QU.
	// If R = O, output “invalid” and stop.

	R := secp256k1.NewIdentityPoint().DoubleScalarMultBasepointVartime(u1, u2, q.point)
	if R.IsIdentity() != 0 {
		return errRIsInfinity
	}

	// 6. Convert the field element xR to an integer xR using the
	// conversion routine specified in Section 2.3.9.
	//
	// 7. Set v = xR mod n.

	xRBytes, _ := R.XBytes() // Can't fail, R != Inf.
	v, _ := secp256k1.NewScalar().SetBytes((*[secp256k1.ScalarSize]byte)(xRBytes))

	// 8. Compare v and r — if v = r, output “valid”, and if
	// v != r, output “invalid”.

	if v.Equal(r) != 1 {
		return errVNeqR
	}

	return nil
}

// hashToScalar converts a hash to a scalar per SEC 1, Version 2.0,
// Section 4.1.3, Step 5 (and Section 4.1.4, Step 3).
//
// Note: This also will reduce the resulting scalar such that it is
// in the range [0, n), which is fine for ECDSA.
func hashToScalar(hash []byte) (*secp256k1.Scalar, error) {
	if len(hash) < secp256k1.ScalarSize {
		return nil, errInvalidDigest
	}

	// TLDR; The left-most Ln-bits of hash.
	var tmp [secp256k1.ScalarSize]byte
	copy(tmp[:], hash)

	s, _ := secp256k1.NewScalar().SetBytes(&tmp) // Reduction info unneeded.
	return s, nil
}

func bytesToCanonicalScalar(sBytes []byte) (*secp256k1.Scalar, error) {
	var (
		tmp    [secp256k1.ScalarSize]byte
		sLen   = len(sBytes)
		offset = 0
	)
	if sLen > secp256k1.ScalarSize || sLen == 0 {
		return nil, errInvalidScalar
	}
	if sLen < secp256k1.ScalarSize {
		offset = secp256k1.ScalarSize - sLen
	}
	copy(tmp[offset:], sBytes)

	s, err := secp256k1.NewScalarFromCanonicalBytes(&tmp)
	if err != nil {
		return nil, errInvalidScalar
	}

	return s, nil
}

func mitigateDebianAndSony(rand io.Reader, ctx string, k *PrivateKey, hBytes []byte) (io.Reader, error) {
	// There are documented attacks that can exploit even the
	// most subtle amounts of bias (< 1-bit) in the generation
	// of the ECDSA nonce.
	//
	// RFC 6979 proposes to use HMAC_DRBG instantiated
	// with the private key and message digest, and making
	// signatures fully deterministic.
	//
	// We go one step further, and use cSHAKE256 to mix
	// the private key, 256-bits of entropy, and the message
	// digest.
	//
	// See:
	// - https://eprint.iacr.org/2020/615.pdf
	// - https://eprint.iacr.org/2019/1155.pdf

	if rand == nil {
		rand = csrand.Reader
	}

	var tmp [wantedEntropyBytes]byte
	if _, err := io.ReadFull(rand, tmp[:]); err != nil {
		return nil, errors.Join(errEntropySource, err)
	}

	xof := sha3.NewCShake256(nil, []byte("Honorary Debian/Sony RNG mitigation:"+ctx))
	_, _ = xof.Write(k.scalar.Bytes())
	_, _ = xof.Write(tmp[:])
	_, _ = xof.Write(hBytes)
	return xof, nil
}

func sampleRandomScalar(rand io.Reader) (*secp256k1.Scalar, error) {
	// Do rejection sampling to ensure that there is no bias in the
	// scalar values.  Note that the odds of a single failure are
	// approximately p = 3.73 * 10^-39, so even requiring a single
	// retry is unlikely unless the entropy source is broken.
	var (
		tmp [secp256k1.ScalarSize]byte
		s   = secp256k1.NewScalar()
	)
	for i := 0; i < maxScalarResamples; i++ {
		if _, err := io.ReadFull(rand, tmp[:]); err != nil {
			return nil, errors.Join(errEntropySource, err)
		}

		_, didReduce := s.SetBytes(&tmp)
		if didReduce == 0 && s.IsZero() == 0 {
			return s, nil
		}
	}

	return nil, errRejectionSampling
}
