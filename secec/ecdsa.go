package secec

import (
	"errors"

	"gitlab.com/yawning/secp256k1-voi.git"
)

var (
	errInvalidScalar = errors.New("secp256k1/secec/ecdsa: invalid scalar")
	errInvalidDigest = errors.New("secp256k1/secec/ecdsa: invalid digest")
	errRIsInfinity   = errors.New("secp256k1/secec/ecdsa: R is the point at infinity")
	errVNeqR         = errors.New("secp256k1/secec/ecdsa: v does not equal r")
)

// VerifyASN1 verifies the ASN.1 encoded signature `sig` of `hash`,
// using the PublicKey `k`, using the verification procedure as specifed
// in SEC 1, Version 2.0, Section 4.1.4.  Its return value records
// whether the signature is valid.
//
// Note: The signature MUST be `SEQUENCE { r INTEGER, s INTEGER }`,
// as in encoded as a `ECDSA-Sig-Value`, WITHOUT the optional `a` and
// `y` fields.
func (k *PublicKey) VerifyASN1(hash, sig []byte) bool {
	rBytes, sBytes, err := parseASN1Signature(sig)
	if err != nil {
		return false
	}

	_, err = verify(k, hash, rBytes, sBytes)
	return err == nil
}

// VerifyASN1Shitcoin verifies the ASN.1 encoded signature `sig` of `hash`,
// using the PublicKey `k`, using the verification procedure as specifed
// in SEC 1, Version 2.0, Section 4.1.4, with the additional restriction
// that `s` MUST be less than or equal to `n / 2`.  Its return value
// records whether the signature is valid.
//
// Note: The signature MUST be `SEQUENCE { r INTEGER, s INTEGER }`,
// as in encoded as a `ECDSA-Sig-Value`, WITHOUT the optional `a` and
// `y` fields.
func (k *PublicKey) VerifyASN1Shitcoin(hash, sig []byte) bool {
	// TODO: Looking at BIP-0066, the checks done appear to match
	// parseASN1Signature's behavior, but this probably needs more
	// testing.
	//
	// However, "Zero, zero fucks given.  Ah Ah Ah.".
	rBytes, sBytes, err := parseASN1Signature(sig)
	if err != nil {
		return false
	}

	sGtHalfN, err := verify(k, hash, rBytes, sBytes)
	return err == nil && sGtHalfN == 0
}

func verify(q *PublicKey, hBytes, rBytes, sBytes []byte) (uint64, error) {
	// 1. If r and s are not both integers in the interval [1, n − 1],
	// output “invalid” and stop.

	r, err := bytesToCanonicalScalar(rBytes)
	if err != nil || r.IsZero() != 0 {
		return 0, errInvalidScalar
	}
	s, err := bytesToCanonicalScalar(sBytes)
	if err != nil || s.IsZero() != 0 {
		return 0, errInvalidScalar
	}

	sGtHalfOrder := s.IsGreaterThanHalfN()

	// 2. Use the hash function established during the setup procedure
	// to compute the hash value:
	//   H = Hash(M)
	// of length hashlen octets as specified in Section 3.5. If the
	// hash function outputs “invalid”, output “invalid” and stop.

	// Note/yawning: H is provided as the input `hBytes`, but at
	// least ensure  that it is "sensible", where we somewhat
	// arbitrarily define "at least 128-bits" as "sensible".
	// Realistically everyone is going to use at least 256-bits.

	if hLen := len(hBytes); hLen < 16 {
		return sGtHalfOrder, errInvalidDigest
	}

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

	e := hashToScalar(hBytes)

	// 4. Compute: u1 = e(s^−1) mod n and u2 = r(s^-1) mod n.

	sInv := secp256k1.NewScalar().Invert(s)
	u1 := secp256k1.NewScalar().Multiply(e, sInv)
	u2 := secp256k1.NewScalar().Multiply(r, sInv)

	// 5. Compute: R = (xR, yR) = u1 * G + u2 * QU.
	// If R = O, output “invalid” and stop.

	R := secp256k1.NewIdentityPoint().DoubleScalarMultBasepointVartime(u1, u2, q.point)
	if R.IsIdentity() != 0 {
		return sGtHalfOrder, errRIsInfinity
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
		return sGtHalfOrder, errVNeqR
	}

	return sGtHalfOrder, nil
}

// hashToScalar converts a hash to a scalar per SEC 1, Version 2.0,
// Section 4.1.3, Step 5 (and Section 4.1.4, Step 3).
//
// Note: This also will reduce the resulting scalar such that it is
// in the range [0, n), which is fine for ECDSA.
func hashToScalar(hash []byte) *secp256k1.Scalar {
	// tldr; The left-most Ln-bits of hash.
	var (
		tmp    [secp256k1.ScalarSize]byte
		offset = 0
	)
	if hLen := len(hash); hLen < secp256k1.ScalarSize {
		offset = secp256k1.ScalarSize - hLen
	}
	copy(tmp[offset:], hash)

	s, _ := secp256k1.NewScalar().SetBytes(&tmp) // Reduction info unneeded.
	return s
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
