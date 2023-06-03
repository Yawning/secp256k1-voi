// Copyright (c) 2023 Yawning Angel
//
// SPDX-License-Identifier: BSD-3-Clause

package secec

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

	"gitlab.com/yawning/secp256k1-voi"
	"gitlab.com/yawning/secp256k1-voi/internal/disalloweq"
	"gitlab.com/yawning/secp256k1-voi/internal/field"
)

const (
	// SchnorrPublicKeySize is the size of a BIP-0340 Schnorr public key
	// in bytes.
	SchnorrPublicKeySize = 32
	// SchnorrSignatureSize is the size of a BIP-0340 Schnorr signature
	// in bytes.
	SchnorrSignatureSize = 64
	// SchnorrMessageSize is the size of a BIP-0340 Schnorr signature
	// message in bytes.
	SchnorrMessageSize = 32

	schnorrEntropySize = 32

	schnorrTagAux       = "BIP0340/aux"
	schnorrTagNonce     = "BIP0340/nonce"
	schnorrTagChallenge = "BIP0340/challenge"

	domainSepSchnorr = "BIP0340-Sign"
)

// SignSchnorr signs signs `msg` (which MUST be `SchnorrMessageSize`
// bytes in length) using the PrivateKey `k`, using the signing procedure
// as specified in BIP-0340.  It returns the byte-encoded signature.
func (k *PrivateKey) SignSchnorr(rand io.Reader, msg []byte) ([]byte, error) {
	if len(msg) != SchnorrMessageSize {
		return nil, errors.New("secp256k1/secec/schnorr: invalid message size")
	}

	// BIP-0340 cautions about how deterministic nonce creation a la
	// RFC6979 can lead to key compromise if the same key is shared
	// between ECDSA and Schnorr signatures due to nonce reuse.
	//
	// This implementation handles that problem by using cSHAKE with
	// a domain separation parameter depending on usage, so even in
	// the pathological case where the entropy source is non-functional,
	// the sampled entropy will be distinct between ECDSA and Schnorr
	// signatures.
	//
	// Other libraries may or may not have this sort of safeguard in
	// place, so it still might not be the best idea to use the same
	// signing key for both schemes, but it is theoretically safe with
	// this library, and other libraries just need to not suck.

	fixedRng, err := mitigateDebianAndSony(rand, domainSepSchnorr, k, msg)
	if err != nil {
		return nil, err
	}
	var auxEntropy [schnorrEntropySize]byte
	if _, err = io.ReadFull(fixedRng, auxEntropy[:]); err != nil {
		return nil, err
	}

	return signSchnorr(&auxEntropy, k, (*[SchnorrMessageSize]byte)(msg))
}

// SchnorrPublicKey is a public key for verifying BIP-0340 Schnorr signatures.
type SchnorrPublicKey struct {
	_ disalloweq.DisallowEqual

	point  *secp256k1.Point // INVARIANT: Never identity, lift_x applied
	xBytes []byte           // SEC 1 X-coordinate
}

// Bytes returns a copy of the uncompressed encoding of the public key.
func (k *SchnorrPublicKey) Bytes() []byte {
	if k.xBytes == nil {
		panic("secp256k1/secec/schnorr: uninitialized public key")
	}

	var tmp [SchnorrPublicKeySize]byte
	copy(tmp[:], k.xBytes)
	return tmp[:]
}

// Equal returns whether `x` represents the same public key as `k`.
// This check is performed in constant time as long as the key types
// match.
func (k *SchnorrPublicKey) Equal(x crypto.PublicKey) bool {
	other, ok := x.(*SchnorrPublicKey)
	if !ok {
		return false
	}

	return other.point.Equal(k.point) == 1
}

// Verify verifies the Schnorr signature `sig` of `msg`, using the
// SchnorrPublicKey `k`, using the verification procedure as specifed
// in BIP-0340.  Its return value records whether the signature is
// valid.
func (k *SchnorrPublicKey) Verify(msg, sig []byte) bool {
	if len(msg) != SchnorrMessageSize {
		return false
	}
	if len(sig) != SchnorrSignatureSize {
		return false
	}

	// The algorithm Verify(pk, m, sig) is defined as:

	// Let P = lift_x(int(pk)); fail if that fails.
	//
	// Note/yawning: k contains a pre-deserialized point, deserialization
	// process is equivalent to lift_x.

	// Let r = int(sig[0:32]); fail if r ≥ p.
	// Let s = int(sig[32:64]); fail if s ≥ n.
	// Let e = int(hashBIP0340/challenge(bytes(r) || bytes(P) || m)) mod n.

	ok, s, e, sigRXBytes := parseSchnorrSignature(k.xBytes, msg, sig)
	if !ok {
		return false
	}

	// Let R = s⋅G - e⋅P.

	e.Negate(e)
	R := secp256k1.NewIdentityPoint().DoubleScalarMultBasepointVartime(s, e, k.point)

	// Fail if is_infinite(R).
	// Fail if not has_even_y(R).
	// Fail if x(R) ≠ r.
	// Return success iff no failure occurred before reaching this point.

	return verifySchnorrSignatureR(sigRXBytes, R)
}

// NewSchnorrPublicKey checks that `key` is valid, and returns a
// SchnorrPublicKey.
func NewSchnorrPublicKey(key []byte) (*SchnorrPublicKey, error) {
	if len(key) != SchnorrPublicKeySize {
		return nil, errors.New("secp256k1/secec/schnorr: invalid public key")
	}

	var ptBytes [secp256k1.CompressedPointSize]byte
	ptBytes[0] = 0x02
	copy(ptBytes[1:], key)

	pt, err := secp256k1.NewPointFromBytes(ptBytes[:])
	if err != nil {
		return nil, fmt.Errorf("secp256k1/secec/schnorr: failed to decompress public key: %w", err)
	}

	return &SchnorrPublicKey{
		point:  pt,
		xBytes: append([]byte{}, key...),
	}, nil
}

// NewSchnorrPublicKeyFromPoint checks that `point` is valid, and returns
// a SchnorrPublicKey.
//
// Note: This routine accepts any point on the curve, and will fixup the
// Y-coordinate if required.
func NewSchnorrPublicKeyFromPoint(point *secp256k1.Point) (*SchnorrPublicKey, error) {
	pt := secp256k1.NewPointFrom(point)
	if pt.IsIdentity() != 0 {
		return nil, errors.New("secp256k1/secec/schnorr: public key is the point at infinity")
	}

	// "Implicitly choosing the Y coordinate that is even"
	pt.ConditionalNegate(pt, pt.IsYOdd())

	ptX, _ := pt.XBytes() // Can't fail, pt != Inf

	return &SchnorrPublicKey{
		point:  pt,
		xBytes: ptX,
	}, nil
}

func newSchnorrPublicKeyFromPrivateKey(sk *PrivateKey) *SchnorrPublicKey {
	pt := secp256k1.NewPointFrom(sk.publicKey.point)

	xBytes, yIsOdd := splitUncompressedPoint(sk.publicKey.pointBytes)
	pt.ConditionalNegate(pt, yIsOdd)

	return &SchnorrPublicKey{
		point:  pt,
		xBytes: xBytes,
	}
}

func schnorrTaggedHash(tag string, vals ...[]byte) []byte {
	hashedTag := sha256.Sum256([]byte(tag))

	h := sha256.New()
	_, _ = h.Write(hashedTag[:])
	_, _ = h.Write(hashedTag[:])
	for _, v := range vals {
		_, _ = h.Write(v)
	}

	return h.Sum(nil)
}

func signSchnorr(auxRand *[schnorrEntropySize]byte, sk *PrivateKey, msg *[SchnorrMessageSize]byte) ([]byte, error) {
	// The algorithm Sign(sk, m) is defined as:

	// Let d' = int(sk)
	// Fail if d' = 0 or d' ≥ n
	// Let P = d'⋅G
	//
	// Note/yawning: sk is a pre-deserialized private key, that is
	// guaranteed to be valid.  Likewise sk.PublicKey() is pre-generated,
	// and is used over sk.SchnorrPublicKey(), because the SchnorrPublicKey
	// caches the result of lift_x for verification.

	// Let d = d' if has_even_y(P), otherwise let d = n - d' .

	pBytes, negateD := splitUncompressedPoint(sk.PublicKey().Bytes())
	d := secp256k1.NewScalarFrom(sk.scalar)
	d.ConditionalNegate(d, negateD)

	// Let t be the byte-wise xor of bytes(d) and hashBIP0340/aux(a)[11].

	var t [schnorrEntropySize]byte
	subtle.XORBytes(t[:], schnorrTaggedHash(schnorrTagAux, auxRand[:]), d.Bytes())

	// Let rand = hashBIP0340/nonce(t || bytes(P) || m)[12].

	rand := schnorrTaggedHash(schnorrTagNonce, t[:], pBytes, msg[:])

	// Let k' = int(rand) mod n[13].

	kPrime, _ := secp256k1.NewScalar().SetBytes((*[secp256k1.ScalarSize]byte)(rand))

	// Fail if k' = 0.

	if kPrime.IsZero() != 0 {
		// In theory this is a probabalistic failure, however the odds
		// of this happening are basically non-existent.
		return nil, errors.New("secp256k1/secec/schnorr: k' = 0")
	}

	// Let R = k'⋅G.

	R := secp256k1.NewIdentityPoint().ScalarBaseMult(kPrime)
	rXBytes, rYIsOdd := splitUncompressedPoint(R.UncompressedBytes())

	// Let k = k' if has_even_y(R), otherwise let k = n - k' .

	k := secp256k1.NewScalar().ConditionalNegate(kPrime, rYIsOdd)

	// Let e = int(hashBIP0340/challenge(bytes(R) || bytes(P) || m)) mod n.

	eBytes := schnorrTaggedHash(schnorrTagChallenge, rXBytes, pBytes, msg[:])
	e, _ := secp256k1.NewScalar().SetBytes((*[secp256k1.ScalarSize]byte)(eBytes))

	// Let sig = bytes(R) || bytes((k + ed) mod n).

	sum := secp256k1.NewScalar().Multiply(e, d) // ed
	sum.Add(k, sum)                             // k + ed
	sig := make([]byte, 0, SchnorrSignatureSize)
	sig = append(sig, rXBytes...)
	sig = append(sig, sum.Bytes()...)

	// If Verify(bytes(P), m, sig) (see below) returns failure, abort[14].
	//
	// Note/yawning: "It is recommended, but can be omitted if the
	// computation cost is prohibitive.".  Doing this check with the
	// standard verification routine, triples the time it takes to sign.
	//
	// There is a trivial optimization that replaces the
	// DoubleScalarMultBasepointVartime with a ScalarBaseMult when
	// verifying signatures signed by your own private key, so do that
	// instead.
	//
	// Note: Apart from the faster calculation of R, the verification
	// process is identical to the normal verify.

	if !verifySchnorrSelf(d, sk.SchnorrPublicKey().Bytes(), msg[:], sig) {
		return nil, errors.New("secp256k1/secec/schnorr: failed to verify sig")
	}

	return sig, nil
}

func verifySchnorrSelf(d *secp256k1.Scalar, pkXBytes, msg, sig []byte) bool {
	ok, s, e, sigRXBytes := parseSchnorrSignature(pkXBytes, msg, sig)
	if !ok {
		return false
	}

	// Let R = (s - d⋅e)⋅G.
	//
	// Note/yawning: d is the private key (or it's negation), so deriving
	// R needs to be done in constant-time.

	factor := secp256k1.NewScalar().Multiply(d, e)
	factor.Subtract(s, factor)
	R := secp256k1.NewIdentityPoint().ScalarBaseMult(factor)

	return verifySchnorrSignatureR(sigRXBytes, R)
}

func parseSchnorrSignature(pkXBytes, msg, sig []byte) (bool, *secp256k1.Scalar, *secp256k1.Scalar, []byte) {
	if len(msg) != SchnorrMessageSize {
		return false, nil, nil, nil
	}
	if len(sig) != SchnorrSignatureSize {
		return false, nil, nil, nil
	}

	// Let r = int(sig[0:32]); fail if r ≥ p.
	//
	// Note/yawning: If one were to want to do this without using the
	// internal field package, the point decompression routine also
	// would work, but would be slower.

	sigRXBytes := sig[0:32]
	if !field.BytesAreCanonical((*[field.ElementSize]byte)(sigRXBytes)) {
		return false, nil, nil, nil
	}

	// Let s = int(sig[32:64]); fail if s ≥ n.

	s, err := secp256k1.NewScalarFromCanonicalBytes((*[secp256k1.ScalarSize]byte)(sig[32:64]))
	if err != nil {
		return false, nil, nil, nil
	}

	// Let e = int(hashBIP0340/challenge(bytes(r) || bytes(P) || m)) mod n.

	eBytes := schnorrTaggedHash(schnorrTagChallenge, sigRXBytes, pkXBytes, msg)
	e, _ := secp256k1.NewScalar().SetBytes((*[secp256k1.ScalarSize]byte)(eBytes))

	return true, s, e, sigRXBytes
}

func verifySchnorrSignatureR(sigRXBytes []byte, R *secp256k1.Point) bool {
	// Fail if is_infinite(R).

	if R.IsIdentity() != 0 {
		return false
	}

	// Note/yawning: Doing it this way saves repeated rescaling, since
	// the curve implementation always does the inversion.

	rXBytes, rYIsOdd := splitUncompressedPoint(R.UncompressedBytes())

	// Fail if not has_even_y(R).

	if rYIsOdd != 0 {
		return false
	}

	// Fail if x(R) ≠ r.
	//
	// Note/yawning: Vartime compare, because this is verification.

	if !bytes.Equal(rXBytes, sigRXBytes[:]) {
		return false
	}

	return true
}
