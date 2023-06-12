// Copyright (c) 2023 Yawning Angel
//
// SPDX-License-Identifier: BSD-3-Clause

// Package secec implements the common primitives on top of secp256k1,
// with an API that is close to the runtime library's `crypto/ecdsa`
// and `crypto/ecdh` packages.
package secec

import (
	"crypto"
	"errors"
	"fmt"
	"io"

	"gitlab.com/yawning/secp256k1-voi"
	"gitlab.com/yawning/secp256k1-voi/internal/disalloweq"
)

// PrivateKey is a secp256k1 private key.
type PrivateKey struct {
	_ disalloweq.DisallowEqual

	scalar           *secp256k1.Scalar // INVARIANT: Always [1,n)
	publicKey        *PublicKey
	schnorrPublicKey *SchnorrPublicKey
}

// Bytes returns a copy of the encoding of the private key.
func (k *PrivateKey) Bytes() []byte {
	return k.scalar.Bytes()
}

// Scalar returns a copy of the scalar underlying `k`.
func (k *PrivateKey) Scalar() *secp256k1.Scalar {
	return secp256k1.NewScalar().Set(k.scalar)
}

// ECDH performs a ECDH exchange and returns the shared secret as
// specified in SEC 1, Version 2.0, Section 3.3.1, and returns the
// x-coordinate encoded according to SEC 1, Version 2.0, Section 2.3.5.
// The result is never the point at infinity.
func (k *PrivateKey) ECDH(remote *PublicKey) ([]byte, error) {
	pt := secp256k1.NewIdentityPoint().ScalarMult(k.scalar, remote.point)
	return pt.XBytes()
}

// Equal returns whether `x` represents the same private key as `k`.
// This check is performed in constant time as long as the key types
// match.
func (k *PrivateKey) Equal(x crypto.PrivateKey) bool {
	other, ok := x.(*PrivateKey)
	if !ok {
		return false
	}

	return other.scalar.Equal(k.scalar) == 1
}

func (k *PrivateKey) Public() crypto.PublicKey {
	return k.publicKey
}

// PublicKey returns the ECDSA/ECDH public key corresponding to `k`.
func (k *PrivateKey) PublicKey() *PublicKey {
	return k.publicKey
}

// SchnorrPublicKey returns the BIP-0340 Schnorr signature public key
// corresponding to `k`.
func (k *PrivateKey) SchnorrPublicKey() *SchnorrPublicKey {
	return k.schnorrPublicKey
}

// PublicKey is a secp256k1 public key.
type PublicKey struct {
	_ disalloweq.DisallowEqual

	point      *secp256k1.Point // INVARIANT: Never identity
	pointBytes []byte           // Uncompressed SEC 1 encoding
}

// Bytes returns a copy of the uncompressed encoding of the public key.
func (k *PublicKey) Bytes() []byte {
	if k.pointBytes == nil {
		panic("secp256k1/secec: uninitialized public key")
	}

	var tmp [secp256k1.UncompressedPointSize]byte
	copy(tmp[:], k.pointBytes)
	return tmp[:]
}

// ASN1Bytes returns a copy of the ASN.1 encoding of the public key,
// as specified in SEC 1, Version 2.0, Appendix C.3.
func (k *PublicKey) ASN1Bytes() []byte {
	return buildASN1PublicKey(k)
}

// Point returns a copy of the point underlying `k`.
func (k *PublicKey) Point() *secp256k1.Point {
	return secp256k1.NewIdentityPoint().Set(k.point)
}

// Equal returns whether `x` represents the same public key as `k`.
// This check is performed in constant time as long as the key types
// match.
func (k *PublicKey) Equal(x crypto.PublicKey) bool {
	other, ok := x.(*PublicKey)
	if !ok {
		return false
	}

	return other.point.Equal(k.point) == 1
}

// IsYOdd returns true iff the y-coordinate of the PublicKey is odd.
func (k *PublicKey) IsYOdd() bool {
	// Since the PublicKey caches the uncompressed point, this
	// is simple and fast.
	return k.isYOdd() != 0
}

func (k *PublicKey) isYOdd() uint64 {
	return uint64(k.pointBytes[secp256k1.UncompressedPointSize-1] & 1)
}

// GenerateKey generates a new PrivateKey from `rand`.
func GenerateKey(rand io.Reader) (*PrivateKey, error) {
	s, err := sampleRandomScalar(rand)
	if err != nil {
		return nil, err
	}

	return newPrivateKeyFromScalar(s)
}

// NewPrivateKey checks that `key` is valid and returns a PrivateKey.
//
// This follows SEC 1, Version 2.0, Section 2.3.6, which amounts to
// decoding the bytes as a fixed length big endian integer and checking
// that the result is lower than the order of the curve. The zero
// private key is also rejected, as the encoding of the corresponding
// public key would be irregular.
func NewPrivateKey(key []byte) (*PrivateKey, error) {
	if len(key) != secp256k1.ScalarSize {
		return nil, errors.New("secp256k1/secec: invalid private key size")
	}

	s, didReduce := secp256k1.NewScalar().SetBytes((*[secp256k1.ScalarSize]byte)(key))
	if didReduce != 0 || s.IsZero() != 0 {
		return nil, errors.New("secp256k1/secec: invalid private key")
	}

	return newPrivateKeyFromScalar(s)
}

func newPrivateKeyFromScalar(s *secp256k1.Scalar) (*PrivateKey, error) {
	// Note: Caller ensures that s is in the correct range.
	privateKey := &PrivateKey{
		scalar: s,
		publicKey: &PublicKey{
			point: secp256k1.NewIdentityPoint().ScalarBaseMult(s),
		},
	}
	privateKey.publicKey.pointBytes = privateKey.publicKey.point.UncompressedBytes()
	privateKey.schnorrPublicKey = newSchnorrPublicKeyFromPrivateKey(privateKey)

	return privateKey, nil
}

// NewPublicKey checks that `key` is valid and returns a PublicKey.
//
// This decodes an encoded point according to SEC 1, Version 2.0,
// Section 2.3.4. The point at infinity is rejected.
func NewPublicKey(key []byte) (*PublicKey, error) {
	// Note: crypto/ecdsa's version ONLY supports uncompressed points
	// but way too much of the shitcoin ecosystem supports compressed,
	// so might as well support all the formats, and explicitly just
	// reject the identity encoding.
	pt, err := secp256k1.NewIdentityPoint().SetBytes(key)
	if err != nil {
		return nil, fmt.Errorf("secp256k1/secec: invalid public key: %w", err)
	}
	if pt.IsIdentity() != 0 {
		return nil, errors.New("secp256k1/secec: public key is the point at infinity")
	}

	return &PublicKey{
		point:      pt,
		pointBytes: pt.UncompressedBytes(),
	}, nil
}

// NewPublicKeyFromPoint checks that `point` is valid, and returns a PublicKey.
func NewPublicKeyFromPoint(point *secp256k1.Point) (*PublicKey, error) {
	// This duplicates code from NewPublicKey to avoid an extra copy.
	pt := secp256k1.NewPointFrom(point)
	if pt.IsIdentity() != 0 {
		return nil, errors.New("secp256k1/secec: public key is the point at infinity")
	}

	return &PublicKey{
		point:      pt,
		pointBytes: pt.UncompressedBytes(),
	}, nil
}

func splitUncompressedPoint(ptBytes []byte) ([]byte, uint64) {
	if len(ptBytes) != secp256k1.UncompressedPointSize {
		panic("secp256k1/secec: invalid uncompressed point for split")
	}
	xBytes := ptBytes[1 : 1+secp256k1.CoordSize]
	yIsOdd := uint64(ptBytes[len(ptBytes)-1] & 1)

	return xBytes, yIsOdd
}
