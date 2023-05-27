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
	stdasn1 "encoding/asn1"
	"errors"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"

	"gitlab.com/yawning/secp256k1-voi.git"
)

var (
	oidEcPublicKey = stdasn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidSecp256k1   = stdasn1.ObjectIdentifier{1, 3, 132, 0, 10}
)

// ParseASN1PublicKey parses a ASN.1 encoded public key as specified in
// SEC 1, Version 2.0, Appendix C.3.
//
// WARNING: This is incomplete and "best-effort".  In particular parsing
// the case where the curve is parameterized as part of the public key
// is not, and will not be supported.
func ParseASN1PublicKey(data []byte) (*PublicKey, error) {
	var (
		inner     cryptobyte.String
		algorithm cryptobyte.String

		subjectPublicKey       stdasn1.BitString
		oidAlgorithm, oidCurve stdasn1.ObjectIdentifier
	)

	input := cryptobyte.String(data)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1(&algorithm, asn1.SEQUENCE) ||
		!inner.ReadASN1BitString(&subjectPublicKey) ||
		!inner.Empty() ||
		!algorithm.ReadASN1ObjectIdentifier(&oidAlgorithm) ||
		!algorithm.ReadASN1ObjectIdentifier(&oidCurve) ||
		!algorithm.Empty() {
		return nil, errors.New("secp256k1: malformed ASN.1 Subject Public Key Info")
	}

	if !oidAlgorithm.Equal(oidEcPublicKey) {
		return nil, errors.New("secp256k1/secec: algorithm is not ecPublicKey")
	}
	if !oidCurve.Equal(oidSecp256k1) {
		return nil, errors.New("secp256k1/secec: named curve is not secp256k1")
	}

	encodedPoint := subjectPublicKey.RightAlign()
	return NewPublicKey(encodedPoint)
}

func parseASN1Signature(data []byte) (*secp256k1.Scalar, *secp256k1.Scalar, error) {
	var (
		inner          cryptobyte.String
		rBytes, sBytes []byte
	)

	input := cryptobyte.String(data)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(&rBytes) ||
		!inner.ReadASN1Integer(&sBytes) ||
		!inner.Empty() {
		return nil, nil, errors.New("secp256k1/secec/ecdsa: malformed ASN.1 signature")
	}

	r, err := bytesToCanonicalScalar(rBytes)
	if err != nil || r.IsZero() != 0 {
		return nil, nil, errInvalidScalar
	}
	s, err := bytesToCanonicalScalar(sBytes)
	if err != nil || s.IsZero() != 0 {
		return nil, nil, errInvalidScalar
	}

	return r, s, nil
}

func buildASN1Signature(r, s *secp256k1.Scalar) []byte {
	var rBig, sBig big.Int
	rBig.SetBytes(r.Bytes())
	sBig.SetBytes(s.Bytes())

	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(&rBig)
		b.AddASN1BigInt(&sBig)
	})

	return b.BytesOrPanic()
}
