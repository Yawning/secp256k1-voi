package secec

import (
	stdasn1 "encoding/asn1"
	"errors"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

var (
	oidEcPublicKey = stdasn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidSecp256k1   = stdasn1.ObjectIdentifier{1, 3, 132, 0, 10}
)

// ParseASN1PublicKey parses a ASN.1 encoded public key as specified in
// SEC 1, Version 2.0, Appendix C.3.
//
// WARNING: This is incomplete and "best-effort", because ASN.1 and
// X.509 are gigantic steaming piles of shit.  Really, the only reason
// this even exists is so that the package can be tested against
// Wycheproof.
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

func parseASN1Signature(data []byte) ([]byte, []byte, error) {
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

	return rBytes, sBytes, nil
}
