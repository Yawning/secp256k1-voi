package secec

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

var (
	oidEcPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidSecp256k1   = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
)

type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

// ParseASN1PublicKey parses a ASN.1 encoded public key as specified in
// SEC 1, Version 2.0, Appendix C.3.
//
// WARNING: This is incomplete and "best-effort", because ASN.1 and
// X.509 are gigantic steaming piles of shit.  Really, the only reason
// this even exists is so that the package can be tested against
// Wycheproof.
func ParseASN1PublicKey(data []byte) (*PublicKey, error) {
	var spki subjectPublicKeyInfo
	rest, err := asn1.Unmarshal(data, &spki)
	if err != nil {
		return nil, fmt.Errorf("secp256k1/secec: malfomed ASN.1: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("secp256k1/secec: trailing data after ASN.1 of public-key")
	}

	if !spki.Algorithm.Algorithm.Equal(oidEcPublicKey) {
		return nil, errors.New("secp256k1/secec: algorithm is not ecPublicKey")
	}

	// XXX: This is probably overly stringent, but it is what
	// `crypto/x509/parser.go:parsePublicKey` does.
	var curveOID asn1.ObjectIdentifier
	rest, err = asn1.Unmarshal(spki.Algorithm.Parameters.FullBytes, &curveOID)
	if err != nil {
		return nil, fmt.Errorf("secp256k1/secec: failed to read named-curve OID: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("secp256k1/secec: trailing data after ASN.1 of named-curve OID")
	}

	if !curveOID.Equal(oidSecp256k1) {
		return nil, errors.New("secp256k1/secec: named curve is not secp256k1")
	}

	encodedPoint := spki.SubjectPublicKey.RightAlign()
	return NewPublicKey(encodedPoint)
}
