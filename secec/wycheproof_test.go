// Copyright (c) 2023 Yawning Angel
//
// SPDX-License-Identifier: BSD-3-Clause

package secec

import (
	"crypto"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"gitlab.com/yawning/secp256k1-voi"
	"gitlab.com/yawning/secp256k1-voi/internal/helpers"
)

const (
	encodingAsn       = "asn"
	encodingWebCrypto = "webcrypto"

	fileEcdhAsn        = "./testdata/wycheproof/ecdh_secp256k1_test.json"
	fileEcdhWebCrypto  = "./testdata/wycheproof/ecdh_secp256k1_webcrypto_test.json"
	fileEcdsaAsnSha256 = "./testdata/wycheproof/ecdsa_secp256k1_sha256_test.json"
	fileEcdsaAsnSha512 = "./testdata/wycheproof/ecdsa_secp256k1_sha512_test.json"
	fileEcdsaShitcoin  = "./testdata/wycheproof/ecdsa_secp256k1_sha256_bitcoin_test.json"

	jwkKtyEc        = "EC"
	jwkCrvSecp256k1 = "P-256K"

	typeEcdsaVerify         = "EcdsaVerify"
	typeEcdsaShitcoinVerify = "EcdsaBitcoinVerify"

	resultValid      = "valid"
	resultAcceptable = "acceptable"
)

var (
	dhFlagsBadPublic = map[string]bool{
		// Failure cases
		"InvalidCompressedPublic": true,
		"InvalidCurveAttack":      true,
		"InvalidEncoding":         true,
		"InvalidPublic":           true,
		"WrongCurve":              true,

		// Encoding: Treat as failure
		"UnnamedCurve": true, // ParseASN1PublicKey does not support this
		"InvalidAsn":   true, // ParseASN1PublicKey is strict
	}

	dhFlagsCompressed = map[string]bool{
		"CompressedPublic": true,
		"CompressedPoint":  true,
	}

	// Pathologically bad ASN.1 signature encodings that should always
	// fail to parse.
	sigFlagsRejectEarly = map[string]bool{
		"BerEncodedSignature":     true,
		"InvalidTypesInSignature": true,
		"InvalidEncoding":         true,
		"MissingZero":             true,
	}

	sigHash = map[string]crypto.Hash{
		"SHA-256": crypto.SHA256,
		"SHA-512": crypto.SHA512,
	}
)

type TestVectors struct {
	Algorithm  string          `json:"algorithm"`
	Schema     string          `json:"schema"`
	Version    string          `json:"generatorVersion"`
	NumTests   int             `json:"numberOfTests"`
	Header     []string        `json:"header"`
	Notes      map[string]Note `json:"notes"`
	TestGroups json.RawMessage `json:"testGroups"`
}

type Note struct {
	BugType     string `json:"bug_type"`
	Description string `json:"descrion"`
}

type DHTestGroup struct {
	Type     string       `json:"type"`
	Curve    string       `json:"curve"`
	Encoding string       `json:"encoding"`
	Tests    []DHTestCase `json:"tests"`
}

type SignatureTestGroup struct {
	Type         string              `json:"type"`
	PublicKey    SignaturePublicKey  `json:"publicKey"`
	PublicKeyDER string              `json:"publicKeyDer"`
	PublicKeyPEM string              `json:"publicKeyPem"`
	Sha          string              `json:"sha"`
	Tests        []SignatureTestCase `json:"tests"`
}

type JsonWebKey struct {
	KeyType string `json:"kty"`
	Crv     string `json:"crv"`
	D       string `json:"d"`
	X       string `json:"x"`
	Y       string `json:"y"`
}

func (jwk *JsonWebKey) IsBasicOk(t *testing.T) error {
	require.EqualValues(t, jwkKtyEc, jwk.KeyType, "kty")
	if jwk.Crv != jwkCrvSecp256k1 {
		return fmt.Errorf("jwk: unsupported curve: '%v'", jwk.Crv)
	}
	return nil
}

func (jwk *JsonWebKey) ToPublic(t *testing.T) (*PublicKey, error) {
	if err := jwk.IsBasicOk(t); err != nil {
		return nil, err
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	require.NoError(t, err, "base64.RawURLEncoding.DecodeString(x)")
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	require.NoError(t, err, "base64.RawURLEncoding.DecodeString(y)")

	pt, err := secp256k1.NewPointFromCoords((*[secp256k1.CoordSize]byte)(xBytes), (*[secp256k1.CoordSize]byte)(yBytes))
	if err != nil {
		return nil, err
	}

	publicKey, err := NewPublicKeyFromPoint(pt)
	require.NoError(t, err, "NewPublicKeyFromPoint")

	return publicKey, nil
}

func (jwk *JsonWebKey) ToPrivate(t *testing.T) (*PrivateKey, error) {
	jwkPub, err := jwk.ToPublic(t)
	require.NoError(t, err, "privateKey: jwk.ToPublic")

	dBytes, err := base64.RawURLEncoding.DecodeString(jwk.D)
	require.NoError(t, err, "base64.RawURLEncoding.DecodeString(d)")

	jwkPriv, err := NewPrivateKey(dBytes)
	require.NoError(t, err, "NewPrivateKey")
	require.True(t, jwkPriv.PublicKey().Equal(jwkPub))

	return jwkPriv, nil
}

type SignaturePublicKey struct {
	Type         string `json:"type"`
	Curve        string `json:"curve"`
	KeySize      int    `json:"keySize"`
	Uncompressed string `json:"uncompressed"`
	Wx           string `json:"wx"`
	Wy           string `json:"wy"`
}

func (spk *SignaturePublicKey) ToPublic(t *testing.T) *PublicKey {
	require.EqualValues(t, "EcPublicKey", spk.Type)
	require.EqualValues(t, "secp256k1", spk.Curve)
	require.EqualValues(t, 256, spk.KeySize)

	uncompressedBytes := helpers.MustBytesFromHex(spk.Uncompressed)
	publicKey, err := NewPublicKey(uncompressedBytes)
	require.NoError(t, err, "NewPublicKey")

	return publicKey
}

type DHTestCase struct {
	ID      int             `json:"tcId"`
	Comment string          `json:"comment"`
	Flags   []string        `json:"flags"`
	Public  json.RawMessage `json:"public"`
	Private json.RawMessage `json:"private"`
	Shared  string          `json:"shared"`
	Result  string          `json:"result"`
}

func (tc *DHTestCase) Run(t *testing.T, tg *DHTestGroup) {
	if tc.Comment != "" {
		t.Logf("%s", tc.Comment)
	}

	sharedBytes := helpers.MustBytesFromHex(tc.Shared)

	var (
		hasFlagBadPublic  = len(tc.Shared) == 0
		hasFlagCompressed bool
	)
	for _, flag := range tc.Flags {
		hasFlagBadPublic = hasFlagBadPublic || dhFlagsBadPublic[flag]
		hasFlagCompressed = hasFlagCompressed || dhFlagsCompressed[flag]
	}
	mustFail := tc.Result != resultValid

	// Special case(s):
	if tg.Type == "EcdhTest" && tg.Curve == "secp256k1" && tg.Encoding == encodingAsn {
		// - ecdh_secp256k1_test.json (#2) - Compressed point
		if tc.ID == 2 && tc.Result == resultAcceptable && hasFlagCompressed {
			// We allow this, while some may not.
			mustFail = false
		}
	}

	var (
		publicKey  *PublicKey
		privateKey *PrivateKey
		err        error
	)
	switch tg.Encoding {
	case encodingAsn:
		// The one saving grace of all this ASN.1 bullshit is that
		// at least the keys in the test vectors are just hex strings
		// that can be passed to the parser, kind of.
		var publicBytesHex, privateBytesHex string
		err = json.Unmarshal(tc.Public, &publicBytesHex)
		require.NoError(t, err, "json.Unmarshal(tc.Public)")
		err = json.Unmarshal(tc.Private, &privateBytesHex)
		require.NoError(t, err, "json.Unmarshal(tc.Private)")

		publicBytes := helpers.MustBytesFromHex(publicBytesHex)
		privateBytes := helpers.MustBytesFromHex(privateBytesHex)

		publicKey, err = ParseASN1PublicKey(publicBytes)
		if hasFlagBadPublic {
			require.Error(t, err, "ParseASN1PublicKey: expected bad: %+v", tc.Flags)
			return
		}
		require.NoError(t, err, "ParseASN1PublicKey: %+v", tc.Flags)

		// The private key encoding can have leading 00s, or
		// leading 00s trimmed.  Apparently I'm supposed to accept
		// anything that represents a scalar in the correct range.
		tmp := make([]byte, secp256k1.ScalarSize)
		sInt := big.NewInt(42069).SetBytes(privateBytes)
		sInt.FillBytes(tmp)
		privateKey, err = NewPrivateKey(tmp)
		require.NoError(t, err, "NewPrivateKey")
	case encodingWebCrypto:
		var publicJWK, privateJWK JsonWebKey
		err = json.Unmarshal(tc.Public, &publicJWK)
		require.NoError(t, err, "json.Unmarshal(tc.Public)")
		err = json.Unmarshal(tc.Private, &privateJWK)
		require.NoError(t, err, "json.Unmarshal(tc.Private)")

		publicKey, err = publicJWK.ToPublic(t)
		if hasFlagBadPublic {
			require.Error(t, err, "JsonWebKey.ToPublic: expected bad: %+v", tc.Flags)
			return
		}
		require.NoError(t, err, "JsonWebKey.ToPublic: %+v", tc.Flags)

		privateKey, err = privateJWK.ToPrivate(t)
		require.NoError(t, err, "JsonWebKey.ToPrivate")
	default:
		t.Fatalf("unknown encoding: '%s'", tg.Encoding)
	}
	require.False(t, mustFail, "failed to reject bad/exotic encoding: %+v", tc.Flags)

	// Check that s11n roundtrips.
	nPub, err := NewPublicKey(publicKey.Bytes())
	require.NoError(t, err, "NewPublicKey(publicKey.Bytes())")
	require.True(t, publicKey.Equal(nPub), "publicKey = NewPublicKey(publicKey.Bytes())")

	nPriv, err := NewPrivateKey(privateKey.Bytes())
	require.NoError(t, err, "NewPrivateey(privateKey.Bytes())")
	require.True(t, privateKey.Equal(nPriv), "privateKey = NewPrivateKey(privateKey.Bytes())")
	require.True(t, privateKey.PublicKey().Equal(nPriv.PublicKey()), "privateKey.PublicKey() == NewPrivateKey(privateKey.Bytes()).PublicKey()")

	derivedShared, err := privateKey.ECDH(publicKey)
	require.NoError(t, err, "privateKey.ECDH")
	require.EqualValues(t, sharedBytes, derivedShared, "privateKey.ECDH(publicKey)")
}

type SignatureTestCase struct {
	ID      int      `json:"tcId"`
	Comment string   `json:"comment"`
	Flags   []string `json:"flags"`
	Msg     string   `json:"msg"`
	Sig     string   `json:"sig"`
	Result  string   `json:"result"`
}

func (tc *SignatureTestCase) Run(t *testing.T, publicKey *PublicKey, tg *SignatureTestGroup) {
	if tc.Comment != "" {
		t.Logf("%s", tc.Comment)
	}

	hashAlg := sigHash[tg.Sha]
	msgBytes := helpers.MustBytesFromHex(tc.Msg)
	sigBytes := helpers.MustBytesFromHex(tc.Sig)

	h := hashAlg.New()
	_, _ = h.Write(msgBytes)
	hBytes := h.Sum(nil)

	mustFail := tc.Result != resultValid

	var sigOkOneshot bool
	switch tg.Type {
	case typeEcdsaVerify:
		sigOkOneshot = publicKey.VerifyASN1(hBytes, sigBytes)
	case typeEcdsaShitcoinVerify:
		// Shitcoin adds a sighash to the end of signatures, that
		// IsValidShitcoinSignatureEncoding expects in all the
		// length checks.
		bipSig := append([]byte{}, sigBytes...)
		bipSig = append(bipSig, 69)
		sigOkOneshot = publicKey.VerifyASN1BIP0066(hBytes, bipSig)
	}
	require.EqualValues(t, !mustFail, sigOkOneshot, "one-shot signature verification: %+v", tc.Flags)

	var hasFlagRejectEarly bool
	for _, flag := range tc.Flags {
		hasFlagRejectEarly = hasFlagRejectEarly || sigFlagsRejectEarly[flag]
	}

	// It would be nice if this could assert that things get rejected
	// at the correct time and place, but when the rejection happens
	// is split between the parsing and the actual signature verify.
	r, s, err := parseASN1Signature(sigBytes)
	if err != nil {
		// As a consolation prize, we re-do the signature verification
		// by calling the internal routines, and assert that totally
		// screwed up signatures get rejected by the ASN.1 parser.
		if mustFail {
			return
		}
	}
	require.False(t, hasFlagRejectEarly, "failed to reject bad/exotic encoding: %+v", tc.Flags)
	require.NoError(t, err, "parseASN1Signature: %+v", tc.Flags)

	splitSigOk := nil == verify(publicKey, hBytes, r, s) // Need the un-fixed up result.
	sigOk := splitSigOk
	if tg.Type == typeEcdsaShitcoinVerify {
		// Special case: `s <= n/2` is only enforced in VerifyASN1Shitcoin.
		sigOk = sigOk && s.IsGreaterThanHalfN() == 0
	}
	require.EqualValues(t, !mustFail, sigOk, "split signature verification: %+v", tc.Flags)

	// Note: This checks the recovery result against verify rather than
	// the test case pass/fail, as the Shitcoin flavored ECDSA test
	// cases checks for `s <= n/2`, which RecoverPublicKey does not
	// enforce (Test cases 1, 388).
	//
	// RecoverPublicKey's acceptance of "high" `s` matches what is
	// done by libsecp256k1, and the EVM precompile.
	recoverOk := recoverPublicKeyExhaustive(publicKey, hBytes, r, s)
	require.EqualValues(t, splitSigOk, recoverOk, "public key recovery: %+v", tc.Flags)
}

func recoverPublicKeyExhaustive(expectedPub *PublicKey, hash []byte, r, s *secp256k1.Scalar) bool {
	// Follow the more traditional approach without recovery_id as in
	// SEC 1.0, Version 2.0, Section 4.1.6.  This can be implemented
	// with our implementation by trying every possible recovery_id.

	for recoveryID := byte(0); recoveryID < 4; recoveryID++ {
		q, err := RecoverPublicKey(hash, r, s, recoveryID)
		if err != nil {
			continue
		}
		// 1.6.2. Verify that Q is the authentic public key.
		if expectedPub.Equal(q) {
			return true
		}
	}
	// 2. Output “invalid”.
	return false
}

func testWycheproofEcdh(t *testing.T, fn string) {
	f, err := os.Open(fn)
	require.NoError(t, err, "os.Open")
	defer f.Close()

	var testVectors TestVectors

	dec := json.NewDecoder(f)
	err = dec.Decode(&testVectors)
	require.NoError(t, err, "dec.Decode")

	t.Logf("Wycheproof Version: %s", testVectors.Version)

	var (
		numTests int
		groups   []DHTestGroup
	)
	err = json.Unmarshal(testVectors.TestGroups, &groups)
	require.NoError(t, err, "json.Unmarshal(testVectors.TestGroups)")

	for _, group := range groups {
		for _, testCase := range group.Tests {
			n := fmt.Sprintf("TestCase/%d", testCase.ID)
			t.Run(n, func(t *testing.T) {
				testCase.Run(t, &group)
			})
			numTests++
		}
	}
	require.Equal(t, testVectors.NumTests, numTests, "unexpected number of tests ran: %d (expected %d)", numTests, testVectors.NumTests)
}

func testWycheproofEcdsa(t *testing.T, fn string) {
	f, err := os.Open(fn)
	require.NoError(t, err, "os.Open")
	defer f.Close()

	var testVectors TestVectors

	dec := json.NewDecoder(f)
	err = dec.Decode(&testVectors)
	require.NoError(t, err, "dec.Decode")

	t.Logf("Wycheproof Version: %s", testVectors.Version)

	var (
		numTests int
		groups   []SignatureTestGroup
	)
	err = json.Unmarshal(testVectors.TestGroups, &groups)
	require.NoError(t, err, "json.Unmarshal(testVectors.TestGroups)")

	for i, group := range groups {
		// Only do this once per group, since s11n is slightly expensive.
		publicKey := group.PublicKey.ToPublic(t)

		pkDer := helpers.MustBytesFromHex(group.PublicKeyDER)
		derPublicKey, err := ParseASN1PublicKey(pkDer)
		require.NoError(t, err, "TestGroup/%d - ParseASN1PublicKey", i)
		require.True(t, publicKey.Equal(derPublicKey), "TestGroup/%d - publicKey != publicKeyDer")

		for _, testCase := range group.Tests {
			n := fmt.Sprintf("TestCase/%d", testCase.ID)
			t.Run(n, func(t *testing.T) {
				testCase.Run(t, publicKey, &group)
			})
			numTests++
		}
	}
	require.Equal(t, testVectors.NumTests, numTests, "unexpected number of tests ran: %d (expected %d)", numTests, testVectors.NumTests)
}

func TestWycheproof(t *testing.T) {
	t.Run("ECDH/Asn", func(t *testing.T) { testWycheproofEcdh(t, fileEcdhAsn) })
	t.Run("ECDH/WebCrypto", func(t *testing.T) { testWycheproofEcdh(t, fileEcdhWebCrypto) })
	t.Run("ECDSA/Asn/SHA256", func(t *testing.T) { testWycheproofEcdsa(t, fileEcdsaAsnSha256) })
	t.Run("ECDSA/Asn/SHA512", func(t *testing.T) { testWycheproofEcdsa(t, fileEcdsaAsnSha512) })
	t.Run("ECDSA/Shitcoin", func(t *testing.T) { testWycheproofEcdsa(t, fileEcdsaShitcoin) })
}
