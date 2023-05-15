package secec

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"gitlab.com/yawning/secp256k1-voi.git"
	"gitlab.com/yawning/secp256k1-voi.git/internal/helpers"
)

const (
	encodingAsn       = "asn"
	encodingWebCrypto = "webcrypto"

	fileEcdhAsn       = "../internal/wycheproof/testdata/ecdh_secp256k1_test.json"
	fileEcdhWebCrypto = "../internal/wycheproof/testdata/ecdh_secp256k1_webcrypto_test.json"

	jwkKtyEc        = "EC"
	jwkCrvSecp256k1 = "P-256K"
)

var dhFlagsBadPublic = map[string]bool{
	// Failure cases
	"InvalidCompressedPublic": true,
	"InvalidCurveAttack":      true,
	"InvalidEncoding":         true,
	"InvalidPublic":           true,
	"WrongCurve":              true,

	// Encoding: Treat as failure
	"UnnamedCurve": true, // ParseASN1PublicKey does not support this

	// Encoding: May be accepted, depends on runtime behavior
	"InvalidAsn": true, // encoding/asn1 is on the strict side
}

var dhFlagsCompressed = map[string]bool{
	"CompressedPublic": true,
	"CompressedPoint":  true,
}

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

type DHTestCase struct {
	ID      int             `json:"tcId"`
	Comment string          `json:"comment"`
	Flags   []string        `json:"flags"`
	Public  json.RawMessage `json:"public"`
	Private json.RawMessage `json:"private"`
	Shared  string          `json:"shared"`
	Result  string          `json:"result"`
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

	// XXX: Maybe the library should provide a way to construct
	// a public key from the x and y-coordinate.
	ptBytes := append([]byte{0x04}, xBytes...)
	ptBytes = append(ptBytes, yBytes...)
	return NewPublicKey(ptBytes)
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
	mustFail := tc.Result != "valid"

	// Special case(s):
	if tg.Type == "EcdhTest" && tg.Curve == "secp256k1" && tg.Encoding == encodingAsn {
		// - ecdh_secp256k1_test.json (#2) - Compressed point
		if tc.ID == 2 && tc.Result == "acceptable" && hasFlagCompressed {
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

func TestWycheproof(t *testing.T) {
	t.Run("ECDH/Asn", func(t *testing.T) { testWycheproofEcdh(t, fileEcdhAsn) })
	t.Run("ECDH/WebCrypto", func(t *testing.T) { testWycheproofEcdh(t, fileEcdhWebCrypto) })
}
