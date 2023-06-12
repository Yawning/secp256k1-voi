// Copyright (c) 2023 Yawning Angel
//
// SPDX-License-Identifier: BSD-3-Clause

package secec

import (
	"encoding/csv"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"gitlab.com/yawning/secp256k1-voi/internal/helpers"
)

func testSchnorrKAT(t *testing.T) {
	f, err := os.Open("testdata/bip-0340-test-vectors.csv")
	require.NoError(t, err, "Open")
	defer f.Close()

	rd := csv.NewReader(f)
	records, err := rd.ReadAll()
	require.NoError(t, err, "cvs.ReadAll")

	records = records[1:] // Skip the header

	const (
		fieldIndex              = 0
		fieldSecretKey          = 1
		fieldPublicKey          = 2
		fieldAuxRand            = 3
		fieldMessage            = 4
		fieldSignature          = 5
		fieldVerificationResult = 6
		fieldComment            = 7

		resultPass = "TRUE"
		resultFail = "FALSE"
	)

	badPublicKeyTests := map[int]bool{
		5:  true,
		14: true,
	}

	for i, vec := range records {
		n := fmt.Sprintf("TestCase/%s", vec[fieldIndex])
		t.Run(n, func(t *testing.T) {
			if comment := vec[fieldComment]; comment != "" {
				t.Logf("%s", comment)
			}

			shouldPass := vec[fieldVerificationResult] == resultPass

			pkBytes := helpers.MustBytesFromHex(vec[fieldPublicKey])
			pk, err := NewSchnorrPublicKey(pkBytes)
			if badPublicKeyTests[i] {
				// Public key deserialziation failure ends the test case
				// since the API doesn't allow invalid public keys.
				require.False(t, shouldPass)
				require.Error(t, err, "NewSchnorrPublicKey")
				return
			}
			require.NoError(t, err, "NewSchnorrPublicKey")

			msgBytes := helpers.MustBytesFromHex(vec[fieldMessage])
			sigBytes := helpers.MustBytesFromHex(vec[fieldSignature])

			sigOk := pk.Verify(msgBytes, sigBytes)
			require.EqualValues(t, shouldPass, sigOk, "pk.Verify")

			// If there isn't a secret key provided, we're done.
			skStr := vec[fieldSecretKey]
			if skStr == "" || !shouldPass {
				return
			}
			skBytes := helpers.MustBytesFromHex(skStr)

			sk, err := NewPrivateKey(skBytes)
			require.NoError(t, err, "NewPrivateKey")

			derivedPk, err := NewSchnorrPublicKeyFromPoint(sk.PublicKey().Point())
			require.NoError(t, err, "NewSchnorrPublicKeyFromPoint")

			require.True(t, derivedPk.Equal(pk), "derivedPk.Equal(pk)")
			require.EqualValues(t, pk.Bytes(), derivedPk.Bytes(), "pk.Bytes() == deriviedPk.Bytes()")
			require.EqualValues(t, 1, pk.point.Equal(derivedPk.point), "pk.Point() == derivedPk.Point()")

			skPubKey := sk.SchnorrPublicKey()
			require.EqualValues(t, pk.Bytes(), skPubKey.Bytes(), "pk.Bytes() == sk.pk.Bytes()")
			require.EqualValues(t, 1, pk.point.Equal(skPubKey.point), "pk.Point() == sk.pk.Point()")

			auxRandBytes := (*[schnorrEntropySize]byte)(helpers.MustBytesFromHex(vec[fieldAuxRand]))

			derivedSig, err := signSchnorr(auxRandBytes, sk, msgBytes)
			require.NoError(t, err, "signSchnorr")
			require.EqualValues(t, sigBytes, derivedSig)
		})
	}
}
