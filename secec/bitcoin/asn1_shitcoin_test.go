// Copyright (c) 2023 Yawning Angel
//
// SPDX-License-Identifier: BSD-3-Clause

package bitcoin

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"gitlab.com/yawning/secp256k1-voi/internal/helpers"
)

type bip0066ValidCase struct {
	DER string `json:"DER"`
	R   string `json:"r"`
	S   string `json:"s"`
}

type bip0066InvalidDecodeCase struct {
	Exception string `json:"exception"`
	DER       string `json:"DER"`
}

type bip0066TestVectors struct {
	Valid   []bip0066ValidCase `json:"valid"`
	Invalid struct {
		Encode json.RawMessage            `json:"encode"`
		Decode []bip0066InvalidDecodeCase `json:"decode"`
	} `json:"invalid"`
}

func TestBIP0066(t *testing.T) {
	f, err := os.Open("testdata/bip-0066-test-vectors.json")
	require.NoError(t, err, "Open")
	defer f.Close()

	var testVectors bip0066TestVectors

	dec := json.NewDecoder(f)
	err = dec.Decode(&testVectors)
	require.NoError(t, err, "dec.Decode")

	for i, testCase := range testVectors.Invalid.Decode {
		n := fmt.Sprintf("TestCase/%d", i)
		t.Run(n, func(t *testing.T) {
			t.Log(testCase.Exception)

			b := helpers.MustBytesFromHex(testCase.DER)
			b = append(b, 69) // Append the sighash byte.
			ok := IsValidSignatureEncodingBIP0066(b)

			require.False(t, ok, "IsValidSignatureEncodingBIP0066")
		})
	}
}
