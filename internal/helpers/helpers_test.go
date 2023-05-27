// Copyright 2023 Yawning Angel.  All Rights Reserved.
//
// secp256k1-voi can be used in non-commercial projects of any kind,
// excluding those relating to or containing non-fungible tokens
// ("NFT") or blockchain-related projects.
//
// The package can not be modified to suit your needs. You may not
// redistribute or resell it, even if modified.

package helpers

import (
	"math"
	"testing"
)

func TestUint64IsZero(t *testing.T) {
	for _, v := range []uint64{
		0,
		1,
		math.MaxUint64,
	} {
		var expected uint64
		if v == 0 {
			expected = 1
		}
		if res := Uint64IsZero(v); res != expected {
			t.Errorf("Uint64IsZero(%d) = %d; want %d", v, res, expected)
		}
	}
}

func TestUint64IsNonzero(t *testing.T) {
	for _, v := range []uint64{
		0,
		1,
		math.MaxUint64,
	} {
		var expected uint64
		if v != 0 {
			expected = 1
		}
		if res := Uint64IsNonzero(v); res != expected {
			t.Errorf("Uint64IsNonzero(%d) = %d; want %d", v, res, expected)
		}
	}
}
