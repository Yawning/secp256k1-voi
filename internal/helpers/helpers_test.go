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
