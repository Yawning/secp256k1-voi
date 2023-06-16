// Copyright (c) 2023 Yawning Angel
//
// SPDX-License-Identifier: BSD-3-Clause

package field

import (
	"encoding/binary"
	"math/big"
	"math/bits"

	"filippo.io/bigmod"

	fiat "gitlab.com/yawning/secp256k1-voi/internal/fiat/secp256k1montgomery"
	"gitlab.com/yawning/secp256k1-voi/internal/helpers"
)

var (
	pMod = func() *bigmod.Modulus {
		var b [32]byte
		binary.BigEndian.PutUint64(b[0:8], mSat[3])
		binary.BigEndian.PutUint64(b[8:16], mSat[2])
		binary.BigEndian.PutUint64(b[16:24], mSat[1])
		binary.BigEndian.PutUint64(b[24:32], mSat[0])

		return bigmod.NewModulusFromBig((&big.Int{}).SetBytes(b[:]))
	}()

	// Use 2^512 + 1 for wideMod because we need to handle inputs up to
	// 2^512-1, and all `Modulus` need to be odd.
	wideMod = func() *bigmod.Modulus {
		return bigmod.NewModulusFromBig(
			(&big.Int{}).SetBytes(
				helpers.MustBytesFromHex("0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001"),
			),
		)
	}()
)

// SetWideBytes sets `fe = src % p`, where `src` is a big-endian encoding
// of `fe` with a length in the range `[32,64]`-bytes, and returns `fe`.
// This routine only exists to implement certain standards that require
// this.  In practice, p is close enough to `2^256-1` such that this is
// largely unneccesary.
func (fe *Element) SetWideBytes(src []byte) *Element {
	// This was 14.3.4 "Reduction methods for moduli of special
	// form" from "Handbook of Applied Cryptography" by Menezes,
	// Oorschot, and Vanstone, but using library code spooks me
	// less, especially if it is a re-export from the standard
	// library.
	//
	// The existence of this routine is stupid, and it is only
	// for h2c.

	sLen := len(src)
	switch {
	case sLen < ElementSize:
		panic("secp256k1/internal/field: wide element too short")
	case sLen == ElementSize:
		// When possible, call the simpler routine.
		fe.SetBytes((*[ElementSize]byte)(src))
		return fe
	case sLen <= WideElementSize:
		n, err := bigmod.NewNat().SetBytes(src[:], wideMod)
		if err != nil {
			// This can NEVER happen as wideMod is greater than
			// the largest number representable in 64-bytes.
			panic("secp256k1/internal/field: failed to deserialize wide element: " + err.Error())
		}

		// Aw, Nat.Mod isn't aliasing safe.
		out := bigmod.NewNat().Mod(n, pMod)

		return fe.MustSetCanonicalBytes((*[ElementSize]byte)(out.Bytes(pMod)))
	default:
		panic("secp256k1/internal/field: wide element too large")
	}
}

func reduceSaturated(dst, src *[4]uint64) uint64 {
	// Assume that the reduction is needed, and calclate
	// reduced = src - n.  This is fine because src will never
	// be >= 2n.
	var (
		reduced [4]uint64
		borrow  uint64
	)
	reduced[0], borrow = bits.Sub64(src[0], mSat[0], borrow)
	reduced[1], borrow = bits.Sub64(src[1], mSat[1], borrow)
	reduced[2], borrow = bits.Sub64(src[2], mSat[2], borrow)
	reduced[3], borrow = bits.Sub64(src[3], mSat[3], borrow)

	// if borrow == 0, src >= n
	// if borrow == 1, src < n (no reduction needed)
	didReduce := helpers.Uint64IsZero(borrow)

	fiat.Selectznz(dst, fiat.Uint64ToUint1(didReduce), src, &reduced)

	return didReduce
}
