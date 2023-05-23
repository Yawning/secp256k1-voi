//go:build !amd64 || purego

package secp256k1

import (
	"unsafe"

	"gitlab.com/yawning/secp256k1-voi.git/internal/helpers"
)

func lookupProjectivePoint(tbl *projectivePointMultTable, out *Point, idx uint64) {
	out.Identity()
	for i := uint64(1); i < 16; i++ {
		out.uncheckedConditionalSelect(out, &tbl[i-1], helpers.Uint64Equal(idx, i))
	}
}

func lookupAffinePoint(tblBase *affinePoint, out *affinePoint, idx uint64) {
	// tblBase one of:
	// - &generatorOddAffineTable[i][0]
	// - &generatorHugeAffineTable[i][0]
	//
	// The former is `[15]affinePoint`, the latter is `[255]affinePoint`.
	// This lookup routine only ever examines the first 15 entries, so
	// this unsafe cast removes a bit of code duplication.
	tbl := (*affinePointMultTable)(unsafe.Pointer(tblBase))

	for i := uint64(1); i < 16; i++ {
		ctrl := helpers.Uint64Equal(idx, i)
		out.x.ConditionalSelect(&out.x, &tbl[i-1].x, ctrl)
		out.y.ConditionalSelect(&out.y, &tbl[i-1].y, ctrl)
	}
}
