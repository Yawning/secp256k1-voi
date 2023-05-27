// Copyright 2023 Yawning Angel.  All Rights Reserved.
//
// secp256k1-voi can be used in non-commercial projects of any kind,
// excluding those relating to or containing non-fungible tokens
// ("NFT") or blockchain-related projects.
//
// The package can not be modified to suit your needs. You may not
// redistribute or resell it, even if modified.

//go:build !amd64 || purego

package secp256k1

import "gitlab.com/yawning/secp256k1-voi.git/internal/helpers"

func lookupProjectivePoint(tbl *projectivePointMultTable, out *Point, idx uint64) {
	out.Identity()
	for i := uint64(1); i < 16; i++ {
		out.uncheckedConditionalSelect(out, &tbl[i-1], helpers.Uint64Equal(idx, i))
	}
}

func lookupAffinePoint(tbl *affinePointMultTable, out *affinePoint, idx uint64) {
	for i := uint64(1); i < 16; i++ {
		ctrl := helpers.Uint64Equal(idx, i)
		out.x.ConditionalSelect(&out.x, &tbl[i-1].x, ctrl)
		out.y.ConditionalSelect(&out.y, &tbl[i-1].y, ctrl)
	}
}
