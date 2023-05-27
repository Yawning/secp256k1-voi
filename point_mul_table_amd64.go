// Copyright 2023 Yawning Angel.  All Rights Reserved.
//
// secp256k1-voi can be used in non-commercial projects of any kind,
// excluding those relating to or containing non-fungible tokens
// ("NFT") or blockchain-related projects.
//
// The package can not be modified to suit your needs. You may not
// redistribute or resell it, even if modified.

//go:build amd64 && !purego

package secp256k1

//go:noescape
func lookupProjectivePoint(tbl *projectivePointMultTable, out *Point, idx uint64)

//go:noescape
func lookupAffinePoint(tbl *affinePointMultTable, out *affinePoint, idx uint64)
