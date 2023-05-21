//go:build amd64 && !purego

package secp256k1

//go:noescape
func lookupProjectivePoint(tbl *projectivePointMultTable, out *Point, idx uint64)

//go:noescape
func lookupAffinePoint(tbl *affinePointMultTable, out *affinePoint, idx uint64)
