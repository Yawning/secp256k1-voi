package secp256k1

import (
	_ "embed"
	"fmt"

	"gitlab.com/yawning/secp256k1-voi.git/internal/field"
	"gitlab.com/yawning/secp256k1-voi.git/internal/helpers"
)

// Tables for doing accelerated scalar multiplication with a window.
//
// This is heavily inspired by Filippo Valsorda's nistec package,
// as it implements the same algorithm I originally settled on,
// with nicer code, and abstracts out the precomputed table.
//
// Note: Effort is made to omit checking `Point.isValid` as much as
// possible as these routines are internal, and it is entirely
// redundant, once the validity of `p` is checked once.

// projectivePointMultTable stores pre-computed multiples [1P, ... 15P],
// with support for `0P` implicitly as part of the table lookup.
//
// For performance reasons, particularly when creating the table, the
// Z-coordinate for entries is not guaranteed to be 1.
type projectivePointMultTable [15]Point

// SelectAndAdd sets `sum = sum + idx * P`, and returns `sum`.  idx
// MUST be in the range of `[0, 15]`.
func (tbl *projectivePointMultTable) SelectAndAdd(sum *Point, idx uint64) *Point {
	addend := newRcvr()
	lookupProjectivePoint(tbl, addend, idx)

	return sum.addComplete(sum, addend)
}

// SelectAndAddVartime sets `sum = sum + idx * P`, and returns `sum` in
// variable time.  idx MUST be in the range of `[0, 15]`.
func (tbl *projectivePointMultTable) SelectAndAddVartime(sum *Point, idx uint64) *Point {
	if idx == 0 {
		return sum
	}
	return sum.addComplete(sum, &tbl[idx-1])
}

func newProjectivePointMultTable(p *Point) projectivePointMultTable {
	var tbl projectivePointMultTable
	tbl[0].Set(p) // will call `assertPointsValid(p)`
	for i := 1; i < len(tbl); i += 2 {
		tbl[i].doubleComplete(&tbl[i/2])
		tbl[i+1].addComplete(&tbl[i], p)
	}

	return tbl
}

// Routines and tables dedicated to scalar basepoint multiplication.
//
// This is a common operation required by higher-level constructs,
// thus more precomputation is used, relative to the generic case.

// affinePoint is a point on the `Z = 1` plane.
type affinePoint struct {
	x, y field.Element
}

// hugeAffinePointMultTable stores a series of 32 tables, of precomputed
// multiples of G [1G, ... 255G].  Each successive table is the previous
// table doubled 8 times.
type hugeAffinePointMultTable [32][255]affinePoint

//go:embed internal/gentable/point_mul_table.bin
var generatorHugeAffineTableBytes []byte

var generatorHugeAffineTable = func() hugeAffinePointMultTable {
	var (
		off int
		err error
	)
	var tbl hugeAffinePointMultTable
	for i := range tbl {
		for j := range tbl[i] {
			xBytes := generatorHugeAffineTableBytes[off : off+field.ElementSize]
			off += field.ElementSize
			yBytes := generatorHugeAffineTableBytes[off : off+field.ElementSize]
			off += field.ElementSize

			p := &tbl[i][j]
			if _, err = p.x.SetCanonicalBytes((*[field.ElementSize]byte)(xBytes)); err != nil {
				panic(fmt.Errorf("secp256k1: failed to deserialize table x-coord: %w", err))
			}
			if _, err = p.y.SetCanonicalBytes((*[field.ElementSize]byte)(yBytes)); err != nil {
				panic(fmt.Errorf("secp256k1: failed to deserialize table y-coord: %w", err))
			}
		}
	}
	return tbl
}()

// XXX: This is totally redundant with generatorHugeAffineTable.  At a
// minimum, the huge table can be used as-is for even indexed tables,
// which would cut the size of this in half.
var generatorSmallAffineTable = func() *[ScalarSize * 2]affinePointMultTable {
	tbl := new([ScalarSize * 2]affinePointMultTable)
	for i := 0; i < ScalarSize; i++ {
		fromTbl := &generatorHugeAffineTable[i]

		for j := 0; j < 15; j++ {
			tbl[i*2][j].x.Set(&fromTbl[j].x)
			tbl[i*2][j].y.Set(&fromTbl[j].y)
		}

		for j := 0; j < 15; j++ {
			fromIdx := (16 + j<<4) - 1
			tbl[i*2+1][j].x.Set(&fromTbl[fromIdx].x)
			tbl[i*2+1][j].y.Set(&fromTbl[fromIdx].y)
		}
	}

	return tbl
}()

// SelectAndAddVartime sets `sum = sum + idx * P`, and returns `sum` in
// variable time.  tableIdx MUST be in the range of `[0, 32)` and idx
// MUST be in the range of `[0, 255]`.
func (tbl *hugeAffinePointMultTable) SelectAndAddVartime(sum *Point, tableIdx int, idx uint64) *Point {
	if idx == 0 {
		return sum
	}

	p := &tbl[tableIdx][idx-1]
	return sum.addMixed(sum, &p.x, &p.y)
}

// affinePointMultTable stores pre-computed multiples [1P, ... 15P].
type affinePointMultTable [15]affinePoint

// SelectAndAdd sets `sum = sum + idx * P`, and returns `sum`.  idx
// MUST be in the range of `[0, 15]`.
func (tbl *affinePointMultTable) SelectAndAdd(sum *Point, idx uint64) *Point {
	var ap affinePoint
	isInfinity := helpers.Uint64IsZero(idx)
	lookupAffinePoint(tbl, &ap, idx)

	// The formula is incorrect for the point at infinity, so store
	// the result in a temporary value...
	tmp := newRcvr().addMixed(sum, &ap.x, &ap.y)

	// ... and conditionally select the correct result.
	return sum.uncheckedConditionalSelect(tmp, sum, isInfinity)
}

// The various "simple" scalar point multiplication routines.
//
// Note: `assertPointsValid` is checked once and only once (as part of)
// building the table, and `v.isValid` is set once (and not overwritten)
// when it is initialized to the point at infinity.

// ScalarBaseMult sets `v = s * G`, and returns `v`, where `G` is the
// generator.
func (v *Point) ScalarBaseMult(s *Scalar) *Point {
	tbl := generatorSmallAffineTable

	v.Identity()
	tableIndex := len(tbl) - 1
	for _, b := range s.Bytes() {
		tbl[tableIndex].SelectAndAdd(v, uint64(b>>4))
		tableIndex--

		tbl[tableIndex].SelectAndAdd(v, uint64(b&0xf))
		tableIndex--
	}

	return v
}

// scalarBaseMultVartime sets `v = s * G`, and returns `v` in variable time.
func (v *Point) scalarBaseMultVartime(s *Scalar) *Point {
	v.Identity()
	for i, b := range s.Bytes() {
		tableIdx := ScalarSize - (1 + i)
		generatorHugeAffineTable.SelectAndAddVartime(v, tableIdx, uint64(b))
	}

	return v
}
