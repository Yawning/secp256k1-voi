package secp256k1

import (
	"gitlab.com/yawning/secp256k1-voi.git/internal/field"
	"gitlab.com/yawning/secp256k1-voi.git/internal/helpers"
)

// TODO: Do this on demand, or hard-code it.  It takes about 14 ms on
// my development system to do the generation.
var generatorAffineTable = newLargeAffinePointMultTable(NewGeneratorPoint())

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
	addend := NewIdentityPoint()
	for i := uint64(1); i < 16; i++ {
		addend.uncheckedConditionalSelect(addend, &tbl[i-1], helpers.Uint64Equal(idx, i))
	}
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

// affinePoint is a point on the `Z = 1` plane.
type affinePoint struct {
	x, y field.Element
}

// affinePointMultTable stores pre-computed multiples [1P, ... 15P].
type affinePointMultTable [15]affinePoint

// SelectAndAdd sets `sum = sum + idx * P`, and returns `sum`.  idx
// MUST be in the range of `[0, 15]`.
func (tbl *affinePointMultTable) SelectAndAdd(sum *Point, idx uint64) *Point {
	var x, y field.Element
	isInfinity := helpers.Uint64IsZero(idx)
	for i := uint64(1); i < 16; i++ {
		ctrl := helpers.Uint64Equal(idx, i)
		x.ConditionalSelect(&x, &tbl[i-1].x, ctrl)
		y.ConditionalSelect(&y, &tbl[i-1].y, ctrl)
	}

	// The formula is incorrect for the point at infinity, so store
	// the result in a temporary value...
	tmp := newRcvr().addMixed(sum, &x, &y)

	// ... and conditionally select the correct result.
	return sum.uncheckedConditionalSelect(tmp, sum, isInfinity)
}

// SelectAndAddVartime sets `sum = sum + idx * P`, and returns `sum` in
// variable time.  idx MUST be in the range of `[0, 15]`.
func (tbl *affinePointMultTable) SelectAndAddVartime(sum *Point, idx uint64) *Point {
	if idx == 0 {
		return sum
	}
	return sum.addMixed(sum, &tbl[idx-1].x, &tbl[idx-1].y)
}

// Calculate a table of tables of precomputed multiples of a given point.
// Each successive table is the previous table doubled four times.
//
// This is the approach taken for scalar-basepoint multiplication in nistec,
// with the following changes:
// - At the cost of substantially increased precomputation time,
// the table entries are rescaled such that Z = 1, and the Z-coordinate
// is omitted.  This saves 32-bytes of memory per entry (960 entries,
// 30720 bytes).
// - As the precomputed multiples of G are guaranteed to have `Z = 1`,
// the mixed point addition formula can be used (along with a conditional
// select to handle the point at infinity).
//
// These optimizations bring the constant time scalar-basepoint multiply
// down from ~37us to ~32us for a 16% saving.  The variable time
// implementation won't gain quite as much as it skips each addition
// entirely 1/16th of the time, but ~21us is more than acceptable.
//
// The generated table consumes `(32 * 2) * 15 * (32 * 2) bytes = 60 KiB`
// of memory.
func newLargeAffinePointMultTable(p *Point) *[ScalarSize * 2]affinePointMultTable {
	assertPointsValid(p)

	// base = p, rescaled so that Z = 1.
	base := NewPointFrom(p)
	if base.z.Equal(field.NewElement().One()) != 1 {
		base.rescale(base)
	}

	tbl := new([ScalarSize * 2]affinePointMultTable)
	for i := 0; i < ScalarSize*2; i++ {
		// base.z == 1, from the rescales.
		tbl[i][0].x.Set(&base.x)
		tbl[i][0].y.Set(&base.y)

		tmp := NewPointFrom(base)
		for j := 1; j < 15; j++ {
			tmp.addMixed(tmp, &base.x, &base.y)
			tmp.rescale(tmp)
			tbl[i][j].x.Set(&tmp.x)
			tbl[i][j].y.Set(&tmp.y)
		}

		base.doubleComplete(base)
		base.doubleComplete(base)
		base.doubleComplete(base)
		base.doubleComplete(base)
		base.rescale(base)
	}

	return tbl
}
