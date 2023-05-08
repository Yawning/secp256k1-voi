package secp256k1

import "gitlab.com/yawning/secp256k1-voi.git/internal/helpers"

// Tables for doing accelerated scalar multiplication with a window.
//
// This is largely inspired by Filippo Valsorda's nistec package,
// as it implements the same algorithm I originally settled on,
// with nicer code.
//
// Note: Effort is made to omit checking `Point.isValid` as much as
// possible as these routines are internal, and it is entirely
// redundant, once the validity of `p` is checked once.

// projectivePointMultTable stores pre-computed multiples [1P, ... 15P],
// with support for `0P` implicitly as part of the table lookup.
//
// For performance reasons, particularly when creating the table, the Z
// coordinate for entries is not guaranteed to be 1.
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

// SelectAndAddVartime sets `sum = sum + idx * P`, and returns `sum` in variable
// time.  idx MUST be in the range of `[0, 15]`.
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
