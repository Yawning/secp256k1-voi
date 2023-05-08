package secp256k1

// The various scalar point multiplication routines.  See `point_table.go`
// for the other half of the picture.
//
// Note: `assertPointsValid` is checked once and only once (as part of)
// building the table, and `v.isValid` is set once (and not overwritten)
// when it is initialized to the point at infinity.

// ScalarMult sets `v = s * p`, and returns `v`.
func (v *Point) ScalarMult(s *Scalar, p *Point) *Point {
	// This uses a 4-bit window, decreasing index (MSB -> LSB).  A 2-bit
	// window is only ~10% worse, so the tradeoff for the larger table
	// isn't totally convincing, but it sees like a reasonably popular
	// window size.

	// Precompute small multiples of P, 1P -> 15P.
	//
	// Past this precomputation, it is safe to trample over v, as p is
	// no longer used so it doesn't mater if they alias.
	tbl := newProjectivePointMultTable(p)

	v.Identity()
	for i, b := range s.getBytesArray() {
		// Skip the very first set of doubles, as v is guaranteed to be
		// the point at infinity.
		if i != 0 {
			v.doubleComplete(v)
			v.doubleComplete(v)
			v.doubleComplete(v)
			v.doubleComplete(v)
		}

		tbl.SelectAndAdd(v, uint64(b>>4))

		v.doubleComplete(v)
		v.doubleComplete(v)
		v.doubleComplete(v)
		v.doubleComplete(v)

		tbl.SelectAndAdd(v, uint64(b&0xf))
	}

	return v
}

// ScalarMultVartime sets `v = s * p`, and returns `v` in variable time.
func (v *Point) ScalarMultVartime(s *Scalar, p *Point) *Point {
	// TODO/perf: There's lots of different ways to improve on this, but
	// even the trival change to a vartime table lookup + add saves ~14%.
	//
	// - Use w-NAF.
	// - Use the endomorphism.
	// - Provide VartimePoint or similar that uses Jacobian coordinates,
	// and the incomplete formulas, as conversion from projective is
	// trivial if `Z=1`, and the case where this needs to be fast is
	// calculating `u1 * G + u2 * Q` where that precondition is
	// reasonable.

	tbl := newProjectivePointMultTable(p)

	v.Identity()
	for i, b := range s.getBytesArray() {
		if i != 0 {
			v.doubleComplete(v)
			v.doubleComplete(v)
			v.doubleComplete(v)
			v.doubleComplete(v)
		}

		tbl.SelectAndAddVartime(v, uint64(b>>4))

		v.doubleComplete(v)
		v.doubleComplete(v)
		v.doubleComplete(v)
		v.doubleComplete(v)

		tbl.SelectAndAddVartime(v, uint64(b&0xf))
	}

	return v
}

// ScalarBaseMult sets `v = s * G`, and returns `v`.
func (v *Point) ScalarBaseMult(s *Scalar) *Point {
	return v.ScalarMult(s, NewGeneratorPoint())
}
