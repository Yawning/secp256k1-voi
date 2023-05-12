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
	for i, b := range s.Bytes() {
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

// scalarMultVartime sets `v = s * p`, and returns `v` in variable time.
func (v *Point) scalarMultVartime(s *Scalar, p *Point) *Point {
	// TODO/perf: There's lots of different ways to improve on this, but
	// even the trival change to a vartime table lookup + add saves ~14%.
	//
	// - Use w-NAF + the endomorphism.
	// - Beg the fiat people for a field multiply specialized for a small
	// multiple, then use Jacobian coordinates, because doubles in theory
	// are cheaper that way if multiply-by-small-integer is cheap.  This
	// will also help the complete formula case (`2m3b`).

	tbl := newProjectivePointMultTable(p)

	v.Identity()
	for i, b := range s.Bytes() {
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

// ScalarBaseMult sets `v = s * G`, and returns `v`, where `G` is the
// generator.
func (v *Point) ScalarBaseMult(s *Scalar) *Point {
	tbl := generatorAffineTable

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
	tbl := generatorAffineTable

	v.Identity()
	tableIndex := len(tbl) - 1
	for _, b := range s.Bytes() {
		tbl[tableIndex].SelectAndAddVartime(v, uint64(b>>4))
		tableIndex--

		tbl[tableIndex].SelectAndAddVartime(v, uint64(b&0xf))
		tableIndex--
	}

	return v
}

// DoubleScalarMultBasepointVartime sets `v = u1 * G + u2 * P`, and returns
// `v` in variable time, where `G` is the generator.
func (v *Point) DoubleScalarMultBasepointVartime(u1, u2 *Scalar, p *Point) *Point {
	// To the best of my knowledge, doing things this way is faster than
	// Shamir-Strauss, given our scalar-basepoint multiply implementation,
	// especially if the variable-base multiply is fully optimized (TBD).
	//
	// This routine is the most performance critical as it is the core
	// of ECDSA verfication.
	u1g := newRcvr().scalarBaseMultVartime(u1)
	u2p := newRcvr().scalarMultVartime(u2, p)
	return v.Add(u1g, u2p)
}
