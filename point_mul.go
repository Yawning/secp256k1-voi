package secp256k1

import "gitlab.com/yawning/secp256k1-voi.git/internal/helpers"

// ScalarMult sets `v = s * p`, and returns `v`.
func (v *Point) ScalarMult(s *Scalar, p *Point) *Point {
	assertPointsValid(p)

	/*
		// Attempt #1: Constant-time double and add (decreasing index).
		//
		// 1. Set Q = 0 (the “point at infinity”)
		// 2. Compute Q ← 2·Q
		// 3. If next bit of n is set, then add P to Q
		// 4. Loop to step 2 until end of multiplier is reached
		q, id, addend := NewIdentityPoint(), NewIdentityPoint(), NewIdentityPoint()
		sBits := s.bits()
		for i := len(sBits) - 1; i >= 0; i-- {
			if i != len(sBits) - 1 {
				q.Double(q)
			}
			addend.ConditionalSelect(id, p, uint64(sBits[i]))

			q.Add(q, addend)
		}

		return v.Set(q)
	*/

	/*
		// Attempt #2: 2-bit window (decreasing index, a la BearSSL).
		//
		// 1. Compute 2·P and 3·P in temporary variables
		// 2. Set Q = 0 (the “point at infinity”)
		// 3. Compute Q ← 2·Q
		// 4. Compute Q ← 2·Q again
		// 5. Depending on the next two bits of n, add 0, P, 2·P or 3·P to Q
		// 6. Loop to step 3 until end of multiplier is reached
		oneP := p
		twoP := newRcvr().Double(p)
		threeP := newRcvr().Add(oneP, twoP)

		q := NewIdentityPoint()
		sBits := s.bits()
		for i := len(sBits) - 1; i >= 0; i = i - 2 {
			if i != len(sBits) - 1 {
				q.Double(q)
				q.Double(q)
			}

			ctrl := uint64(sBits[i]<<1 | sBits[i-1])
			addend := NewIdentityPoint()
			addend.ConditionalSelect(addend, oneP, helpers.Uint64Equal(ctrl, 1))
			addend.ConditionalSelect(addend, twoP, helpers.Uint64Equal(ctrl, 2))
			addend.ConditionalSelect(addend, threeP, helpers.Uint64Equal(ctrl, 3))

			q.Add(q, addend)
		}

		return v.Set(q)
	*/

	// This uses a 4-bit window, decreasing index (MSB -> LSB).  A 2-bit
	// window is only ~10% worse, so the tradeoff for the larger table
	// isn't totally convincing, but it sees like a reasonably popular
	// window size.

	// Precompute small multiples of P, 0P -> 15P
	var tbl [16]Point
	// tbl[0].Set(NewIdentityPoint()) // Leaving this uninitialized is ok...
	tbl[1].Set(p)
	for i := 2; i < len(tbl); i += 2 {
		tbl[i].Double(&tbl[i/2])
		tbl[i+1].Add(&tbl[i], p)
	}

	q := NewIdentityPoint()
	sBits := s.bits()
	for i := len(sBits) - 1; i >= 0; i = i - 4 {
		if i != len(sBits)-1 { // The branch predictor will save us.
			q.Double(q)
			q.Double(q)
			q.Double(q)
			q.Double(q)
		}

		ctrl := uint64(sBits[i]<<3 | sBits[i-1]<<2 | sBits[i-2]<<1 | sBits[i-3])
		addend := NewIdentityPoint()
		for j := uint64(1); j < uint64(len(tbl)); j++ { // Skip the 0th element.
			addend.ConditionalSelect(addend, &tbl[j], helpers.Uint64Equal(ctrl, j))
		}

		q.Add(q, addend)
	}

	return v.Set(q)
}

// ScalarBaseMult sets `v = s * G`, and returns `v`.
func (v *Point) ScalarBaseMult(s *Scalar, p *Point) *Point {
	return v.ScalarMult(s, NewGeneratorPoint())
}
