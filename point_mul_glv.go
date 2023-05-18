package secp256k1

import (
	"math/big"

	"gitlab.com/yawning/secp256k1-voi.git/internal/field"
)

// GLV decomposition is first documented in "Faster Point Multiplication
// on Elliptic Curves with Efficient Endomorphisms" by Gallant, Lambert,
// and Vanstone.  This is the infamous endomorphism-based secp256k1
// acceleration.
//
// Given:
// - P(x,y) on the curve
// - P'(beta*x,y) on the curve
//
// There is a scalar lambda where lambda * P = P'.
//
// For an arbitrary scalar k:
// - Decompose into k = k1 + k2 * lambda mod n
// - Calculate k * P = k1 * P + k2 * lambda * P
//                   = k1 * P + k2 * P'
//
// See:
// - https://www.iacr.org/archive/crypto2001/21390189.pdf
// - https://link.springer.com/book/10.1007/b97644
// - https://bitcointalk.org/index.php?topic=3238.0
// - https://homepages.dcc.ufmg.br/~leob/papers/jcen12.pdf

var (
	// -Lambda = 0xac9c52b33fa3cf1f5ad9e3fd77ed9ba4a880b9fc8ec739c2e0cfc810b51283cf
	negLambda = newScalarFromSaturated(
		0xac9c52b33fa3cf1f,
		0x5ad9e3fd77ed9ba4,
		0xa880b9fc8ec739c2,
		0xe0cfc810b51283cf,
	)

	// Beta = 0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee
	beta = field.NewElementFromSaturated(
		0x7ae96a2b657c0710,
		0x6e64479eac3434e9,
		0x9cf0497512f58995,
		0xc1396c28719501ee,
	)

	// -B1 = 0xe4437ed6010e88286f547fa90abfe4c3
	negB1 = newScalarFromSaturated(
		0,
		0,
		0xe4437ed6010e8828,
		0x6f547fa90abfe4c3,
	)
	bigNegB1 = func() *big.Int {
		z, _ := (&big.Int{}).SetString("0xe4437ed6010e88286f547fa90abfe4c3", 0)
		return z
	}()

	// B2 = 0x3086d221a7d46bcde86c90e49284eb15
	bigB2 = func() *big.Int {
		z, _ := (&big.Int{}).SetString("0x3086d221a7d46bcde86c90e49284eb15", 0)
		return z
	}()

	// -B2 = 0xfffffffffffffffffffffffffffffffe8a280ac50774346dd765cda83db1562c
	negB2 = newScalarFromSaturated(
		0xffffffffffffffff,
		0xfffffffffffffffe,
		0x8a280ac50774346d,
		0xd765cda83db1562c,
	)

	// n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
	bigN = func() *big.Int {
		z, _ := (&big.Int{}).SetString("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 0)
		return z
	}()
)

func (s *Scalar) splitVartime() (*Scalar, *Scalar) {
	// From "Guide to Elliptic Curve Cryptography" by Hankerson,
	// Menezes, Vanstone, Algorithm 3.74 "Balanced length-two
	// representation of a multiplier":
	//
	//   c1 = round(b2 * k / n)
	//   c2 = round(-b1 * k / n)
	//   k1 = k - c1a1 - c2a2
	//   k2 =    -c1b1 - c2b2
	//
	// As libsecp256k1's implementation and comments notes:
	//   k1 = k - k2 * lambda mod n
	// Which saves having to use a1 and a2.

	// Regardless of how we do this, because fiat won't do it
	// for us, we need to get the non-montgomery representation
	// of k.

	kBytes := s.Bytes()

	// First attempt: Do the naive thing, and use math/big.Int
	// to derive c1 and c2.  This isn't nearly as bad as it may
	// seem, given the vartime label (~2040 ns).  Shame that it
	// does heap allocs though.

	bigK := (&big.Int{}).SetBytes(kBytes)

	big2Scalar := func(z *big.Int) *Scalar {
		var tmp [ScalarSize]byte
		z.FillBytes(tmp[:])

		// INVARIANT: z < n
		sc, err := NewScalarFromCanonicalBytes(&tmp)
		if err != nil {
			panic("secp256k1/scalar: failed to set in split: " + err.Error())
		}
		return sc
	}

	// c1 = round(b2 * k / n)
	c1 := big2Scalar((&big.Int{}).Div((&big.Int{}).Mul(bigB2, bigK), bigN))

	// c2 = round(-b1 * k / n)
	c2 := big2Scalar((&big.Int{}).Div((&big.Int{}).Mul(bigNegB1, bigK), bigN))

	// k2 = -c1b1 - c2b2
	k2 := NewScalar().Multiply(c1, negB1)
	tmp := NewScalar().Multiply(c2, negB2)
	k2 = k2.Add(k2, tmp)

	// k1 = k - k2 * lambda mod n
	k1 := NewScalar().Multiply(k2, negLambda)
	k1.Add(s, k1)

	return k1, k2
}

func (v *Point) mulBeta(p *Point) *Point {
	assertPointsValid(p)

	v.x.Multiply(&p.x, beta)
	v.y.Set(&p.y)
	v.z.Set(&p.z)
	v.isValid = p.isValid

	return v
}

// scalarMultVartimeGLV sets `v = s * p`, and returns `v` in variable time.
func (v *Point) scalarMultVartimeGLV(s *Scalar, p *Point) *Point {
	// TODO/perf: Consider using w-NAF as well.

	pee := NewPointFrom(p)
	peePrime := newRcvr().mulBeta(p)

	// Split the scalar.
	//
	// Pick the shorter reprentation for each of the returned scalars
	// by negating both the scalar and it's corresponding point if
	// required.
	k1, k2 := s.splitVartime()
	if k1.IsGreaterThanHalfN() == 1 {
		k1.Negate(k1)
		pee.Negate(pee)
	}
	if k2.IsGreaterThanHalfN() == 1 {
		k2.Negate(k2)
		peePrime.Negate(peePrime)
	}

	pTbl := newProjectivePointMultTable(pee)
	pPrimeTbl := newProjectivePointMultTable(peePrime)

	v.Identity()

	off := 15 // XXX: Could be 16 with tighter bounds on split.
	k1Bytes, k2Bytes := k1.Bytes(), k2.Bytes()
	for {
		if k1Bytes[off] != 0 || k2Bytes[off] != 0 {
			break
		}
		off++
		if off == ScalarSize {
			// k1 == 0 && k2 == 0, therefore s * P = Inf
			return v
		}
	}

	k1Bytes, k2Bytes = k1Bytes[off:], k2Bytes[off:]
	kLen := len(k1Bytes)

	for i := 0; i < kLen; i++ {
		if i != 0 {
			v.doubleComplete(v)
			v.doubleComplete(v)
			v.doubleComplete(v)
			v.doubleComplete(v)
		}

		bK1, bK2 := k1Bytes[i], k2Bytes[i]

		pTbl.SelectAndAddVartime(v, uint64(bK1>>4))
		pPrimeTbl.SelectAndAddVartime(v, uint64(bK2>>4))

		v.doubleComplete(v)
		v.doubleComplete(v)
		v.doubleComplete(v)
		v.doubleComplete(v)

		pTbl.SelectAndAddVartime(v, uint64(bK1&0xf))
		pPrimeTbl.SelectAndAddVartime(v, uint64(bK2&0xf))
	}

	return v
}
