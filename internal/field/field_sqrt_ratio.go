// Copyright (c) 2023 Yawning Angel
//
// SPDX-License-Identifier: BSD-3-Clause

// Code generated by addchain. DO NOT EDIT.

package field

// c2 = sqrt(-Z)
var feC2 = NewElementFromSaturated(
	0x31fdf302724013e5,
	0x7ad13fb38f842afe,
	0xec184f00a74789dd,
	0x286729c8303c4a59,
)

// Sqrt sets `fe = Sqrt(a)`, and returns 1 iff the square root exists.
// In all other cases, `fe = 0`, and 0 is returned.
func (fe *Element) Sqrt(a *Element) (*Element, uint64) {
	// This is slightly more complicated than doing `fe^((p+1)/4)`,
	// but this makes implementing h2c a lot easier, and addchain
	// does all the heavy lifting anyway.

	tmp, isSqrt := NewElement().SqrtRatio(a, feOne)
	fe.ConditionalSelect(&feZero, tmp, isSqrt)

	return fe, isSqrt
}

func (z *Element) SqrtRatio(u, v *Element) (*Element, uint64) {
	// From Hashing to Elliptic Curves (draft-irtf-cfrg-hash-to-curve-16)

	// F.2.1.2.  optimized sqrt_ratio for q = 3 mod 4

	// 1. tv1 = v^2
	tv1 := NewElement().Square(v)

	// 2. tv2 = u * v
	tv2 := NewElement().Multiply(u, v)

	// 3. tv1 = tv1 * tv2
	tv1.Multiply(tv1, tv2)

	// 4. y1 = tv1^c1
	y1 := NewElement().pow3mod4(tv1)

	// 5. y1 = y1 * tv2
	y1.Multiply(y1, tv2)

	// 6. y2 = y1 * c2
	y2 := NewElement().Multiply(y1, feC2)

	// 7. tv3 = y1^2
	tv3 := NewElement().Square(y1)

	// 8. tv3 = tv3 * v
	tv3.Multiply(tv3, v)

	// 9. isQR = tv3 == u
	isQuadraticResidue := tv3.Equal(u)

	// 10. y = CMOV(y2, y1, isQR)
	z.ConditionalSelect(y2, y1, isQuadraticResidue)

	// 11. return (isQR, y)

	return z, isQuadraticResidue
}

func (z *Element) pow3mod4(x *Element) *Element {
	// Exponentiation computation is derived from the addition chain:
	//
	//	_10      = 2*1
	//	_11      = 1 + _10
	//	_1100    = _11 << 2
	//	_1111    = _11 + _1100
	//	_11110   = 2*_1111
	//	_11111   = 1 + _11110
	//	_1111100 = _11111 << 2
	//	_1111111 = _11 + _1111100
	//	x11      = _1111111 << 4 + _1111
	//	x22      = x11 << 11 + x11
	//	x27      = x22 << 5 + _11111
	//	x54      = x27 << 27 + x27
	//	x108     = x54 << 54 + x54
	//	x216     = x108 << 108 + x108
	//	x223     = x216 << 7 + _1111111
	//	i266     = ((x223 << 23 + x22) << 5 + 1) << 3
	//	return     _11 + i266
	//
	// Operations: 253 squares 14 multiplies
	//
	// Generated by github.com/mmcloughlin/addchain v0.4.0.

	// Allocate Temporaries.
	var (
		t0 = NewElement()
		t1 = NewElement()
		t2 = NewElement()
		t3 = NewElement()
		t4 = NewElement()
		t5 = NewElement()
	)

	// Step 1: t0 = x^0x2
	t0.Square(x)

	// Step 2: t0 = x^0x3
	t0.Multiply(x, t0)

	// Step 4: t1 = x^0xc
	t1.Pow2k(t0, 2)

	// Step 5: t1 = x^0xf
	t1.Multiply(t0, t1)

	// Step 6: t2 = x^0x1e
	t2.Square(t1)

	// Step 7: t2 = x^0x1f
	t2.Multiply(x, t2)

	// Step 9: t3 = x^0x7c
	t3.Pow2k(t2, 2)

	// Step 10: t3 = x^0x7f
	t3.Multiply(t0, t3)

	// Step 14: t4 = x^0x7f0
	t4.Pow2k(t3, 4)

	// Step 15: t1 = x^0x7ff
	t1.Multiply(t1, t4)

	// Step 26: t4 = x^0x3ff800
	t4.Pow2k(t1, 11)

	// Step 27: t1 = x^0x3fffff
	t1.Multiply(t1, t4)

	// Step 32: t4 = x^0x7ffffe0
	t4.Pow2k(t1, 5)

	// Step 33: t2 = x^0x7ffffff
	t2.Multiply(t2, t4)

	// Step 60: t4 = x^0x3ffffff8000000
	t4.Pow2k(t2, 27)

	// Step 61: t2 = x^0x3fffffffffffff
	t2.Multiply(t2, t4)

	// Step 115: t4 = x^0xfffffffffffffc0000000000000
	t4.Pow2k(t2, 54)

	// Step 116: t2 = x^0xfffffffffffffffffffffffffff
	t2.Multiply(t2, t4)

	// Step 224: t4 = x^0xfffffffffffffffffffffffffff000000000000000000000000000
	t4.Pow2k(t2, 108)

	// Step 225: t2 = x^0xffffffffffffffffffffffffffffffffffffffffffffffffffffff
	t2.Multiply(t2, t4)

	// Step 232: t2 = x^0x7fffffffffffffffffffffffffffffffffffffffffffffffffffff80
	t2.Pow2k(t2, 7)

	// Step 233: t3 = x^0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffff
	t3.Multiply(t3, t2)

	// Step 256: t3 = x^0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffff800000
	t3.Pow2k(t3, 23)

	// Step 257: t1 = x^0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff
	t1.Multiply(t1, t3)

	// Step 262: t1 = x^0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe0
	t1.Pow2k(t1, 5)

	// Step 263: t5 = x^0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe1
	t5.Multiply(x, t1)

	// Step 266: t5 = x^0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff08
	t5.Pow2k(t5, 3)

	// Step 267: z = x^0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0b
	z.Multiply(t0, t5)

	return z
}
