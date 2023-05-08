// Copyright (c) 2013, 2014 Pieter Wuille
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package field

// This routine is shamelessly lifted from libsecp256k1.  Unlike RustCrypto,
// I chose to keep the upstream license notice.

// Sqrt sets `fe = Sqrt(a)`, and returns 1 iff the square root exists.
// In all other cases, `fe = 0`, and 0 is returned.
func (fe *Element) Sqrt(a *Element) (*Element, uint64) {
	// Given that p is congruent to 3 mod 4, we can compute the square
	// root of a mod p as the (p+1)/4'th power of a.
	//
	// As (p+1)/4 is an even number, it will have the same result for
	// a and for (-a). Only one of these two numbers actually has a
	// square root however, so we test at the end by squaring and
	// comparing to the input.
	// Also because (p+1)/4 is an even number, the computed square
	// root is itself always a square (a ** ((p+1)/4) is the square

	var (
		x2   = NewElement()
		x3   = NewElement()
		x6   = NewElement()
		x9   = NewElement()
		x11  = NewElement()
		x22  = NewElement()
		x44  = NewElement()
		x88  = NewElement()
		x176 = NewElement()
		x220 = NewElement()
		x223 = NewElement()
		t1   = NewElement()
		r    = NewElement()
	)

	// The binary representation of (p + 1)/4 has 3 blocks of 1s,
	// with lengths in { 2, 22, 223 }. Use an addition chain to
	// calculate 2^n - 1 for each block: 1, [2], 3, 6, 9, 11, [22],
	// 44, 88, 176, 220, [223]

	x2.Square(a)
	x2.Multiply(x2, a)

	x3.Square(x2)
	x3.Multiply(x3, a)

	x6.Pow2k(x3, 3)
	x6.Multiply(x6, x3)

	x9.Pow2k(x6, 3)
	x9.Multiply(x9, x3)

	x11.Pow2k(x9, 2)
	x11.Multiply(x11, x2)

	x22.Pow2k(x11, 11)
	x22.Multiply(x22, x11)

	x44.Pow2k(x22, 22)
	x44.Multiply(x44, x22)

	x88.Pow2k(x44, 44)
	x88.Multiply(x88, x44)

	x176.Pow2k(x88, 88)
	x176.Multiply(x176, x88)

	x220.Pow2k(x176, 44)
	x220.Multiply(x220, x44)

	x223.Pow2k(x220, 3)
	x223.Multiply(x223, x3)

	// The final result is then assembled using a sliding window over
	// the blocks.

	t1.Pow2k(x223, 23)
	t1.Multiply(t1, x22)
	t1.Pow2k(t1, 6)
	t1.Multiply(t1, x2)
	t1.Square(t1)
	r.Square(t1)

	// Check that a square root was actually calculated
	//
	// Note/yawning: Set fe after the check to support the input and
	// output aliasing, and set fe to something sensible if the square
	// root doesn't exist.

	t1.Square(r)
	isSqrt := t1.Equal(a) // of a ** ((p+1)/8)).

	fe.ConditionalSelect(&zeroElement, r, isSqrt)

	return fe, isSqrt
}
