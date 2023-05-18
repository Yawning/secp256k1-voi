package secp256k1

import (
	"encoding/binary"
	"errors"
	"math/bits"

	"gitlab.com/yawning/secp256k1-voi.git/internal/disalloweq"
	fiat "gitlab.com/yawning/secp256k1-voi.git/internal/fiat/secp256k1montgomeryscalar"
	"gitlab.com/yawning/secp256k1-voi.git/internal/helpers"
)

// ScalarSize is the size of a scalar in bytes.
const ScalarSize = 32

var (
	nSat = func() [5]uint64 {
		var n [5]uint64
		fiat.Msat(&n)
		return n
	}()

	// nSat >> 1
	halfNSat = [4]uint64{
		0xdfe92f46681b20a0,
		0x5d576e7357a4501d,
		0xffffffffffffffff,
		0x7fffffffffffffff,
	}
)

// Scalar is an integer modulo `n = 2^256 - 432420386565659656852420866394968145599`.
// All arguments and receivers are allowed to alias.  The zero value is
// a valid zero element.
type Scalar struct {
	_ disalloweq.DisallowEqual
	m fiat.MontgomeryDomainFieldElement
}

// Zero sets `s = 0` and returns `s`.
func (s *Scalar) Zero() *Scalar {
	for i := range s.m {
		s.m[i] = 0
	}
	return s
}

// One sets `s = 1` and returns `s`.
func (s *Scalar) One() *Scalar {
	fiat.SetOne(&s.m)
	return s
}

// Add sets `s = a + b` and returns `s`.
func (s *Scalar) Add(a, b *Scalar) *Scalar {
	fiat.Add(&s.m, &a.m, &b.m)
	return s
}

// Subtract sets `s = a - b` and returns `s`.
func (s *Scalar) Subtract(a, b *Scalar) *Scalar {
	fiat.Sub(&s.m, &a.m, &b.m)
	return s
}

// Negate sets `s = -a` and returns `s`.
func (s *Scalar) Negate(a *Scalar) *Scalar {
	fiat.Opp(&s.m, &a.m)
	return s
}

// Multiply sets `s = a * b` and returns `s`.
func (s *Scalar) Multiply(a, b *Scalar) *Scalar {
	fiat.Mul(&s.m, &a.m, &b.m)
	return s
}

// Square sets `s = a * a` and returns `s`.
func (s *Scalar) Square(a *Scalar) *Scalar {
	fiat.Square(&s.m, &a.m)
	return s
}

// Set sets `s = a` and returns `s`.
func (s *Scalar) Set(a *Scalar) *Scalar {
	copy(s.m[:], a.m[:])
	return s
}

// SetBytes sets `s = src`, where `src` is a 32-byte big-endian encoding
// of `s`, and returns `s, 0`.  If `src` is not a canonical encoding of
// `s`, `src` is reduced modulo n, and SetBytes returns `s, 1`.
func (s *Scalar) SetBytes(src *[ScalarSize]byte) (*Scalar, uint64) {
	l := helpers.BytesToSaturated(src)

	didReduce := reduceSaturated(&l, &l)
	s.uncheckedSetSaturated(&l)

	return s, didReduce
}

// SetCanonicalBytes sets `s = src`, where `src` is a 32-byte big-endian
// encoding of `s`, and returns `s`.  If `src` is not a canonical encoding
// of `s`, SetCanonicalBytes returns nil and an error, and the receiver is
// unchanged.
func (s *Scalar) SetCanonicalBytes(src *[ScalarSize]byte) (*Scalar, error) {
	l := helpers.BytesToSaturated(src)

	if reduceSaturated(&l, &l) != 0 {
		return nil, errors.New("secp256k1: scalar value out of range")
	}
	s.uncheckedSetSaturated(&l)

	return s, nil
}

// Bytes returns the canonical big-endian encoding of `s`.
func (s *Scalar) Bytes() []byte {
	// Blah blah blah outline blah escape analysis blah.
	var dst [ScalarSize]byte
	return s.getBytes(&dst)
}

func (s *Scalar) getBytes(dst *[ScalarSize]byte) []byte {
	var nm fiat.NonMontgomeryDomainFieldElement
	fiat.FromMontgomery(&nm, &s.m)

	binary.BigEndian.PutUint64(dst[0:], nm[3])
	binary.BigEndian.PutUint64(dst[8:], nm[2])
	binary.BigEndian.PutUint64(dst[16:], nm[1])
	binary.BigEndian.PutUint64(dst[24:], nm[0])

	return dst[:]
}

// ConditionalNegate sets `s = a` iff `ctrl == 0`, `s = -a` otherwise,
// and returns `s`.
func (s *Scalar) ConditionalNegate(a *Scalar, ctrl uint64) *Scalar {
	sNeg := NewScalar().Negate(a)

	return s.ConditionalSelect(a, sNeg, ctrl)
}

// ConditionalSelect sets `s = a` iff `ctrl == 0`, `s = b` otherwise,
// and returns `s`.
func (s *Scalar) ConditionalSelect(a, b *Scalar, ctrl uint64) *Scalar {
	fiat.Selectznz((*[4]uint64)(&s.m), fiat.Uint64ToUint1(ctrl), (*[4]uint64)(&a.m), (*[4]uint64)(&b.m))
	return s
}

// Equal returns 1 iff `s == a`, 0 otherwise.
func (s *Scalar) Equal(a *Scalar) uint64 {
	return helpers.FiatLimbsAreEqual((*[4]uint64)(&s.m), (*[4]uint64)(&a.m))
}

// IsZero returns 1 iff `s == 0`, 0 otherwise.
func (s *Scalar) IsZero() uint64 {
	var ctrl uint64
	fiat.Nonzero(&ctrl, (*[4]uint64)(&s.m))

	return helpers.Uint64IsZero(ctrl)
}

// IsGreaterThanHalfN returns 1 iff `s > n / 2`, where `n` is the order
// of G, 0 otherwise.
func (s *Scalar) IsGreaterThanHalfN() uint64 {
	var nm fiat.NonMontgomeryDomainFieldElement
	fiat.FromMontgomery(&nm, &s.m)

	var (
		borrow uint64
		diff   [4]uint64
	)
	diff[0], borrow = bits.Sub64(nm[0], halfNSat[0], borrow)
	diff[1], borrow = bits.Sub64(nm[1], halfNSat[1], borrow)
	diff[2], borrow = bits.Sub64(nm[2], halfNSat[2], borrow)
	diff[3], borrow = bits.Sub64(nm[3], halfNSat[3], borrow)

	// if borrow == 1, s < n/2
	// if borrow == 0 && diff == 0, s = n/2
	return helpers.Uint64IsZero(borrow) & helpers.Uint64IsNonzero(diff[0]|diff[1]|diff[2]|diff[3])
}

func (s *Scalar) uncheckedSetSaturated(a *[4]uint64) *Scalar {
	fiat.ToMontgomery(&s.m, (*fiat.NonMontgomeryDomainFieldElement)(a))
	return s
}

// pow2k sets `s = a ^ (2 * k)` and returns `s`.  k MUST be non-zero.
func (s *Scalar) pow2k(a *Scalar, k uint) *Scalar {
	if k == 0 {
		// This could just set s = a, but "don't do that".
		panic("secp256k1: Scalar.pow2k k out of bounds")
	}

	// XXX/perf: It might be worth inlining this manually at some point.
	fiat.Square(&s.m, &a.m)
	for i := uint(1); i < k; i++ {
		fiat.Square(&s.m, &s.m)
	}

	return s
}

// NewScalar returns a new zero Scalar.
func NewScalar() *Scalar {
	return &Scalar{}
}

// NewScalarFrom creates a new Scalar from another.
func NewScalarFrom(other *Scalar) *Scalar {
	return NewScalar().Set(other)
}

// NewScalarFromCanonicalBytes creates a new Scalar from the canonical
// big-endian byte representation.
func NewScalarFromCanonicalBytes(src *[ScalarSize]byte) (*Scalar, error) {
	s, err := NewScalar().SetCanonicalBytes(src)
	if err != nil {
		return nil, err
	}

	return s, nil
}

func newScalarFromSaturated(l3, l2, l1, l0 uint64) *Scalar {
	// Since the NonMontgomeryDomainFieldElement is fully-saturated
	// this is trivial.
	var l [4]uint64
	l[0] = l0
	l[1] = l1
	l[2] = l2
	l[3] = l3

	// Yes, this panics if you fuck up.  Why are you using this for
	// anything but pre-computed constants?
	if reduceSaturated(&l, &l) != 0 {
		panic("secp256k1: saturated scalar out of range")
	}

	return NewScalar().uncheckedSetSaturated(&l)
}

func reduceSaturated(dst, src *[4]uint64) uint64 {
	// Assume that the reduction is needed, and calclate
	// reduced = src - n.  This is fine because src will never
	// be >= 2n.
	var (
		reduced [4]uint64
		borrow  uint64
	)
	reduced[0], borrow = bits.Sub64(src[0], nSat[0], borrow)
	reduced[1], borrow = bits.Sub64(src[1], nSat[1], borrow)
	reduced[2], borrow = bits.Sub64(src[2], nSat[2], borrow)
	reduced[3], borrow = bits.Sub64(src[3], nSat[3], borrow)

	// if borrow == 0, src >= n
	// if borrow == 1, src < n (no reduction needed)
	didReduce := helpers.Uint64IsZero(borrow)

	fiat.Selectznz(dst, fiat.Uint64ToUint1(didReduce), src, &reduced)

	return didReduce
}
