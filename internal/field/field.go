// Package field implements arithmetic modulo p = 2^256 - 2^32 - 977.
package field

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"

	"gitlab.com/yawning/secp256k1-voi.git/internal/disalloweq"
	fiat "gitlab.com/yawning/secp256k1-voi.git/internal/fiat/secp256k1montgomery"
	"gitlab.com/yawning/secp256k1-voi.git/internal/helpers"
)

// ElementSize is the size of a field element in bytes.
const ElementSize = 32

var (
	mSat = func() [5]uint64 {
		var m [5]uint64
		fiat.Msat(&m)
		return m
	}()

	zeroElement Element
)

// Element is a field element.  All arguments and receivers are allowed
// to alias.  The zero value is a valid zero element.
type Element struct {
	_ disalloweq.DisallowEqual
	m fiat.MontgomeryDomainFieldElement
}

// Zero sets `fe = 0` and returns `fe`.
func (fe *Element) Zero() *Element {
	for i := range fe.m {
		fe.m[i] = 0
	}
	return fe
}

// One sets `fe = 1` and returns `fe`.
func (fe *Element) One() *Element {
	fiat.SetOne(&fe.m)
	return fe
}

// Add sets `fe = a + b` and returns `fe`.
func (fe *Element) Add(a, b *Element) *Element {
	fiat.Add(&fe.m, &a.m, &b.m)
	return fe
}

// Subtract sets `fe = a - b` and returns `fe`.
func (fe *Element) Subtract(a, b *Element) *Element {
	fiat.Sub(&fe.m, &a.m, &b.m)
	return fe
}

// Negate sets `fe = -a` and returns `fe`.
func (fe *Element) Negate(a *Element) *Element {
	fiat.Opp(&fe.m, &a.m)
	return fe
}

// Multiply sets `fe = a * b` and returns `fe`.
func (fe *Element) Multiply(a, b *Element) *Element {
	fiat.Mul(&fe.m, &a.m, &b.m)
	return fe
}

// Square sets `fe = a * a` and returns `fe`.
func (fe *Element) Square(a *Element) *Element {
	fiat.Square(&fe.m, &a.m)
	return fe
}

// Pow2k sets `fe = a ^ (2 * k)` and returns `fe`.  k MUST be non-zero.
func (fe *Element) Pow2k(a *Element, k uint) *Element {
	if k == 0 {
		// This could just set fe = a, but "don't do that".
		panic("internal/field: k out of bounds")
	}

	// XXX/perf: It might be worth inlining this manually at some point.
	fiat.Square(&fe.m, &a.m)
	for i := uint(1); i < k; i++ {
		fiat.Square(&fe.m, &fe.m)
	}

	return fe
}

// Set sets `fe = a` and returns `fe`.
func (fe *Element) Set(a *Element) *Element {
	copy(fe.m[:], a.m[:])
	return fe
}

// SetCanonicalBytes sets `fe = src`, where `src` is a 32-byte big-endian
// encoding of `fe`, and returns `fe`.  If `src` is not a canonical
// encoding of `fe`, SetCanonicalBytes returns nil and an error, and the
// receiver is unchanged.
func (fe *Element) SetCanonicalBytes(src *[ElementSize]byte) (*Element, error) {
	l := helpers.BytesToSaturated(src)

	if !fe.setSaturated(&l) {
		return nil, errors.New("internal/field: value out of range")
	}

	return fe, nil
}

// Bytes returns the canonical big-endian encoding of `fe`.
func (fe *Element) Bytes() []byte {
	// Blah blah blah outline blah escape analysis blah.
	var dst [ElementSize]byte
	return fe.getBytes(&dst)
}

func (fe *Element) getBytes(dst *[ElementSize]byte) []byte {
	var nm fiat.NonMontgomeryDomainFieldElement
	fiat.FromMontgomery(&nm, &fe.m)

	binary.BigEndian.PutUint64(dst[0:], nm[3])
	binary.BigEndian.PutUint64(dst[8:], nm[2])
	binary.BigEndian.PutUint64(dst[16:], nm[1])
	binary.BigEndian.PutUint64(dst[24:], nm[0])

	return dst[:]
}

// ConditionalSelect sets `fe = a` iff `ctrl == 0`, `fe = b` otherwise,
// and returns `fe`.
func (fe *Element) ConditionalSelect(a, b *Element, ctrl uint64) *Element {
	fiat.Selectznz((*[4]uint64)(&fe.m), fiat.Uint64ToUint1(ctrl), (*[4]uint64)(&a.m), (*[4]uint64)(&b.m))
	return fe
}

// Equal returns 1 iff `fe == a`, 0 otherwise.
func (fe *Element) Equal(a *Element) uint64 {
	return helpers.FiatLimbsAreEqual((*[4]uint64)(&fe.m), (*[4]uint64)(&a.m))
}

// IsZero returns 1 iff `fe == 0`, 0 otherwise.
func (fe *Element) IsZero() uint64 {
	var ctrl uint64
	fiat.Nonzero(&ctrl, (*[4]uint64)(&fe.m))

	return helpers.Uint64IsZero(ctrl)
}

// IsOdd returns 1 iff `fe % 2 == 1`, 0 otherwise.
func (fe *Element) IsOdd() uint64 {
	// XXX/perf: Can't this just be done in the Montgomery domain?
	var nm fiat.NonMontgomeryDomainFieldElement
	fiat.FromMontgomery(&nm, &fe.m)

	return helpers.Uint64IsNonzero(nm[0] & 1)
}

// String returns the big-endian hex representation of `fe`.
func (fe *Element) String() string {
	return hex.EncodeToString(fe.Bytes())
}

func (fe *Element) setSaturated(a *[4]uint64) bool {
	if !saturatedInRange(a) {
		return false
	}
	fiat.ToMontgomery(&fe.m, (*fiat.NonMontgomeryDomainFieldElement)(a))
	return true
}

// MustRandomize randomizes and returns `fe`, or panics.
func (fe *Element) MustRandomize() *Element {
	var b [ElementSize]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			panic("internal/field: entropy source failure")
		}
		if _, err := fe.SetCanonicalBytes(&b); err == nil {
			return fe
		}
	}
}

// NewElement returns a new zero Element.
func NewElement() *Element {
	return &Element{}
}

// NewElementFrom creates a new Element from another.
func NewElementFrom(other *Element) *Element {
	return NewElement().Set(other)
}

// NewElementFromSaturated creates a new Element from the raw saturated representation.
func NewElementFromSaturated(l3, l2, l1, l0 uint64) *Element {
	// Since the NonMontgomeryDomainFieldElement is fully-saturated
	// this is trivial.
	var l [4]uint64
	l[0] = l0
	l[1] = l1
	l[2] = l2
	l[3] = l3

	// Yes, this panics if you fuck up.  Why are you using this for
	// anything but pre-computed constants?
	var fe Element
	if !fe.setSaturated(&l) {
		panic("internal/field: saturated limbs out of range")
	}

	return &fe
}

// NewElementFromCanonicalBytes creates a new Element from the canonical
// big-endian byte representation.
func NewElementFromCanonicalBytes(src *[ElementSize]byte) (*Element, error) {
	e, err := NewElement().SetCanonicalBytes(src)
	if err != nil {
		return nil, err
	}

	return e, nil
}

func saturatedInRange(a *[4]uint64) bool {
	// XXX: Maybe this should do this "more correctly" and return
	// a uint64.  But AFAIK the only use of this routine is going
	// to be to return an error or to immediately panic.
	//
	// See the logic in the scalar `reduceSaturated` routine for
	// an example of "more correctly".
	var ok bool
	for i := 3; i >= 0; i-- {
		// For this specific value of `m`, the `src` limb can't be
		// greater than the corresponding `m` limb unless it is
		// the least-significant limb, so there is no need to
		// explicitly check for the "greater-than" or "equal" cases.
		ok = ok || a[i] < mSat[i]
	}

	return ok
}
