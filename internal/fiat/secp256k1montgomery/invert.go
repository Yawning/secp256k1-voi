package secp256k1montgomery

// Adapted from `fiat-crypto/inversion/c/inversion_template.c` and
// `fiat-crypto/inversion/zig/inversion.zig`.
//
// See: https://eprint.iacr.org/2021/549.pdf

const (
	invSatLimbs = 5   // SAT_LIMBS
	invLimbs    = 4   // LIMBS
	invLenPrime = 256 // LEN_PRIME
	invWordSize = 64  // WORD_SIZE
)

var (
	invPrecomp = func() *MontgomeryDomainFieldElement {
		var precomp MontgomeryDomainFieldElement
		DivstepPrecomp((*[4]uint64)(&precomp))
		return &precomp
	}()

	invIterations = func() int {
		return divstepIterations(invLenPrime)
	}()
)

func divstepIterations(lenPrime int) int {
	if lenPrime < 46 {
		return ((49 * lenPrime) + 80) / 17
	}
	return ((49 * lenPrime) + 57) / 17
}

func Invert(out, a *MontgomeryDomainFieldElement) {
	// Input being in the Montgomery domain is more ergonomic.
	var (
		tmp NonMontgomeryDomainFieldElement
		g   [invSatLimbs]uint64
	)
	FromMontgomery(&tmp, a)
	copy(g[:], tmp[:])

	var (
		f [invSatLimbs]uint64

		d          uint64 = 1
		r, v, h    MontgomeryDomainFieldElement
		out1       uint64
		out2, out3 [invSatLimbs]uint64
		out4, out5 MontgomeryDomainFieldElement
	)

	Msat(&f)
	SetOne(&r)

	for i := 0; i < invIterations-(invIterations%2); i = i + 2 {
		Divstep(&out1, &out2, &out3, (*[4]uint64)(&out4), (*[4]uint64)(&out5), d, &f, &g, (*[4]uint64)(&v), (*[4]uint64)(&r))
		Divstep(&d, &f, &g, (*[4]uint64)(&v), (*[4]uint64)(&r), out1, &out2, &out3, (*[4]uint64)(&out4), (*[4]uint64)(&out5))
	}
	if invIterations%2 != 0 {
		Divstep(&out1, &out2, &out3, (*[4]uint64)(&out4), (*[4]uint64)(&out5), d, &f, &g, (*[4]uint64)(&v), (*[4]uint64)(&r))
		v = out4
		f = out2
	}

	Opp(&h, &v)
	Selectznz((*[4]uint64)(&v), (uint1)(f[invSatLimbs-1]>>(invWordSize-1)), (*[4]uint64)(&v), (*[4]uint64)(&h))
	Mul(out, &v, invPrecomp)
}
