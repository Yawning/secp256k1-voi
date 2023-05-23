//go:build ignore

package main

import (
	. "github.com/mmcloughlin/avo/build"
	"github.com/mmcloughlin/avo/buildtags"
	. "github.com/mmcloughlin/avo/operand"
)

func main() {
	Package(".")

	c, err := buildtags.ParseConstraint("amd64,!purego")
	if err != nil {
		panic(err)
	}
	Constraints(c)

	lookupProjectivePoint()
	lookupAffinePoint()

	Generate()
}

func lookupProjectivePoint() {
	TEXT(
		"lookupProjectivePoint",
		NOSPLIT|NOFRAME,
		"func(tbl *projectivePointMultTable, out *Point, idx uint64)",
	)

	Comment(
		"This is nice and easy, since it is 3x32-bytes, so this fits",
		"neatly into the x86 SIMD registers.  While AVX is significantly",
		"nicer to work with, this is done with SSE2 so that only one",
		"version of this needs to be implemented.",
		"",
		"x0 = x[0] x1 = x[1]",
		"y0 = y[0] y1 = y[1]",
		"z0 = z[0] z1 = z[1]",
	)

	idx, mask := XMM(), XMM()
	tmp := Load(Param("idx"), GP64())
	MOVD(tmp, idx)
	PSHUFD(Imm(0), idx, idx)

	tblR := Load(Param("tbl"), GP64())
	tbl := Mem{Base: tblR}

	x0, x1, y0, y1, z0, z1 := XMM(), XMM(), XMM(), XMM(), XMM(), XMM()

	Comment("Implicit entry tbl[0] = Identity (0, 1, 0)")
	PXOR(mask, mask)
	PXOR(x0, x0)
	PXOR(x1, x1)
	PCMPEQL(idx, mask)
	MOVQ(U64(0x1000003d1), tmp)
	MOVQ(tmp, y0)
	PAND(mask, y0)
	PXOR(y1, y1)
	PXOR(z0, z0)
	PXOR(z1, z1)

	t0, t1, t2, t3, t4, t5 := XMM(), XMM(), XMM(), XMM(), XMM(), XMM()

	Comment("For i = 1; i <= 15; i++")
	i := tmp
	MOVQ(U64(1), i)

	Label("projectiveLookupLoop")
	MOVD(i, mask)
	INCQ(i)
	PSHUFD(Imm(0), mask, mask)
	PCMPEQL(idx, mask)
	MOVOU(tbl.Offset(0), t0)
	MOVOU(tbl.Offset(16), t1)
	MOVOU(tbl.Offset(32), t2)
	MOVOU(tbl.Offset(48), t3)
	MOVOU(tbl.Offset(64), t4)
	MOVOU(tbl.Offset(80), t5)
	ADDQ(Imm(96+8), tblR) // +8 for `isValid`
	CMPQ(i, Imm(15))
	PAND(mask, t0)
	PAND(mask, t1)
	PAND(mask, t2)
	PAND(mask, t3)
	PAND(mask, t4)
	PAND(mask, t5)
	POR(t0, x0)
	POR(t1, x1)
	POR(t2, y0)
	POR(t3, y1)
	POR(t4, z0)
	POR(t5, z1)
	JLE(LabelRef("projectiveLookupLoop"))

	Comment("Write out the result.")
	out := Mem{Base: Load(Param("out"), GP64())}
	MOVOU(x0, out.Offset(0))
	MOVOU(x1, out.Offset(16))
	MOVOU(y0, out.Offset(32))
	MOVOU(y1, out.Offset(48))
	MOVOU(z0, out.Offset(64))
	MOVOU(z1, out.Offset(80))

	RET()
}

func lookupAffinePoint() {
	TEXT(
		"lookupAffinePoint",
		NOSPLIT|NOFRAME,
		"func(tbl *affinePoint, out *affinePoint, idx uint64)",
	)

	Comment(
		"This is nice and easy, since it is 2x32-bytes, so this fits",
		"neatly into the x86 SIMD registers.  While AVX is significantly",
		"nicer to work with, this is done with SSE2 so that only one",
		"version of this needs to be implemented.",
		"",
		"x0 = x[0] x1 = x[1]",
		"y0 = y[0] y1 = y[1]",
	)

	idx, mask := XMM(), XMM()
	tmp := Load(Param("idx"), GP64())
	MOVD(tmp, idx)
	PSHUFD(Imm(0), idx, idx)

	tblR := Load(Param("tbl"), GP64())
	tbl := Mem{Base: tblR}

	x0, x1, y0, y1 := XMM(), XMM(), XMM(), XMM()

	Comment("Skip idx = 0, addition formula is invalid.")
	PXOR(x0, x0)
	PXOR(x1, x1)
	PXOR(y0, y0)
	PXOR(y1, y1)

	t0, t1, t2, t3 := XMM(), XMM(), XMM(), XMM()

	Comment("For i = 1; i <= 15; i++")
	i := tmp
	MOVQ(U64(1), i)

	Label("affineLookupLoop")
	MOVD(i, mask)
	INCQ(i)
	PSHUFD(Imm(0), mask, mask)
	PCMPEQL(idx, mask)
	MOVOU(tbl.Offset(0), t0)
	MOVOU(tbl.Offset(16), t1)
	MOVOU(tbl.Offset(32), t2)
	MOVOU(tbl.Offset(48), t3)
	ADDQ(Imm(64), tblR)
	CMPQ(i, Imm(15))
	PAND(mask, t0)
	PAND(mask, t1)
	PAND(mask, t2)
	PAND(mask, t3)
	POR(t0, x0)
	POR(t1, x1)
	POR(t2, y0)
	POR(t3, y1)
	JLE(LabelRef("affineLookupLoop"))

	Comment("Write out the result.")
	out := Mem{Base: Load(Param("out"), GP64())}
	MOVOU(x0, out.Offset(0))
	MOVOU(x1, out.Offset(16))
	MOVOU(y0, out.Offset(32))
	MOVOU(y1, out.Offset(48))

	RET()
}
