package field

import (
	"testing"

	fiat "gitlab.com/yawning/secp256k1-voi.git/internal/fiat/secp256k1montgomery"
)

func BenchmarkField(b *testing.B) {
	b.Run("Invert/addchain", func(b *testing.B) {
		fe := NewElement().MustRandomize()
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			fe.Invert(fe)
		}
	})
	b.Run("Invert/fiat", func(b *testing.B) {
		fe := NewElement().MustRandomize()
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			fe.InvertFiat(fe)
		}
	})
}

func (fe *Element) InvertFiat(x *Element) *Element {
	fiat.Invert(&fe.m, &x.m)
	return fe
}
