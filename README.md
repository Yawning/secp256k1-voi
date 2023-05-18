### secp256k1-voi - Yet another secp256k1 implementation
#### Yawning Angel (yawning at schwanenlied dot me)

> Ponzi schemes exist in stable disequilibrium. This means that while
> they can’t ultimately succeed, they can persist indefinitely—until
> they don’t.
>
> --Harry Markopolos

This is a correctness/simplicity-first implementation of the secp256k1
elliptic curve used by shitcoins, written as an elaborate cry for help.

The following techniques and tools are used for "correctness/simplicity":
- The scalar/field arithmetic implementations are produced by [fiat-crypto][1].
- The scalar/field inversion, and the field square root implementations
are produced by [addchain][2].
- Exception free point addition and doubling formulas from
["Complete addition formulas for prime order elliptic curves"][3] by
Renes, Costello, and Batina are used.

#### WARNING

***DO NOT USE THIS PACKAGE FOR ANYTHING YET***

#### Notes

- No, this is not done yet.
- Yes, the propriatary license is a placeholder till this is done, and
I figure out what I want to do with it.
- Yes, this needs a lot more test cases.
- No, this has not been audited.  Unless you are willing to pay for it,
do not ask about it.  If you do not know how much that will cost, you
can not afford it.
- The API and some interals are ***heavily*** inspired by
Filippo's [edwards25519][4] and [nistec][5] packages.
- Only the 64-bit implementations of the underlying field arithmetic are
used, as 32-bit architectures are either increasingly irrelevant (x86, ARM)
or fucking garbage (WASM).  I may reconsider this when Golang gets build
tags that make this easy (and no, keeping track of all the architectures
is not "easy").
- No attempt is made to sanitize memory.  It is a lost cause in most
languages, and totally, utterly hopeless in Go.
- Worms in my brain, get them out.

##### Performance

In short (only relevant figures listed):
```
cpu: AMD Ryzen 7 5700G with Radeon Graphics
BenchmarkPoint/ScalarMult-16               	   10000	    100306 ns/op	       0 B/op       0 allocs/op
BenchmarkPoint/ScalarBaseMult-16           	   38205	     31741 ns/op	       0 B/op       0 allocs/op
BenchmarkPoint/DoubleScalarMultBasepointVartime-16         	   14076	     88455 ns/op	     672 B/op	      11 allocs/op
BenchmarkPoint/s11n/UncompressedBytes-16                   	  192446	      5517 ns/op	       0 B/op	       0 allocs/op
BenchmarkPoint/s11n/CompressedBytes-16                     	  219115	      5520 ns/op	       0 B/op	       0 allocs/op
```

"It's alright".  `dcrd/dcrec/secp256k1` is faster (back of the envelope
performance for `u1 * G + u2 * P` is approx 81 us on my system), but
that implementation does not have any constant time curve operations,
and the scalar multiply uses a lot more optimization techniques.

Potential improvements:
- The constant time table lookup can be trivially vectorized.
- The GLV decomposition is not all that optimized.
- The GLV decomposition can be used for the ScalarMult as well.
- In theory [Bernstein-Yang inversion][6] should be faster than addition
chain based ones, and fiat provides a divstep implementation.  Figure out
why it is considerably (approx 2.5x) slower in practice.
- If absolutely needed, this could use a hilariously oversized table for
the scalar-basepoint multiply like dcrec (512 KiB vs 60 KiB).

[1]: https://github.com/mit-plv/fiat-crypto
[2]: https://github.com/mmcloughlin/addchain
[3]: https://eprint.iacr.org/2015/1060.pdf
[4]: https://pkg.go.dev/filippo.io/edwards25519
[5]: https://pkg.go.dev/filippo.io/nistec
[6]: https://eprint.iacr.org/2019/266