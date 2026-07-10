// Package namedret exercises Go's named-return values, particularly the
// fixed-array shape `func f() (a [N]frontend.Variable, ...)`. The zero
// value of a fixed array in Go is an N-element zero-filled array, so the
// prologue must emit `List.replicate N (0 : F)` — not `[]`, which would
// silently drop every subsequent `List.set` on that mut binding.
package namedret

import "github.com/consensys/gnark/frontend"

type NamedRet struct {
	Src [4]frontend.Variable
}

// makeArrs mirrors the Zolana KeySchedule shape (the case that surfaced
// the bug): two named-return fixed arrays populated by index writes in
// a loop before a bare `return`.
func makeArrs(src [4]frontend.Variable) (a [4]frontend.Variable, b [3]frontend.Variable) {
	for i := 0; i < 4; i++ {
		a[i] = src[i]
	}
	for i := 0; i < 3; i++ {
		b[i] = src[i]
	}
	return
}

func (c *NamedRet) Define(api frontend.API) error {
	a, b := makeArrs(c.Src)
	api.AssertIsEqual(a[0], c.Src[0])
	api.AssertIsEqual(b[0], c.Src[0])
	return nil
}
