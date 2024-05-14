package vergo

type Uint64 Vergo[uint64]

func Add(a, b Uint64) Uint64 {
	return Uint64(PrimOp1(func() uint64 { return a.Value + b.Value }, *a.Variable, *b.Variable))
}
