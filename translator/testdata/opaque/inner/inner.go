// Package inner supplies a generic type that the outer circuit instantiates
// through an alias — the shape of zolana's `P256PublicKey = PublicKey[…, …]`
// that motivated the OpaqueTypes config knob.
package inner

// Wrap is a generic container: the translator can't classify its
// instantiation structurally without generics support, so callers pin the
// alias to a Lean opaque type via Config.OpaqueTypes.
type Wrap[X any, Y any] struct {
	A X
	B Y
}
