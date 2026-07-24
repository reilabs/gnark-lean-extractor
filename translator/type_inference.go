package translator

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"
)

// baseKind is the underlying scalar kind that lives at the leaf of a kind's
// depth stack. Exactly one of these applies to any kind, and the zero value
// (baseF, meaning F / frontend.Variable) makes `kind{}` a valid literal for
// the default case.
type baseKind int8

const (
	baseF      baseKind = iota // F — the field element (frontend.Variable)
	baseInt64                  // Int64 — Go integer, tracked bit-exactly
	baseBigInt                 // Int — Go math/big.Int (arbitrary-precision)
	baseBool                   // Bool — Go bool
	baseStruct                 // a Go named struct; kind.named is set
	baseOpaque                 // a Config.OpaqueTypes name; kind.opaque is set
)

// kind is the translator's type universe: a base (F / Int64 / Bool / named
// struct / opaque type) plus a list depth stacked on top.
type kind struct {
	base   baseKind
	depth  int          // 0 = base, 1 = List base, 2 = List (List base), ...
	named  *types.Named // set iff base == baseStruct
	opaque string       // set iff base == baseOpaque
}

func (b *funcBody) leanType(k kind) string {
	var s string
	switch k.base {
	case baseInt64:
		s = "Int64"
	case baseBigInt:
		s = "Int"
	case baseBool:
		s = "Bool"
	case baseOpaque:
		s = k.opaque
	case baseStruct:
		s = b.emit.structReg.name(k.named)
	default:
		s = "F"
	}
	for i := 0; i < k.depth; i++ {
		if strings.Contains(s, " ") {
			s = "List (" + s + ")"
		} else {
			s = "List " + s
		}
	}
	return s
}

// leanTypeParen renders the type parenthesized when needed as an argument of
// `Circuit`.
func (b *funcBody) leanTypeParen(k kind) string {
	s := b.leanType(k)
	if strings.Contains(s, " ") {
		return "(" + s + ")"
	}
	return s
}

func (k kind) elem() kind {
	return kind{base: k.base, depth: k.depth - 1, named: k.named, opaque: k.opaque}
}

func gnarkNamed(typ types.Type, name string) bool {
	named, ok := typ.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj.Name() == name && obj.Pkg() != nil &&
		obj.Pkg().Path() == "github.com/consensys/gnark/frontend"
}

func isVariable(typ types.Type) bool { return gnarkNamed(typ, "Variable") }
func isAPI(typ types.Type) bool      { return gnarkNamed(typ, "API") }

// isLogderivTable reports whether typ is (a pointer to) logderivlookup.Table.
func isLogderivTable(typ types.Type) bool {
	if p, ok := typ.(*types.Pointer); ok {
		typ = p.Elem()
	}
	named, ok := typ.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj != nil && obj.Pkg() != nil &&
		obj.Pkg().Path() == "github.com/consensys/gnark/std/lookup/logderivlookup" &&
		obj.Name() == "Table"
}

// logderivOp classifies a call to a logderivlookup.Table method/constructor,
// returning "New" | "Insert" | "Lookup" (or "" for anything else).
func logderivOp(fn *types.Func) string {
	if fn == nil || fn.Pkg() == nil ||
		fn.Pkg().Path() != "github.com/consensys/gnark/std/lookup/logderivlookup" {
		return ""
	}
	switch fn.Name() {
	case "New", "Insert", "Lookup":
		return fn.Name()
	}
	return ""
}

// isError reports whether typ is the builtin `error` interface.
func isError(typ types.Type) bool {
	named, ok := typ.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj.Name() == "error" && obj.Pkg() == nil
}

// isEmptyInterface reports whether typ is a bare, unnamed `interface{}` /
// `any`. Named interfaces (notably `frontend.Variable`, whose underlying is
// empty-interface) are excluded — the translator classifies Variable as F
// and shouldn't re-infer.
func isEmptyInterface(typ types.Type) bool {
	if _, ok := typ.(*types.Named); ok {
		return false
	}
	iface, ok := typ.Underlying().(*types.Interface)
	return ok && iface.NumMethods() == 0
}

// findReturnExprType walks a function body and returns the Go type of the
// first single-expression return it finds.
func findReturnExprType(body *ast.BlockStmt, info *types.Info) types.Type {
	var found types.Type
	ast.Inspect(body, func(n ast.Node) bool {
		if rs, ok := n.(*ast.ReturnStmt); ok && len(rs.Results) == 1 {
			found = info.TypeOf(rs.Results[0])
			return false
		}
		return true
	})
	return found
}

// Returns the result tuple of a signature with a trailing `error` removed,
// along with a flag recording whether one was stripped.
func stripTrailingError(results *types.Tuple) (*types.Tuple, bool) {
	n := results.Len()
	if n == 0 || !isError(results.At(n-1).Type()) {
		return results, false
	}
	kept := make([]*types.Var, n-1)
	for i := 0; i < n-1; i++ {
		kept[i] = results.At(i)
	}
	return types.NewTuple(kept...), true
}

func (b *funcBody) classify(typ types.Type, pos token.Pos) kind {
	if isVariable(typ) {
		return kind{}
	}
	// `math/big.Int` is arbitrary-precision integer. We model it as Lean's Int
	if named, ok := typ.(*types.Named); ok {
		obj := named.Obj()
		if obj != nil && obj.Pkg() != nil &&
			obj.Pkg().Path() == "math/big" && obj.Name() == "Int" {
			return kind{base: baseBigInt}
		}
	}
	// logderivlookup.Table is modeled as a plain `List F` (its entries).
	if isLogderivTable(typ) {
		return kind{base: baseF, depth: 1}
	}
	// Pointer types are erased: gnark helpers use `*Struct` to pass value
	// records by reference, but the translation is value-semantic, so
	// `*T` classifies as `T`.
	if p, ok := typ.(*types.Pointer); ok {
		return b.classify(p.Elem(), pos)
	}
	// Config-declared opaque types: generic instantiations or foreign
	// structs the caller has explicitly declined to model. Emit an
	// `axiom X : Type` and return an opaque kind.
	if leanName, ok := b.opaqueLeanName(typ); ok {
		b.emit.opaqueReg.register(leanName)
		return kind{base: baseOpaque, opaque: leanName}
	}
	// Non-opaque aliases: recurse into the target so downstream sees the
	// structural type.
	if alias, ok := typ.(*types.Alias); ok {
		return b.classify(types.Unalias(alias), pos)
	}
	if named, ok := typ.(*types.Named); ok {
		if st, ok := named.Underlying().(*types.Struct); ok {
			b.registerStruct(named, st, pos)
			return kind{base: baseStruct, named: named}
		}
	}
	switch u := typ.Underlying().(type) {
	case *types.Basic:
		// byte / uint8 model field-shaped raw bytes (see []byte folding
		// in translate.go): they classify as F, not Int64, so byte
		// slices flow through the F pipeline.
		if u.Kind() == types.Uint8 {
			return kind{}
		}
		if u.Kind() == types.Bool {
			return kind{base: baseBool}
		}
		if u.Info()&types.IsInteger != 0 {
			return kind{base: baseInt64}
		}
	case *types.Slice:
		e := b.classify(u.Elem(), pos)
		// Slices of Go bool have no value model; slices of everything else
		// (F, Int64 index tables like AES's byteOrder, structs, opaques) do.
		if e.base != baseBool {
			return kind{base: e.base, depth: e.depth + 1, named: e.named, opaque: e.opaque}
		}
	case *types.Array:
		e := b.classify(u.Elem(), pos)
		if e.base != baseBool {
			return kind{base: e.base, depth: e.depth + 1, named: e.named, opaque: e.opaque}
		}
	}
	b.errf(pos, "unsupported type %s (expected frontend.Variable, integers, structs, or slices/arrays thereof)", typ)
	return kind{}
}

// opaqueLeanName returns the Lean name configured for typ's fully-qualified
// Go name, or false if none is set. Named types and (Go 1.22+) aliases are
// both recognized; aliases match by their alias name rather than the
// aliased target.
func (b *funcBody) opaqueLeanName(typ types.Type) (string, bool) {
	if len(b.cfg.OpaqueTypes) == 0 {
		return "", false
	}
	var obj *types.TypeName
	switch tt := typ.(type) {
	case *types.Named:
		obj = tt.Obj()
	case *types.Alias:
		obj = tt.Obj()
	}
	if obj == nil || obj.Pkg() == nil {
		return "", false
	}
	fqn := obj.Pkg().Path() + "." + obj.Name()
	name, ok := b.cfg.OpaqueTypes[fqn]
	return name, ok
}

// registerStruct emits a Lean `structure` declaration for a Go named struct
// (once per type). Called from classify on first sighting. Field types are
// classified recursively via the structRegistry, which reserves the outer
// struct's name BEFORE running this build callback so inner structs get
// emitted first (topological order) while outer references resolve.
func (b *funcBody) registerStruct(named *types.Named, st *types.Struct, pos token.Pos) {
	b.emit.structReg.getOrRegister(named, func(name string) string {
		var fieldLines []string
		for i := 0; i < st.NumFields(); i++ {
			fld := st.Field(i)
			if fld.Embedded() {
				b.errf(pos, "embedded fields are not supported (in struct %s)", named.Obj().Name())
			}
			// frontend.API fields are ambient (the gates), not values —
			// gadgets that stash the API in their state drop that field; the
			// gate path reaches it through the receiver instead.
			if isAPI(fld.Type()) {
				continue
			}
			k := b.classify(fld.Type(), fld.Pos())
			fieldLines = append(fieldLines, fmt.Sprintf("  %s : %s", sanitize(fld.Name()), b.leanType(k)))
		}
		return fmt.Sprintf("structure %s where\n%s\n  deriving Inhabited", name, strings.Join(fieldLines, "\n"))
	})
}
