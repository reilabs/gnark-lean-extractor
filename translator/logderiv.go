package translator

import (
	"fmt"
	"go/ast"
	"go/types"
	"strings"
)

// logderivPeephole models logderivlookup.Table operations that appear as
// expressions — New and Lookup — over the `List F` representation of a table
// (see isLogderivTable). Insert is a mutation and is handled at statement
// level (see exprStmt). Returns (lean, monadic, handled).
//
//	logderivlookup.New(api)        → ([] : List F)
//	table.Lookup(i)                → Circuit.lookup table [i]
//	table.Lookup(idxs...)          → Circuit.lookup table idxs
func (b *funcBody) logderivPeephole(e *ast.CallExpr, fn *types.Func) (string, bool, bool) {
	switch logderivOp(fn) {
	case "New":
		return "([] : List F)", false, true
	case "Lookup":
		sel, ok := unparen(e.Fun).(*ast.SelectorExpr)
		if !ok {
			b.errf(e.Pos(), "logderivlookup.Lookup call has no receiver")
		}
		table := wrapParen(b.atom(sel.X, kind{base: baseF, depth: 1}))
		var idxs string
		if e.Ellipsis.IsValid() {
			// Spread: the single argument is the index list.
			idxs = wrapParen(b.atom(e.Args[0], kind{base: baseF, depth: 1}))
		} else {
			parts := make([]string, len(e.Args))
			for i, a := range e.Args {
				parts[i] = b.atom(a, kind{})
			}
			idxs = "[" + strings.Join(parts, ", ") + "]"
		}
		return fmt.Sprintf("Circuit.lookup %s %s", table, idxs), true, true
	}
	return "", false, false
}

// emitLogderivInsert translates `table.Insert(v)` as a value-semantic append
// to the `List F` modeling the table: `table := table.concat v`. The receiver
// must be a bound local (scanMut marks it `let mut`).
func (b *funcBody) emitLogderivInsert(call *ast.CallExpr) {
	sel, ok := unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		b.errf(call.Pos(), "logderivlookup.Insert call has no receiver")
	}
	id, ok := unparen(sel.X).(*ast.Ident)
	if !ok {
		b.errf(call.Pos(), "logderivlookup.Insert is only supported on a bound local table")
	}
	name, ok := b.names[b.info.Uses[id]]
	if !ok {
		b.errf(id.Pos(), "Insert on unknown table %s", id.Name)
	}
	val := b.atom(call.Args[0], kind{})
	b.push(reassign{name: name, rhs: fmt.Sprintf("%s.concat %s", name, val)})
}
