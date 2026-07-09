package translator

import (
	"fmt"
	"strings"
)

// stmt is a single Lean do-block statement. Concrete kinds below cover every
// shape the walker produces; nothing else emits raw strings any more. The
// walker builds a []stmt tree, and renderBlock textualizes it in one pass.
// Decisions the old codebase made mid-walk with a `last lastStmt` cursor
// (append `pure ()` at block end when trailing a binding, indent bodies)
// are made structurally at render time from the tree.
type stmt interface{ isStmt() }

func (letBind) isStmt()     {}
func (discardBind) isStmt() {}
func (reassign) isStmt()    {}
func (indexSet) isStmt()    {}
func (fieldSet) isStmt()    {}
func (tupleLet) isStmt()    {}
func (tupleAssign) isStmt() {}
func (copyFull) isStmt()    {}
func (copySlice) isStmt()   {}
func (bareExpr) isStmt()    {}
func (forLoop) isStmt()     {}
func (forSlice) isStmt()    {}
func (forIndexed) isStmt()  {}
func (ifStmt) isStmt()      {}
func (ret) isStmt()         {}

// letBind — `let [mut] <name>[<ascr>] := rhs`  or  `let ... ← rhs`.
type letBind struct {
	name    string
	ascr    string // e.g. " : Int64", "" otherwise
	rhs     string
	monadic bool
	mut     bool
}

// discardBind — `let _ ← rhs` or `let _ := rhs`.
type discardBind struct {
	rhs     string
	monadic bool
}

// reassign — write to a previously bound `let mut` name.
type reassign struct {
	name    string
	rhs     string
	monadic bool
}

// indexSet — `<name> := <name>.set <idx> <val>` for slice element writes.
type indexSet struct{ name, idx, val string }

// fieldSet — `<name> := { <name> with <field> := <val> }` for struct fields.
type fieldSet struct{ name, field, val string }

// tupleLet — `let (<names…>) ← rhs` for fresh binding of a Circuit tuple.
type tupleLet struct {
	names []string
	rhs   string
}

// tupleAssign — Lean has no `(x,y) ← m` reassignment syntax. Bind the tuple
// to a fresh tmp, then split into per-position writes. The `parts` describe
// each target's shape (reassign, fresh let, or index-set).
type tupleAssign struct {
	tmp   string
	rhs   string
	parts []tuplePart
}

type tuplePartKind int

const (
	tuplePartLet    tuplePartKind = iota // let <name> := tmp.<i>
	tuplePartAssign                      // <name> := tmp.<i>
	tuplePartIndex                       // <name> := <name>.set <idx> (tmp.<i>)
)

type tuplePart struct {
	kind    tuplePartKind
	name    string
	tupleIx int    // 1-based
	idxExpr string // for tuplePartIndex only
}

// copyFull — Go's `copy(xs, src)` under value semantics rebinds xs to hold
// the appropriate prefix of src.
type copyFull struct{ name, src string }

// copySlice — Go's `copy(xs[lo:hi], src)` splices src into the range.
type copySlice struct{ name, lo, hi, src string }

// bareExpr — a statement-level Unit-typed monadic call (`Gates.eq a b`),
// or a trailing monadic return expression.
type bareExpr struct{ rhs string }

// forLoop — `for <name> in goRange <lo> <hi> do <body>`.
// If step is non-empty, uses `goRangeStep <lo> <hi> <step>` instead.
type forLoop struct {
	name, lo, hi, step string
	body               block
}

// forSlice — `for <val> in <xs> do <body>` (range with only the value).
type forSlice struct {
	val, xs string
	body    block
}

// forIndexed — index-first range. If val is non-empty the body is prefixed
// with `let <val> := <xs>[<idx>.toInt.toNat]!` so the value name is in scope.
type forIndexed struct {
	idx, val, xs string
	body         block
}

// ifStmt — `if <cond> then <then>` with optional `else <els>`.
type ifStmt struct {
	cond string
	then block
	els  *block
}

// ret — return statement. `unit` renders as `pure ()`. Otherwise, `monadic`
// picks between a trailing expression (do-block trailing form) and an
// explicit `return <val>`.
type ret struct {
	val     string
	monadic bool
	unit    bool
}

// block is a do-block body. allowReassignEnd controls whether a trailing
// reassignment / index-set / field-set / copy needs a `pure ()` terminator
// (function bodies say no; loop/if bodies say yes).
type block struct {
	stmts            []stmt
	allowReassignEnd bool
}

// needsTerminator reports whether renderBlock must append `pure ()` after
// the last statement. A do-block ending in a `let` (or discard-let) has no
// trailing expression; a `reassign` / `indexSet` / `fieldSet` / `copyFull` /
// `copySlice` / `tupleAssign` is only a valid tail when the enclosing
// context accepts it (loop/if body: yes; function body: no). Loops, ifs,
// bare expressions, and returns are always valid tails.
func (b block) needsTerminator() bool {
	if len(b.stmts) == 0 {
		return true
	}
	switch b.stmts[len(b.stmts)-1].(type) {
	case letBind, discardBind, tupleLet:
		return true
	case reassign, indexSet, fieldSet, copyFull, copySlice, tupleAssign:
		return !b.allowReassignEnd
	}
	return false
}

// renderBlock textualizes a block at the given indent (in units of two
// spaces), returning one line per element (including any terminator). The
// caller joins with "\n".
func renderBlock(b block, indent int) []string {
	pad := indentAt(indent)
	out := make([]string, 0, len(b.stmts)+1)
	for _, s := range b.stmts {
		out = append(out, renderStmt(s, indent)...)
	}
	if b.needsTerminator() {
		out = append(out, pad+"pure ()")
	}
	return out
}

func renderStmt(s stmt, indent int) []string {
	pad := indentAt(indent)
	switch s := s.(type) {
	case letBind:
		arrow := ":="
		if s.monadic {
			arrow = "←"
		}
		m := ""
		if s.mut {
			m = "mut "
		}
		return []string{fmt.Sprintf("%slet %s%s%s %s %s", pad, m, s.name, s.ascr, arrow, s.rhs)}
	case discardBind:
		arrow := ":="
		if s.monadic {
			arrow = "←"
		}
		return []string{fmt.Sprintf("%slet _ %s %s", pad, arrow, s.rhs)}
	case reassign:
		arrow := ":="
		if s.monadic {
			arrow = "←"
		}
		return []string{fmt.Sprintf("%s%s %s %s", pad, s.name, arrow, s.rhs)}
	case indexSet:
		return []string{fmt.Sprintf("%s%s := %s.set %s %s", pad, s.name, s.name, s.idx, s.val)}
	case fieldSet:
		return []string{fmt.Sprintf("%s%s := { %s with %s := %s }", pad, s.name, s.name, s.field, s.val)}
	case tupleLet:
		return []string{fmt.Sprintf("%slet (%s) ← %s", pad, strings.Join(s.names, ", "), s.rhs)}
	case tupleAssign:
		lines := []string{fmt.Sprintf("%slet %s ← %s", pad, s.tmp, s.rhs)}
		for _, p := range s.parts {
			switch p.kind {
			case tuplePartLet:
				lines = append(lines, fmt.Sprintf("%slet %s := %s.%d", pad, p.name, s.tmp, p.tupleIx))
			case tuplePartAssign:
				lines = append(lines, fmt.Sprintf("%s%s := %s.%d", pad, p.name, s.tmp, p.tupleIx))
			case tuplePartIndex:
				lines = append(lines, fmt.Sprintf("%s%s := %s.set %s (%s.%d)",
					pad, p.name, p.name, p.idxExpr, s.tmp, p.tupleIx))
			}
		}
		return lines
	case copyFull:
		return []string{fmt.Sprintf("%s%s := %s.take %s.length", pad, s.name, s.src, s.name)}
	case copySlice:
		return []string{fmt.Sprintf("%s%s := %s.take %s ++ %s.take (%s - %s) ++ %s.drop %s",
			pad, s.name, s.name, s.lo, s.src, s.hi, s.lo, s.name, s.hi)}
	case bareExpr:
		return []string{pad + s.rhs}
	case forLoop:
		header := fmt.Sprintf("%sfor %s in goRange %s %s do", pad, s.name, s.lo, s.hi)
		if s.step != "" {
			header = fmt.Sprintf("%sfor %s in goRangeStep %s %s %s do", pad, s.name, s.lo, s.hi, s.step)
		}
		lines := []string{header}
		return append(lines, renderBlock(s.body, indent+1)...)
	case forSlice:
		lines := []string{fmt.Sprintf("%sfor %s in %s do", pad, s.val, s.xs)}
		return append(lines, renderBlock(s.body, indent+1)...)
	case forIndexed:
		lines := []string{fmt.Sprintf("%sfor %s in goRange 0 (Int64.ofNat %s.length) do", pad, s.idx, s.xs)}
		body := s.body
		if s.val != "" {
			// The value binding lives at the top of the body so the loop's
			// variable is in scope for the rest of the block.
			body = block{
				stmts: append([]stmt{letBind{
					name: s.val,
					rhs:  fmt.Sprintf("%s[%s.toInt.toNat]!", s.xs, s.idx),
				}}, s.body.stmts...),
				allowReassignEnd: s.body.allowReassignEnd,
			}
		}
		return append(lines, renderBlock(body, indent+1)...)
	case ifStmt:
		lines := []string{fmt.Sprintf("%sif %s then", pad, s.cond)}
		lines = append(lines, renderBlock(s.then, indent+1)...)
		if s.els != nil {
			lines = append(lines, pad+"else")
			lines = append(lines, renderBlock(*s.els, indent+1)...)
		}
		return lines
	case ret:
		if s.unit {
			return []string{pad + "pure ()"}
		}
		if s.monadic {
			return []string{pad + s.val}
		}
		return []string{pad + "return " + s.val}
	}
	panic(fmt.Sprintf("renderStmt: unknown stmt %T", s))
}

func indentAt(n int) string { return strings.Repeat("  ", n) }
