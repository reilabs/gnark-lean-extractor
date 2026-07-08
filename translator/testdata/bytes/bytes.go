// Package bytes exercises `[]byte("literal")` folding: the translator emits a
// `List F` with one field per source byte.
package bytes

import "github.com/consensys/gnark/frontend"

type Bytes struct {
	Sum frontend.Variable
}

func addBytes(api frontend.API, bs []frontend.Variable) frontend.Variable {
	acc := frontend.Variable(0)
	for _, b := range bs {
		acc = api.Add(acc, b)
	}
	return acc
}

func (c *Bytes) Define(api frontend.API) error {
	dom := []byte("abc")
	vars := make([]frontend.Variable, len(dom))
	for i, b := range dom {
		vars[i] = frontend.Variable(b)
	}
	api.AssertIsEqual(addBytes(api, vars), c.Sum)
	return nil
}
