// Run from the source root: go run .scripts/al3-verify.go -a ... -b ...
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/relux-works/a2a-swarm/internal/al3smoke"
	"io"
	"os"
)

func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "al3: transcript refused")
		os.Exit(1)
	}
}
func run() error {
	var a, b, ak, bk, url, id string
	flag.StringVar(&a, "a", "", "role A JSONL")
	flag.StringVar(&b, "b", "", "role B JSONL")
	flag.StringVar(&ak, "a-key", "", "A public key")
	flag.StringVar(&bk, "b-key", "", "B public key")
	flag.StringVar(&url, "relay", "", "supplied relay")
	flag.StringVar(&id, "run-id", "", "shared run ID")
	flag.Parse()
	if flag.NArg() != 0 {
		return al3smoke.ErrSmoke
	}
	read := func(path string) ([]al3smoke.Evidence, error) {
		f, e := os.Open(path)
		if e != nil {
			return nil, e
		}
		defer f.Close()
		st, e := f.Stat()
		if e != nil || !st.Mode().IsRegular() || st.Size() > 65536 {
			return nil, al3smoke.ErrSmoke
		}
		d := json.NewDecoder(io.LimitReader(f, 65537))
		d.DisallowUnknownFields()
		var rows []al3smoke.Evidence
		for {
			var r al3smoke.Evidence
			e := d.Decode(&r)
			if e == io.EOF {
				return rows, nil
			}
			if e != nil || len(rows) >= 4 {
				return nil, al3smoke.ErrSmoke
			}
			rows = append(rows, r)
		}
	}
	ar, e := read(a)
	if e != nil {
		return e
	}
	br, e := read(b)
	if e != nil {
		return e
	}
	result, e := al3smoke.Normalize(ar, br, ak, bk, url, id)
	if e != nil {
		return e
	}
	_, e = fmt.Println(string(result))
	return e
}
