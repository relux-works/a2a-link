package main

import (
	"os"
	"path/filepath"
	"testing"
)

// A fresh output is written durably; retries preserve its bytes. Symlinked
// output parents refuse before creating an alias-target file. This tests local
// file behavior, not power-loss simulation or remote filesystem guarantees.
func TestOutputCreation(t *testing.T) {
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(root, "output.jsonl")
	f, e := openOutput(path)
	if e != nil {
		t.Fatal(e)
	}
	if n, e := (durableOutput{f}).Write([]byte("evidence\n")); e != nil || n != 9 {
		t.Fatal("durable write", e)
	}
	f.Close()
	if f, e := openOutput(path); e == nil {
		f.Close()
		t.Fatal("existing output replaced")
	}
	raw, e := os.ReadFile(path)
	if e != nil || string(raw) != "evidence\n" {
		t.Fatal("existing output modified")
	}
	alias := filepath.Join(root, "alias")
	if e := os.Symlink(root, alias); e != nil {
		t.Fatal(e)
	}
	if f, e := openOutput(filepath.Join(alias, "escaped")); e == nil {
		f.Close()
		t.Fatal("symlink parent accepted")
	}
	if _, e := os.Stat(filepath.Join(root, "escaped")); !os.IsNotExist(e) {
		t.Fatal("symlink refusal created output")
	}
}
