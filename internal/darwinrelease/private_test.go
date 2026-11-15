package darwinrelease

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Private preparation admits before reading signing fields, re-admits before readback, and has no publisher effect.
func TestPrivateProducerGateOrder(t *testing.T) {
	steps := []string{}
	dir := filepath.Join(t.TempDir(), "bundle")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	out, e := prepareBundle(func() error { steps = append(steps, "admit"); return nil }, func() (string, error) { steps = append(steps, "prepare"); return dir, nil }, func(string) error { steps = append(steps, "sign"); return nil }, func(string) error { steps = append(steps, "verify"); return nil })
	if e != nil || out != dir || !reflect.DeepEqual(steps, []string{"admit", "prepare", "sign", "admit", "verify"}) {
		t.Fatal(steps, out, e)
	}
}

// A refusal before preparation has no producer/signing effects; a later failure removes only this producer's output.
func TestPrivateProducerRefusals(t *testing.T) {
	for _, failure := range []string{"admit", "prepare", "sign", "readmit", "verify"} {
		t.Run(failure, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "bundle")
			prepared := false
			admissions := 0
			want := errors.New(failure)
			out, e := prepareBundle(func() error {
				admissions++
				if failure == "admit" || failure == "readmit" && admissions == 2 {
					return want
				}
				return nil
			}, func() (string, error) {
				prepared = true
				if failure == "prepare" {
					return "", want
				}
				if e := os.Mkdir(dir, 0700); e != nil {
					t.Fatal(e)
				}
				return dir, nil
			}, func(string) error {
				if failure == "sign" {
					return want
				}
				return nil
			}, func(string) error {
				if failure == "verify" {
					return want
				}
				return nil
			})
			if e != want || out != "" {
				t.Fatal(out, e)
			}
			if failure == "admit" && prepared {
				t.Fatal("prepared before admission")
			}
			if _, e := os.Stat(dir); !os.IsNotExist(e) {
				t.Fatal("failure exposed private bundle", e)
			}
		})
	}
}
