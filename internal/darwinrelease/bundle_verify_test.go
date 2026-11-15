package darwinrelease

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Native assembly authenticates and re-verifies the immutable public bundle without signing material or payload execution.
func TestPreparedDarwinBundleNative(t *testing.T) {
	dir := os.Getenv("A2A_NATIVE_PREPARED_FIXTURE")
	if dir == "" {
		t.Skip("immutable hosted Darwin fixture required")
	}
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Fatal("native fixture requires Darwin arm64")
	}
	root, e := filepath.Abs("../..")
	if e != nil {
		t.Fatal(e)
	}
	if e = VerifyPreparedBundle(context.Background(), root, "v0.1.1", "3c3c3d1c8c6fd8386fa4a740dbdb6f99a92bb8d1", "ccb3786d57d59cf1b7980808c80013b4c10fc7c5", dir); e != nil {
		t.Fatal(e)
	}
}

// Closed native input extraction accepts a regular 0755 executable and refuses installer-mode, link, traversal, duplicate and membership plants.
func TestDarwinInputTarEntries(t *testing.T) {
	for _, kind := range []string{"valid", "setuid", "setgid", "sticky", "nonexec", "symlink", "traversal", "duplicate", "extra", "missing"} {
		t.Run(kind, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "payload.tar.gz")
			f, e := os.Create(p)
			if e != nil {
				t.Fatal(e)
			}
			gz := gzip.NewWriter(f)
			tw := tar.NewWriter(gz)
			h := &tar.Header{Name: "a2a", Mode: 0755, Size: 3, Typeflag: tar.TypeReg}
			switch kind {
			case "setuid":
				h.Mode = 04755
			case "setgid":
				h.Mode = 02755
			case "sticky":
				h.Mode = 01755
			case "nonexec":
				h.Mode = 0644
			case "symlink":
				h.Typeflag = tar.TypeSymlink
				h.Size = 0
				h.Linkname = "other"
			case "traversal":
				h.Name = "../a2a"
			}
			if kind != "missing" {
				if e = tw.WriteHeader(h); e != nil {
					t.Fatal(e)
				}
				if h.Size > 0 {
					if _, e = tw.Write([]byte("bin")); e != nil {
						t.Fatal(e)
					}
				}
			}
			if kind == "duplicate" || kind == "extra" {
				n := "a2a"
				if kind == "extra" {
					n = "extra"
				}
				if e = tw.WriteHeader(&tar.Header{Name: n, Mode: 0755, Typeflag: tar.TypeReg, Size: 3}); e != nil {
					t.Fatal(e)
				}
				if _, e = tw.Write([]byte("bin")); e != nil {
					t.Fatal(e)
				}
			}
			if e = tw.Close(); e != nil {
				t.Fatal(e)
			}
			if e = gz.Close(); e != nil {
				t.Fatal(e)
			}
			if e = f.Close(); e != nil {
				t.Fatal(e)
			}
			_, e = extractBoundTar(p, map[string]int64{"a2a": 0755})
			if kind == "valid" {
				if e != nil {
					t.Fatal(e)
				}
			} else if e == nil {
				t.Fatal("unsafe input accepted")
			}
		})
	}
}
