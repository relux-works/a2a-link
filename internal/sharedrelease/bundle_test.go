package sharedrelease

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/a2a-swarm/internal/darwinrelease"
)

func bundleFixture(t *testing.T, b Binding, mutate func(map[string][]byte)) []byte {
	t.Helper()
	files := map[string][]byte{}
	for _, n := range DarwinMembers(b.Version()) {
		files[n] = []byte("fixture")
	}
	ev := darwinrelease.Evidence{Admission: darwinrelease.Admission{Tag: b.Tag, Commit: b.Commit, TagObject: b.TagObject, Version: b.Version()}}
	raw, e := json.Marshal(ev)
	if e != nil {
		t.Fatal(e)
	}
	files["release-evidence.json"] = raw
	if mutate != nil {
		mutate(files)
	}
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	for n, x := range files {
		w, e := z.Create(n)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = w.Write(x); e != nil {
			t.Fatal(e)
		}
	}
	if e = z.Close(); e != nil {
		t.Fatal(e)
	}
	return buf.Bytes()
}

// Captured bytes require the producer's exact ID/digest/run/workflow/source/tag object and closed members; failures expose no output.
func TestPrivateArtifactCaptureBindings(t *testing.T) {
	b := Binding{"v0.1.2", strings.Repeat("a", 40), strings.Repeat("b", 40)}
	for _, tc := range []struct{ name, want string }{{"valid", ""}, {"wrong-id", "artifact-producer-binding"}, {"wrong-digest", "artifact-producer-binding"}, {"wrong-source", "artifact-producer-binding"}, {"wrong-tag", "artifact-producer-binding"}, {"wrong-object", "artifact-producer-binding"}, {"wrong-workflow", "artifact-producer-binding"}, {"changed-zip", "artifact-zip-digest"}, {"extra-member", "artifact-zip-members"}, {"missing-member", "artifact-zip-members"}, {"evidence-object", "artifact-evidence-binding"}} {
		t.Run(tc.name, func(t *testing.T) {
			raw := bundleFixture(t, b, func(files map[string][]byte) {
				switch tc.name {
				case "extra-member":
					files["private.key"] = []byte("not-a-secret")
				case "missing-member":
					delete(files, "checksums.txt")
				case "evidence-object":
					files["release-evidence.json"] = []byte(`{}`)
				}
			})
			dir := t.TempDir()
			path := filepath.Join(dir, "input.zip")
			if e := os.WriteFile(path, raw, 0600); e != nil {
				t.Fatal(e)
			}
			ref := ArtifactReference{1, 2, Hash(raw), "darwin"}
			out := filepath.Join(dir, "out")
			observer := func(context.Context, int64, int64, string) (darwinrelease.ArtifactObservation, error) {
				a := darwinrelease.ArtifactObservation{ID: 1, RunID: 2, JobID: 3, Name: "a2a-darwin-" + b.TagObject, Digest: "sha256:" + ref.SHA256, Commit: b.Commit, Branch: b.Tag, Workflow: Workflow, JobName: "darwin-producer / prepare"}
				switch tc.name {
				case "wrong-id":
					a.ID++
				case "wrong-digest":
					a.Digest = "sha256:" + strings.Repeat("0", 64)
				case "wrong-source":
					a.Commit = strings.Repeat("0", 40)
				case "wrong-tag":
					a.Branch = "v0.1.3"
				case "wrong-object":
					a.Name = "a2a-darwin-" + strings.Repeat("c", 40)
				case "wrong-workflow":
					a.Workflow = "other.yml"
				case "changed-zip":
					if e := os.WriteFile(path, append(raw, 1), 0600); e != nil {
						t.Fatal(e)
					}
				}
				return a, nil
			}
			e := captureBundle(context.Background(), path, out, b, ref, observer)
			if tc.want == "" {
				if e != nil {
					t.Fatal(e)
				}
				for _, n := range DarwinMembers(b.Version()) {
					if _, e := os.Stat(filepath.Join(out, n)); e != nil {
						t.Fatal(e)
					}
				}
			} else {
				if e == nil || e.Error() != tc.want {
					t.Fatalf("want %s, got %v", tc.want, e)
				}
				if _, e := os.Stat(out); !os.IsNotExist(e) {
					t.Fatal("partial output", e)
				}
			}
		})
	}
}

// A ZIP entry cannot disguise traversal, a duplicate, a symlink, or an empty input as an approved flat file.
func TestArtifactZIPClosedEntries(t *testing.T) {
	for _, kind := range []string{"valid", "traversal", "duplicate", "symlink", "empty"} {
		t.Run(kind, func(t *testing.T) {
			var buf bytes.Buffer
			z := zip.NewWriter(&buf)
			h := &zip.FileHeader{Name: "a2a", Method: zip.Store}
			h.SetMode(0600)
			if kind == "traversal" {
				h.Name = "../a2a"
			}
			if kind == "symlink" {
				h.SetMode(os.ModeSymlink | 0777)
			}
			w, e := z.CreateHeader(h)
			if e != nil {
				t.Fatal(e)
			}
			if kind != "empty" {
				if _, e = w.Write([]byte("bin")); e != nil {
					t.Fatal(e)
				}
			}
			if kind == "duplicate" {
				if _, e = z.Create("a2a"); e != nil {
					t.Fatal(e)
				}
			}
			if e = z.Close(); e != nil {
				t.Fatal(e)
			}
			_, e = closedZIP(buf.Bytes(), []string{"a2a"})
			if kind == "valid" {
				if e != nil {
					t.Fatal(e)
				}
			} else if e == nil {
				t.Fatal("unsafe ZIP accepted")
			}
		})
	}
}
