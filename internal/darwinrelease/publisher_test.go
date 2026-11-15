package darwinrelease

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// The real HTTP client publishes one verified draft only; exact digest/member, re-admission and ambiguity plants never trigger a retry or deletion.
func TestPublisherClosedTransition(t *testing.T) {
	for _, tc := range []struct{ name, want string }{{"valid", ""}, {"unverified", "candidate-refused"}, {"existing", "release-already-exists"}, {"changed-main", "publication-admission-changed"}, {"upload-digest", "uploaded-bytes-mismatch"}, {"extra-upload", "release-readback-members"}, {"missing-upload", "release-readback-members"}, {"premature", "premature-publication"}, {"readback-digest", "release-readback-digest"}, {"unknown-public", "publication-outcome-unknown; read-only reconciliation: public; no retry"}, {"unknown-draft", "publication-outcome-unknown; read-only reconciliation: draft; no retry"}, {"unknown-read", "publication-outcome-unknown; read-only reconciliation inconclusive"}, {"readback-draft", "publication-readback-still-draft"}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			data := []byte("verified fixture")
			if e := os.WriteFile(filepath.Join(dir, "asset"), data, 0600); e != nil {
				t.Fatal(e)
			}
			a := Admission{Tag: "v0.1.2", TagObject: strings.Repeat("b", 40), Commit: strings.Repeat("a", 40), Version: "0.1.2"}
			drafts, uploads, transitions, admissions := 0, 0, 0, 0
			public := false
			unexpected := false
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				response := func(v any) {
					if e := json.NewEncoder(w).Encode(v); e != nil {
						t.Error(e)
					}
				}
				if r.Method == "DELETE" || r.Method != "GET" && r.Method != "POST" && r.Method != "PATCH" {
					unexpected = true
					w.WriteHeader(500)
					return
				}
				switch {
				case strings.Contains(r.URL.Path, "/tags/"):
					if tc.name == "existing" {
						response(map[string]any{"id": 7})
						return
					}
					w.WriteHeader(404)
				case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/releases"):
					drafts++
					w.WriteHeader(201)
					response(map[string]any{"id": 7, "draft": true, "prerelease": false, "tag_name": a.Tag, "target_commitish": a.Commit})
				case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/assets"):
					uploads++
					raw, e := io.ReadAll(r.Body)
					if e != nil || string(raw) != string(data) {
						t.Error("wrong upload", e)
					}
					sha := digest(data)
					if tc.name == "upload-digest" {
						sha = strings.Repeat("0", 64)
					}
					w.WriteHeader(201)
					response(map[string]any{"id": 8, "name": "asset", "state": "uploaded", "size": len(data), "digest": "sha256:" + sha})
				case r.Method == "PATCH":
					transitions++
					if tc.name == "unknown-draft" {
						w.WriteHeader(503)
						return
					}
					public = true
					if strings.HasPrefix(tc.name, "unknown-") {
						w.WriteHeader(503)
						return
					}
					response(map[string]any{"id": 7, "draft": false, "tag_name": a.Tag})
				case strings.HasSuffix(r.URL.Path, "/assets"):
					sha := digest(data)
					if tc.name == "readback-digest" {
						sha = strings.Repeat("0", 64)
					}
					assets := []map[string]any{{"id": 8, "name": "asset", "state": "uploaded", "size": len(data), "digest": "sha256:" + sha}}
					if tc.name == "extra-upload" {
						assets = append(assets, map[string]any{"id": 9, "name": "extra"})
					}
					if tc.name == "missing-upload" {
						assets = nil
					}
					response(assets)
				default:
					if tc.name == "unknown-read" && transitions > 0 {
						w.WriteHeader(503)
						return
					}
					draft := !public
					if tc.name == "premature" {
						draft = false
					}
					if tc.name == "readback-draft" && transitions > 0 {
						draft = true
					}
					response(map[string]any{"id": 7, "draft": draft, "prerelease": false, "tag_name": a.Tag, "target_commitish": a.Commit})
				}
			}))
			defer s.Close()
			client := s.Client()
			baseTransport := client.Transport
			client.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Host == "uploads.github.com" {
					r.URL.Scheme = "http"
					r.URL.Host = strings.TrimPrefix(s.URL, "http://")
				}
				return baseTransport.RoundTrip(r)
			})
			g := &githubAPI{s.URL, "fixture", client}
			admit := func() (Admission, error) {
				admissions++
				b := a
				if tc.name == "changed-main" && admissions >= 3 {
					b.Commit = strings.Repeat("c", 40)
				}
				return b, nil
			}
			gate := func(context.Context, string) error {
				if tc.name == "unverified" {
					return fmt.Errorf("candidate-refused")
				}
				return nil
			}
			e := publishPrepared(context.Background(), g, admit, a.Tag, a.TagObject, dir, []string{"asset"}, "fixture", gate)
			if tc.want == "" {
				if e != nil || !public || transitions != 1 || drafts != 1 || uploads != 1 {
					t.Fatal(e, public, transitions, drafts, uploads)
				}
			} else if e == nil || e.Error() != tc.want {
				t.Fatalf("want %s, got %v", tc.want, e)
			}
			if drafts > 1 || uploads > 1 || transitions > 1 || unexpected {
				t.Fatal("repeated or forbidden mutation", drafts, uploads, transitions, unexpected)
			}
			if tc.name == "unverified" || tc.name == "existing" {
				if drafts != 0 || uploads != 0 || transitions != 0 {
					t.Fatal("premature effects")
				}
			}
			if tc.name == "upload-digest" || tc.name == "extra-upload" || tc.name == "missing-upload" || tc.name == "premature" || tc.name == "readback-digest" || tc.name == "changed-main" {
				if transitions != 0 {
					t.Fatal("transition after failed gate")
				}
			}
		})
	}
}

// Read-only reconciliation binds recorded release/source/asset identities and never sends a write, even for a surviving private draft.
func TestReadOnlyReconciliation(t *testing.T) {
	for _, draft := range []bool{true, false} {
		t.Run(fmt.Sprint(draft), func(t *testing.T) {
			calls := 0
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != "GET" {
					t.Error("recovery mutation", r.Method)
				}
				if strings.HasSuffix(r.URL.Path, "/assets") {
					json.NewEncoder(w).Encode([]releaseAsset{{ID: 8, Name: "asset", Digest: "sha256:" + digest([]byte("bytes")), State: "uploaded", Size: 5}})
				} else {
					json.NewEncoder(w).Encode(map[string]any{"id": 7, "tag_name": "v0.1.2", "target_commitish": "commit", "draft": draft, "prerelease": false})
				}
			}))
			defer s.Close()
			g := githubAPI{s.URL, "fixture", s.Client()}
			state, e := g.reconcile(context.Background(), 7, "v0.1.2", "commit", map[string]releaseFile{"asset": {[]byte("bytes"), digest([]byte("bytes"))}}, false)
			want := "public"
			if draft {
				want = "draft"
			}
			if e != nil || state != want || calls != 2 {
				t.Fatal(state, e, calls)
			}
		})
	}
}
