package darwinrelease

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// Real transport handling preserves metadata/ZIP digests and strips credentials
// on the blob request; each intended refusal leaves no output.
func TestArtifactDownloadConsumer(t *testing.T) {
	for _, kind := range []string{"valid", "metadata", "expired", "unknown-expiry", "redirect", "blob-auth", "digest", "missing"} {
		t.Run(kind, func(t *testing.T) {
			raw := []byte("ZIP transport fixture")
			sha := digest(raw)
			blobCalls := 0
			client := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
				status := 200
				body := raw
				h := http.Header{}
				if r.URL.Host == "api.github.com" {
					if r.Header.Get("Authorization") != "Bearer fixture" {
						t.Fatal("missing API auth")
					}
					if filepath.Base(r.URL.Path) == "zip" {
						status = 302
						target := "https://fixture.blob.core.windows.net/archive"
						if kind == "redirect" {
							target = "https://example.invalid/archive"
						}
						h.Set("Location", target)
						body = nil
					} else {
						m := map[string]any{"id": 7, "digest": "sha256:" + sha, "expired": false}
						if kind == "metadata" {
							m["digest"] = "sha256:" + digest([]byte("other"))
						}
						if kind == "expired" {
							m["expired"] = true
						}
						if kind == "unknown-expiry" {
							delete(m, "expired")
						}
						body, _ = json.Marshal(m)
					}
				} else {
					blobCalls++
					if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
						t.Fatal("credential leaked to blob")
					}
					if kind == "digest" {
						body = []byte("changed")
					}
					if kind == "missing" {
						status = 404
					}
				}
				return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(bytes.NewReader(body))}, nil
			})}
			g := &githubAPI{"https://api.github.com", "fixture", client}
			out := filepath.Join(t.TempDir(), "input.zip")
			e := g.downloadArtifactZIP(context.Background(), 7, sha, out)
			want := map[string]string{"metadata": "artifact-download-metadata", "expired": "artifact-download-metadata", "unknown-expiry": "artifact-download-metadata", "redirect": "artifact-download-redirect", "digest": "artifact-download-digest", "missing": "artifact-download-status"}[kind]
			if kind == "valid" || kind == "blob-auth" {
				if e != nil || blobCalls != 1 {
					t.Fatal(e, blobCalls)
				}
			} else {
				if e == nil || e.Error() != want {
					t.Fatalf("want %s, got %v", want, e)
				}
				if _, e = os.Stat(out); !os.IsNotExist(e) {
					t.Fatal("partial output")
				}
			}
		})
	}
}

// The hosted consumer verifies a real service ZIP by immutable upload outputs;
// this fetch is read-only and has no release or installation authority.
func TestRealArtifactDownload(t *testing.T) {
	text := os.Getenv("A2A_DOWNLOAD_ARTIFACT_ID")
	if text == "" {
		t.Skip("hosted immutable artifact ID/digest required")
	}
	id, e := strconv.ParseInt(text, 10, 64)
	if e != nil {
		t.Fatal(e)
	}
	out := filepath.Join(t.TempDir(), "input.zip")
	if e = DownloadArtifactZIP(context.Background(), id, os.Getenv("A2A_DOWNLOAD_ARTIFACT_SHA256"), out); e != nil {
		t.Fatal(e)
	}
}
