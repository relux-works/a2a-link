package sharedrelease

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

type fixtureTransport func(*http.Request) (*http.Response, error)

func (f fixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Public download binding accepts matching bytes and refuses a changed body, non-200 status, unsafe URL or malformed expected hash.
func TestPublicAssetDownloadBinding(t *testing.T) {
	for _, kind := range []string{"valid", "changed", "missing", "unsafe-url", "bad-digest"} {
		t.Run(kind, func(t *testing.T) {
			expected := Hash([]byte("published fixture"))
			source := "https://github.com/relux-works/a2a-swarm/releases/download/v0.1.2/asset"
			calls := 0
			if kind == "unsafe-url" {
				source = "http://github.com/asset"
			}
			if kind == "bad-digest" {
				expected = "bad"
			}
			client := &http.Client{Transport: fixtureTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != "GET" || r.Header.Get("Authorization") != "" {
					t.Fatal("not credential-free read")
				}
				body := []byte("published fixture")
				status := 200
				if kind == "changed" {
					body = append(body, 1)
				}
				if kind == "missing" {
					status = 404
				}
				return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}, nil
			})}
			_, e := downloadPublicAsset(context.Background(), client, source, expected)
			want := map[string]string{"changed": "public-asset-digest-mismatch", "missing": "public-asset-status", "unsafe-url": "public-asset-input-contract", "bad-digest": "public-asset-input-contract"}[kind]
			if kind == "valid" {
				if e != nil {
					t.Fatal(e)
				}
			} else if e == nil || e.Error() != want {
				t.Fatalf("want %s, got %v", want, e)
			}
			if (kind == "unsafe-url" || kind == "bad-digest") && calls != 0 {
				t.Fatal("invalid input reached network")
			}
		})
	}
}

// The immutable public Darwin archive is a real HTTP positive and wrong-digest negative; no published Linux fixture exists yet.
func TestRealPublicDownloadDigest(t *testing.T) {
	if os.Getenv("A2A_PUBLIC_DOWNLOAD_FIXTURE") == "" {
		t.Skip("hosted immutable public download control required")
	}
	source := "https://github.com/relux-works/a2a-swarm/releases/download/v0.1.1/a2a_0.1.1_darwin_arm64.tar.gz"
	client := &http.Client{CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if !publicAssetURL(r.URL) {
			return os.ErrPermission
		}
		return nil
	}}
	for _, sum := range []string{"bdbe48f46824cfb1c37b9f475099527e1b51df0988447b135b363d716185bfe7", strings.Repeat("0", 64)} {
		_, e := downloadPublicAsset(context.Background(), client, source, sum)
		if sum == strings.Repeat("0", 64) {
			if e == nil || e.Error() != "public-asset-digest-mismatch" {
				t.Fatal("wrong real digest survived", e)
			}
		} else if e != nil {
			t.Fatal(e)
		}
	}
}
