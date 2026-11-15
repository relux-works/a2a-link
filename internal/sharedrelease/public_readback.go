package sharedrelease

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/relux-works/a2a-swarm/internal/cask"
)

// PublicReadback repeats authenticated candidate verification and downloads the
// exact public member set. It sends no credentials and performs no write to
// GitHub or the tap. A URL, status or byte mismatch is never a successful readback.
func PublicReadback(ctx context.Context, b Binding, dir string) error {
	if e := VerifyCandidate(ctx, b, dir, nil); e != nil {
		return e
	}
	client := &http.Client{Timeout: 2 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 4 || !publicAssetURL(req.URL) {
			return errors.New("public-asset-redirect-refused")
		}
		return nil
	}}
	captured, e := os.MkdirTemp("", "a2a-public-readback-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(captured)
	for _, n := range FinalMembers(b.Version()) {
		expected, e := readRegular(dir, n)
		if e != nil {
			return e
		}
		raw, e := downloadPublicAsset(ctx, client, cask.ReleaseBase+b.Tag+"/"+n, Hash(expected))
		if e != nil {
			return e
		}
		if e = os.WriteFile(filepath.Join(captured, n), raw, 0600); e != nil {
			return e
		}
	}
	return VerifyCandidate(ctx, b, captured, nil)
}
func publicAssetURL(u *url.URL) bool {
	return u != nil && u.Scheme == "https" && u.User == nil && u.Port() == "" && u.Fragment == "" && (u.Host == "github.com" || u.Host == "release-assets.githubusercontent.com")
}
func downloadPublicAsset(ctx context.Context, client *http.Client, source, expected string) ([]byte, error) {
	u, e := url.Parse(source)
	if e != nil || !publicAssetURL(u) || !digestForm.MatchString(expected) {
		return nil, errors.New("public-asset-input-contract")
	}
	req, e := http.NewRequestWithContext(ctx, "GET", source, nil)
	if e != nil {
		return nil, errors.New("public-asset-request")
	}
	response, e := client.Do(req)
	if e != nil {
		return nil, errors.New("public-asset-read")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("public-asset-status")
	}
	if response.ContentLength > 128<<20 {
		return nil, errors.New("public-asset-size")
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, 128<<20+1))
	if e != nil || len(raw) > 128<<20 {
		return nil, errors.New("public-asset-read")
	}
	if Hash(raw) != expected {
		return nil, errors.New("public-asset-digest-mismatch")
	}
	return raw, nil
}
