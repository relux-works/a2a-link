package darwinrelease

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var sha256Text = regexp.MustCompile(`^[0-9a-f]{64}$`)

// DownloadArtifactZIP reads the immutable artifact API response and verifies
// the complete downloaded ZIP digest. Redirect credentials never leave the API.
func DownloadArtifactZIP(ctx context.Context, id int64, sha, out string) error {
	return newGitHub(os.Getenv("GITHUB_TOKEN")).downloadArtifactZIP(ctx, id, sha, out)
}
func (g *githubAPI) downloadArtifactZIP(ctx context.Context, id int64, sha, out string) error {
	if id <= 0 || !sha256Text.MatchString(sha) || out == "" {
		return errors.New("artifact-download-input")
	}
	if _, e := os.Lstat(out); !os.IsNotExist(e) {
		return errors.New("artifact-download-output-exists")
	}
	var meta struct {
		ID      int64
		Digest  string
		Expired *bool
	}
	prefix := fmt.Sprintf("/repos/relux-works/a2a-swarm/actions/artifacts/%d", id)
	if e := g.get(ctx, prefix, &meta); e != nil {
		return e
	}
	if meta.ID != id || meta.Expired == nil || *meta.Expired || meta.Digest != "sha256:"+sha {
		return errors.New("artifact-download-metadata")
	}
	client := *g.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, e := http.NewRequestWithContext(ctx, "GET", g.base+prefix+"/zip", nil)
	if e != nil {
		return errors.New("artifact-download-request")
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	response, e := client.Do(req)
	if e != nil {
		return errors.New("artifact-download-api")
	}
	if response.StatusCode == 302 {
		location, e := url.Parse(response.Header.Get("Location"))
		response.Body.Close()
		if e != nil || !artifactBlobURL(location) {
			return errors.New("artifact-download-redirect")
		}
		// Make a fresh request, with neither Authorization nor cookies/headers copied.
		req, e = http.NewRequestWithContext(ctx, "GET", location.String(), nil)
		if e != nil {
			return errors.New("artifact-download-request")
		}
		response, e = client.Do(req)
		if e != nil {
			return errors.New("artifact-download-blob")
		}
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return errors.New("artifact-download-status")
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, 128<<20+1))
	if e != nil || len(raw) > 128<<20 {
		return errors.New("artifact-download-size")
	}
	if digest(raw) != sha {
		return errors.New("artifact-download-digest")
	}
	temp, e := os.CreateTemp(filepath.Dir(out), ".a2a-artifact-")
	if e != nil {
		return e
	}
	defer os.Remove(temp.Name())
	if _, e = temp.Write(raw); e != nil {
		temp.Close()
		return e
	}
	if e = temp.Close(); e != nil {
		return e
	}
	return os.Rename(temp.Name(), out)
}
func artifactBlobURL(u *url.URL) bool {
	if u == nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.Fragment != "" {
		return false
	}
	return strings.HasSuffix(u.Host, ".blob.core.windows.net") || strings.HasSuffix(u.Host, ".actions.githubusercontent.com")
}
