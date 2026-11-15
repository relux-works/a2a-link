package darwinrelease

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
)

// PublicationGate authenticates a closed captured candidate. Only trusted
// controller code supplies it; there is no CLI flag or fixture-trust override.
type PublicationGate func(context.Context, string) error

type releaseAsset struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Digest string `json:"digest"`
	State  string `json:"state"`
	Size   int64  `json:"size"`
}
type releaseState struct {
	ID         int64          `json:"id"`
	Draft      *bool          `json:"draft"`
	Prerelease *bool          `json:"prerelease"`
	Tag        string         `json:"tag_name"`
	Commit     string         `json:"target_commitish"`
	Assets     []releaseAsset `json:"assets"`
}
type releaseFile struct {
	bytes []byte
	sha   string
}

// PublishPreparedAssets reuses the original client and one-draft/one-transition
// protocol. The combined route remains held until its trusted controller calls
// this boundary with all production verification gates and a custody lease.
func PublishPreparedAssets(ctx context.Context, root, tag, tagObject, dir string, names []string, notes string, verify PublicationGate) error {
	admit := func() (Admission, error) { return Admit(ctx, root, tag, tagObject) }
	return publishPrepared(ctx, newGitHub(os.Getenv("GITHUB_TOKEN")), admit, tag, tagObject, dir, names, notes, verify)
}

func captureRelease(dir string, names []string) (string, map[string]releaseFile, error) {
	if len(names) == 0 || len(names) > 32 {
		return "", nil, errors.New("publication-member-contract")
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != len(names) {
		return "", nil, errors.New("publication-member-contract")
	}
	stage, e := os.MkdirTemp("", "a2a-publication-input-")
	if e != nil {
		return "", nil, e
	}
	files := map[string]releaseFile{}
	success := false
	defer func() {
		if !success {
			os.RemoveAll(stage)
		}
	}()
	for _, n := range names {
		if n == "" || filepath.Base(n) != n || n == "." || files[n].bytes != nil {
			return "", nil, errors.New("publication-member-contract")
		}
		path := filepath.Join(dir, n)
		st, e := os.Lstat(path)
		if e != nil || !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > 128<<20 {
			return "", nil, errors.New("publication-member-type")
		}
		raw, e := os.ReadFile(path)
		if e != nil {
			return "", nil, e
		}
		files[n] = releaseFile{raw, digest(raw)}
		if e = os.WriteFile(filepath.Join(stage, n), raw, 0600); e != nil {
			return "", nil, e
		}
	}
	success = true
	return stage, files, nil
}
func sameAdmission(a, b Admission) bool {
	return a.Tag == b.Tag && a.TagObject == b.TagObject && a.Commit == b.Commit && a.Version == b.Version
}

func publishPrepared(ctx context.Context, g *githubAPI, admit func() (Admission, error), tag, tagObject, dir string, names []string, notes string, verify PublicationGate) error {
	if verify == nil {
		return errors.New("publication-verifier-required")
	}
	a, e := admit()
	if e != nil {
		return e
	}
	if a.Tag != tag || a.TagObject != tagObject || !objectID.MatchString(a.Commit) {
		return errors.New("publication-admission-binding")
	}
	captured, files, e := captureRelease(dir, names)
	if e != nil {
		return e
	}
	defer os.RemoveAll(captured)
	if e = verify(ctx, captured); e != nil {
		return e
	}
	prefix := "/repos/relux-works/a2a-swarm/releases"
	var existing releaseState
	status, e := g.request(ctx, "GET", prefix+"/tags/"+url.PathEscape(tag), nil, &existing)
	if e != nil {
		return e
	}
	if status != 404 {
		return errors.New("release-already-exists")
	}
	// Admission is repeated immediately before the first external mutation.
	current, e := admit()
	if e != nil {
		return e
	}
	if !sameAdmission(a, current) {
		return errors.New("publication-admission-changed")
	}
	var draft releaseState
	status, e = g.request(ctx, "POST", prefix, map[string]any{"tag_name": tag, "target_commitish": a.Commit, "name": "a2a " + tag, "draft": true, "prerelease": false, "body": notes}, &draft)
	if e != nil {
		return errors.New("draft-outcome-unknown; reconcile read-only without rerun")
	}
	if status != 201 || draft.ID <= 0 || draft.Draft == nil || !*draft.Draft || draft.Tag != tag || draft.Commit != a.Commit || draft.Prerelease == nil || *draft.Prerelease {
		return errors.New("release-draft-response")
	}
	for _, n := range names {
		if e = g.upload(ctx, draft.ID, n, files[n]); e != nil {
			return e
		}
	}
	// List the complete server-side member set, not only successful individual
	// upload responses. Unexpected/duplicate/missing members prevent transition.
	if _, e = g.reconcile(ctx, draft.ID, tag, a.Commit, files, true); e != nil {
		return e
	}
	current, e = admit()
	if e != nil {
		return e
	}
	if !sameAdmission(a, current) {
		return errors.New("publication-admission-changed")
	}
	if e = verify(ctx, captured); e != nil {
		return e
	}
	path := prefix + "/" + strconv.FormatInt(draft.ID, 10)
	var published releaseState
	status, e = g.request(ctx, "PATCH", path, map[string]bool{"draft": false}, &published)
	if e != nil || status != 200 || published.ID != draft.ID || published.Draft == nil || *published.Draft || published.Tag != tag {
		// Observe once, never repeat the transition, overwrite, delete or retag.
		state, readErr := g.reconcile(ctx, draft.ID, tag, a.Commit, files, false)
		if readErr != nil {
			return errors.New("publication-outcome-unknown; read-only reconciliation inconclusive")
		}
		return fmt.Errorf("publication-outcome-unknown; read-only reconciliation: %s; no retry", state)
	}
	state, e := g.reconcile(ctx, draft.ID, tag, a.Commit, files, false)
	if e != nil {
		return e
	}
	if state != "public" {
		return errors.New("publication-readback-still-draft")
	}
	return nil
}

func (g *githubAPI) upload(ctx context.Context, id int64, name string, file releaseFile) error {
	endpoint := fmt.Sprintf("https://uploads.github.com/repos/relux-works/a2a-swarm/releases/%d/assets?name=%s", id, url.QueryEscape(name))
	req, e := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(file.bytes))
	if e != nil {
		return errors.New("asset-request")
	}
	req.ContentLength = int64(len(file.bytes))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, e := g.client.Do(req)
	if e != nil {
		return errors.New("asset-upload-outcome-unknown; reconcile read-only")
	}
	defer resp.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	var uploaded releaseAsset
	if resp.StatusCode != 201 || e != nil || len(raw) > 1<<20 || json.Unmarshal(raw, &uploaded) != nil || uploaded.ID <= 0 || uploaded.Name != name || uploaded.State != "uploaded" || uploaded.Size != int64(len(file.bytes)) {
		return errors.New("asset-upload-response")
	}
	if uploaded.Digest != "sha256:"+file.sha {
		return errors.New("uploaded-bytes-mismatch")
	}
	return nil
}

func (g *githubAPI) reconcile(ctx context.Context, id int64, tag, commit string, files map[string]releaseFile, requireDraft bool) (string, error) {
	var r releaseState
	if e := g.get(ctx, "/repos/relux-works/a2a-swarm/releases/"+strconv.FormatInt(id, 10), &r); e != nil {
		return "", e
	}
	if id <= 0 || r.ID != id || r.Tag != tag || r.Commit != commit || r.Draft == nil || r.Prerelease == nil || *r.Prerelease {
		return "", errors.New("release-readback-binding")
	}
	if requireDraft && !*r.Draft {
		return "", errors.New("premature-publication")
	}
	var listed []releaseAsset
	if e := g.get(ctx, "/repos/relux-works/a2a-swarm/releases/"+strconv.FormatInt(id, 10)+"/assets?per_page=100", &listed); e != nil {
		return "", e
	}
	if len(listed) != len(files) || len(listed) >= 100 {
		return "", errors.New("release-readback-members")
	}
	seen := map[string]bool{}
	ids := map[int64]bool{}
	for _, a := range listed {
		f, ok := files[a.Name]
		if !ok || seen[a.Name] || a.ID <= 0 || ids[a.ID] || a.Size != int64(len(f.bytes)) || a.State != "uploaded" || a.Digest != "sha256:"+f.sha {
			return "", errors.New("release-readback-digest")
		}
		seen[a.Name] = true
		ids[a.ID] = true
	}
	if *r.Draft {
		return "draft", nil
	}
	return "public", nil
}

// ReconcilePreparedAssets observes an interrupted publication read-only against
// the original authenticated local candidate and recorded draft ID. It never
// attempts a new draft, upload, transition, deletion, retag or overwrite.
func ReconcilePreparedAssets(ctx context.Context, id int64, tag, commit, dir string, names []string, verify PublicationGate) (string, error) {
	if id <= 0 || !stableTag.MatchString(tag) || !objectID.MatchString(commit) || verify == nil {
		return "", errors.New("reconciliation-input-contract")
	}
	captured, files, e := captureRelease(dir, names)
	if e != nil {
		return "", e
	}
	defer os.RemoveAll(captured)
	if e = verify(ctx, captured); e != nil {
		return "", e
	}
	return newGitHub(os.Getenv("GITHUB_TOKEN")).reconcile(ctx, id, tag, commit, files, false)
}
