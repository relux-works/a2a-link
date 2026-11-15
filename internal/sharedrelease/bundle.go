package sharedrelease

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/relux-works/a2a-swarm/internal/darwinrelease"
)

// ArtifactReference comes from the producer's immutable upload outputs, never
// from an artifact-name search. The ZIP digest is the artifact service digest.
type ArtifactReference struct {
	ID       int64  `json:"id"`
	RunID    int64  `json:"run_id"`
	SHA256   string `json:"sha256"`
	Platform string `json:"platform"`
}
type artifactObserver func(context.Context, int64, int64, string) (darwinrelease.ArtifactObservation, error)

// CaptureBundle captures and associates one private producer artifact. It does
// not authenticate platform signatures or authorize publication; CreateManifest
// independently authenticates the resulting complete platform directory.
func CaptureBundle(ctx context.Context, path, out string, b Binding, ref ArtifactReference) error {
	return captureBundle(ctx, path, out, b, ref, darwinrelease.ObserveArtifact)
}
func captureBundle(ctx context.Context, path, out string, b Binding, ref ArtifactReference, observe artifactObserver) (err error) {
	if err = b.Validate(); err != nil {
		return err
	}
	if ref.ID <= 0 || ref.RunID <= 0 || !digestForm.MatchString(ref.SHA256) {
		return errors.New("artifact-reference-malformed")
	}
	var names []string
	switch ref.Platform {
	case "darwin":
		names = DarwinMembers(b.Version())
	case "linux":
		names = LinuxMembers(b.Version())
	default:
		return errors.New("artifact-platform-refused")
	}
	job := ref.Platform + "-producer"
	if ref.Platform == "darwin" {
		job = "darwin-producer / prepare"
	}
	observation, err := observe(ctx, ref.ID, ref.RunID, job)
	if err != nil {
		return err
	}
	if observation.ID != ref.ID || observation.RunID != ref.RunID || observation.JobID <= 0 || observation.JobName != job || observation.Name != "a2a-"+ref.Platform+"-"+b.TagObject || observation.Digest != "sha256:"+ref.SHA256 || observation.Commit != b.Commit || observation.Branch != b.Tag || observation.Workflow != Workflow {
		return errors.New("artifact-producer-binding")
	}
	raw, err := readRegular(filepath.Dir(path), filepath.Base(path))
	if err != nil {
		return err
	}
	if Hash(raw) != ref.SHA256 {
		return errors.New("artifact-zip-digest")
	}
	files, err := closedZIP(raw, names)
	if err != nil {
		return err
	}
	if ref.Platform == "linux" {
		var ev LinuxEvidence
		if DecodeExact(files["linux-release-evidence.json"], &ev) != nil || ev.Binding != b || ev.Trust != "production" {
			return errors.New("artifact-evidence-binding")
		}
	} else {
		var ev darwinrelease.Evidence
		if json.Unmarshal(files["release-evidence.json"], &ev) != nil || ev.Admission.Tag != b.Tag || ev.Admission.Commit != b.Commit || ev.Admission.TagObject != b.TagObject || ev.Admission.Version != b.Version() {
			return errors.New("artifact-evidence-binding")
		}
	}
	if _, e := os.Lstat(out); !os.IsNotExist(e) {
		return errors.New("artifact-output-exists")
	}
	stage, err := os.MkdirTemp(filepath.Dir(out), ".a2a-bundle-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	for _, n := range names {
		if err = os.WriteFile(filepath.Join(stage, n), files[n], 0600); err != nil {
			return err
		}
	}
	return os.Rename(stage, out)
}

func closedZIP(raw []byte, names []string) (map[string][]byte, error) {
	z, e := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if e != nil {
		return nil, errors.New("artifact-zip-malformed")
	}
	if len(z.File) != len(names) {
		return nil, errors.New("artifact-zip-members")
	}
	allowed := map[string]bool{}
	for _, n := range names {
		allowed[n] = true
	}
	result := map[string][]byte{}
	var total uint64
	for _, f := range z.File {
		if !allowed[f.Name] || result[f.Name] != nil || !f.Mode().IsRegular() || f.Mode()&os.ModeSymlink != 0 || f.UncompressedSize64 == 0 || f.UncompressedSize64 > 128<<20 {
			return nil, errors.New("artifact-zip-member")
		}
		total += f.UncompressedSize64
		if total > 512<<20 {
			return nil, errors.New("artifact-zip-size")
		}
		r, e := f.Open()
		if e != nil {
			return nil, errors.New("artifact-zip-read")
		}
		x, e := io.ReadAll(io.LimitReader(r, 128<<20+1))
		closeErr := r.Close()
		if e != nil || closeErr != nil || uint64(len(x)) != f.UncompressedSize64 {
			return nil, errors.New("artifact-zip-read")
		}
		result[f.Name] = x
	}
	for _, n := range names {
		if result[n] == nil {
			return nil, fmt.Errorf("artifact-zip-missing: %s", n)
		}
	}
	return result, nil
}
