package darwinrelease

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func archiveEvidence(dir, out string) error {
	es, e := os.ReadDir(dir)
	if e != nil {
		return e
	}
	f, e := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, entry := range es {
		if entry.IsDir() {
			return errors.New("evidence-entry")
		}
		b, e := os.ReadFile(filepath.Join(dir, entry.Name()))
		if e != nil {
			return e
		}
		if e = tw.WriteHeader(&tar.Header{Name: entry.Name(), Mode: 0600, Size: int64(len(b)), Typeflag: tar.TypeReg}); e != nil {
			return e
		}
		if _, e = tw.Write(b); e != nil {
			return e
		}
	}
	if e = tw.Close(); e != nil {
		return e
	}
	if e = gz.Close(); e != nil {
		return e
	}
	return f.Close()
}
func verifyAssetChecksums(dir string) error {
	data, e := os.ReadFile(filepath.Join(dir, "checksums.txt"))
	if e != nil {
		return errors.New("checksums-missing")
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		f := strings.Split(line, "  ")
		if len(f) != 2 || len(f[0]) != 64 || filepath.Base(f[1]) != f[1] || seen[f[1]] {
			return errors.New("checksums-malformed")
		}
		seen[f[1]] = true
		b, e := os.ReadFile(filepath.Join(dir, f[1]))
		if e != nil || digest(b) != f[0] {
			return errors.New("distributed-bytes-changed")
		}
	}
	archives := 0
	for name := range seen {
		if regexp.MustCompile(`^a2a_(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)_darwin_arm64\.tar\.gz$`).MatchString(name) {
			archives++
		} else if name != "evidence.tar.gz" && name != "release-evidence.json" {
			return errors.New("asset-unqualified")
		}
	}
	if archives != 1 || !seen["evidence.tar.gz"] || !seen["release-evidence.json"] {
		return errors.New("asset-members")
	}
	es, e := os.ReadDir(dir)
	if e != nil || len(seen) != 3 || len(es) != 6 {
		return errors.New("asset-members")
	}
	for _, entry := range es {
		if entry.IsDir() {
			return errors.New("asset-directory")
		}
		n := entry.Name()
		if !seen[n] && n != "checksums.txt" && n != "checksums.txt.sig" && n != "checksums.txt.pem" {
			return errors.New("asset-unqualified")
		}
		st, e := os.Lstat(filepath.Join(dir, n))
		if e != nil || !st.Mode().IsRegular() || st.Size() == 0 {
			return errors.New("asset-type")
		}
	}
	return nil
}

func publishAssets(ctx context.Context, root, tag, tagObject, dir string) error {
	names := []string{"a2a_" + strings.TrimPrefix(tag, "v") + "_darwin_arm64.tar.gz", "checksums.txt", "checksums.txt.sig", "checksums.txt.pem", "evidence.tar.gz", "release-evidence.json"}
	return PublishPreparedAssets(ctx, root, tag, tagObject, dir, names, "Darwin arm64 CLI and sibling status companion. Verify checksums and release evidence before separately authorized adoption. Native Keychain/no-UI and cross-version qualification remain separate.", func(ctx context.Context, captured string) error { return verifySignedAssets(ctx, root, tag, captured) })
}
