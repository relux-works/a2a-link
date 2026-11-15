// Package sharedrelease prepares private Linux bundles and verifies the closed
// production platform aggregate. It has no release or tap publication API.
package sharedrelease

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/relux-works/a2a-swarm/internal/cask"
)

const (
	Schema     = "a2a-release-assets/2"
	Repository = "relux-works/a2a-swarm"
	Workflow   = ".github/workflows/shared-release.yml"
	Issuer     = "https://token.actions.githubusercontent.com"
)

var stable = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
var object = regexp.MustCompile(`^[0-9a-f]{40}$`)
var digestForm = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Binding struct {
	Tag       string `json:"tag"`
	Commit    string `json:"commit"`
	TagObject string `json:"tag_object"`
}

func (b Binding) Version() string { return strings.TrimPrefix(b.Tag, "v") }
func (b Binding) Validate() error {
	if b.Tag != "v"+b.Version() || !stable.MatchString(b.Version()) {
		return errors.New("release-version-not-stable")
	}
	if !object.MatchString(b.Commit) || !object.MatchString(b.TagObject) {
		return errors.New("release-binding-malformed")
	}
	return nil
}

// LinuxArtifacts is the exact archive/package set, in a stable order.
func LinuxArtifacts(v string) []string {
	return []string{"a2a_" + v + "_linux_amd64.tar.gz", "a2a_" + v + "_linux_arm64.tar.gz",
		"a2a_" + v + "_amd64.deb", "a2a_" + v + "_arm64.deb", "a2a-" + v + "-1.x86_64.rpm", "a2a-" + v + "-1.aarch64.rpm"}
}
func LinuxMembers(v string) []string {
	n := LinuxArtifacts(v)
	for _, a := range LinuxArtifacts(v) {
		n = append(n, a+".sbom.json")
	}
	return append(n, "linux-checksums.txt", "linux-checksums.txt.sig", "linux-checksums.txt.pem", "linux-release-evidence.json")
}
func DarwinMembers(v string) []string {
	return []string{"a2a_" + v + "_darwin_arm64.tar.gz", "checksums.txt", "checksums.txt.sig", "checksums.txt.pem", "evidence.tar.gz", "release-evidence.json"}
}
func Members(v string) []string {
	n := append(DarwinMembers(v), LinuxMembers(v)...)
	sort.Strings(n)
	return n
}

type Manifest struct {
	Schema        string       `json:"schema"`
	Binding       Binding      `json:"binding"`
	Version       string       `json:"version"`
	Architectures []string     `json:"architectures"`
	Assets        []cask.Asset `json:"assets"`
}

// DecodeExact refuses unknown, absent, differently cased and duplicate keys at
// every typed object level. A valid last duplicate never hides an earlier key.
func DecodeExact(raw []byte, dst any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) (any, error)
	walk = func(depth int) (any, error) {
		if depth > 32 {
			return nil, errors.New("json-depth")
		}
		t, e := d.Token()
		if e != nil {
			return nil, e
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				m := map[string]any{}
				for d.More() {
					k, e := d.Token()
					if e != nil {
						return nil, e
					}
					s, ok := k.(string)
					if !ok {
						return nil, errors.New("json-key")
					}
					if _, ok = m[s]; ok {
						return nil, fmt.Errorf("json-duplicate-key: %s", s)
					}
					v, e := walk(depth + 1)
					if e != nil {
						return nil, e
					}
					m[s] = v
				}
				_, e = d.Token()
				return m, e
			case '[':
				a := []any{}
				for d.More() {
					v, e := walk(depth + 1)
					if e != nil {
						return nil, e
					}
					a = append(a, v)
				}
				_, e = d.Token()
				return a, e
			default:
				return nil, errors.New("json-delimiter")
			}
		}
		return t, nil
	}
	v, e := walk(0)
	if e != nil {
		return e
	}
	if _, e = d.Token(); e != io.EOF {
		return errors.New("json-trailing-data")
	}
	var shape func(any, reflect.Type) error
	shape = func(v any, t reflect.Type) error {
		if t.Kind() == reflect.Pointer {
			return shape(v, t.Elem())
		}
		switch t.Kind() {
		case reflect.Struct:
			m, ok := v.(map[string]any)
			if !ok {
				return errors.New("json-object-required")
			}
			keys := map[string]reflect.Type{}
			for i := 0; i < t.NumField(); i++ {
				f := t.Field(i)
				if f.PkgPath != "" {
					continue
				}
				n := strings.Split(f.Tag.Get("json"), ",")[0]
				if n == "" {
					n = f.Name
				}
				if n != "-" {
					keys[n] = f.Type
				}
			}
			for k := range m {
				if _, ok := keys[k]; !ok {
					return fmt.Errorf("json-unknown-key: %s", k)
				}
			}
			for k, typ := range keys {
				x, ok := m[k]
				if !ok {
					return fmt.Errorf("json-missing-key: %s", k)
				}
				if e := shape(x, typ); e != nil {
					return e
				}
			}
		case reflect.Slice:
			a, ok := v.([]any)
			if !ok {
				return errors.New("json-array-required")
			}
			for _, x := range a {
				if e := shape(x, t.Elem()); e != nil {
					return e
				}
			}
		}
		return nil
	}
	if e = shape(v, reflect.TypeOf(dst)); e != nil {
		return e
	}
	return json.Unmarshal(raw, dst)
}

func ParseManifest(raw []byte, expected Binding) (Manifest, error) {
	var m Manifest
	if e := DecodeExact(raw, &m); e != nil {
		return m, fmt.Errorf("manifest-malformed: %w", e)
	}
	if m.Schema != Schema {
		return m, errors.New("manifest-production-schema-required")
	}
	if e := expected.Validate(); e != nil {
		return m, e
	}
	if m.Binding != expected {
		return m, errors.New("manifest-source-tag-binding-mismatch")
	}
	if m.Version != expected.Version() {
		return m, errors.New("manifest-tag-version-mismatch")
	}
	if strings.Join(m.Architectures, ",") != "darwin/arm64,linux/amd64,linux/arm64" {
		return m, errors.New("manifest-architecture-set")
	}
	allowed := map[string]bool{}
	for _, n := range Members(m.Version) {
		allowed[n] = true
	}
	seen := map[string]bool{}
	for _, a := range m.Assets {
		if !allowed[a.Name] {
			return m, fmt.Errorf("manifest-member-unknown: %s", a.Name)
		}
		if seen[a.Name] {
			return m, fmt.Errorf("manifest-member-duplicate: %s", a.Name)
		}
		seen[a.Name] = true
		if a.URL != cask.ReleaseBase+m.Binding.Tag+"/"+a.Name {
			return m, fmt.Errorf("manifest-url: %s", a.Name)
		}
		if !digestForm.MatchString(a.SHA256) {
			return m, fmt.Errorf("manifest-digest: %s", a.Name)
		}
	}
	for _, n := range Members(m.Version) {
		if !seen[n] {
			return m, fmt.Errorf("manifest-member-missing: %s", n)
		}
	}
	return m, nil
}

// Cask projects only the three archive rows after full production validation.
func (m Manifest) Cask() cask.Manifest {
	d, la, lr := cask.Archives(m.Version)
	c := cask.Manifest{Schema: cask.Schema, Tag: m.Binding.Tag, Commit: m.Binding.Commit, Version: m.Version}
	for _, a := range m.Assets {
		if a.Name == d || a.Name == la || a.Name == lr {
			c.Assets = append(c.Assets, a)
		}
	}
	return c
}

func Hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func fileHash(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func readRegular(dir, name string) ([]byte, error) {
	p := filepath.Join(dir, name)
	s, e := os.Lstat(p)
	if e != nil || !s.Mode().IsRegular() || s.Size() <= 0 || s.Size() > 256<<20 {
		return nil, fmt.Errorf("asset-type-or-missing: %s", name)
	}
	b, e := os.ReadFile(p)
	if e != nil {
		return nil, fmt.Errorf("asset-unreadable: %s", name)
	}
	return b, nil
}

func exactDirectory(dir string, names []string) error {
	es, e := os.ReadDir(dir)
	if e != nil {
		return errors.New("bundle-unreadable")
	}
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	for _, entry := range es {
		if !want[entry.Name()] {
			return fmt.Errorf("bundle-member-unknown: %s", entry.Name())
		}
		if _, e := readRegular(dir, entry.Name()); e != nil {
			return e
		}
		delete(want, entry.Name())
	}
	for _, n := range names {
		if want[n] {
			return fmt.Errorf("bundle-member-missing: %s", n)
		}
	}
	return nil
}

// BindFiles checks every platform row, including signatures, evidence and
// SBOMs. Self/signature files may accompany an already assembled aggregate;
// neither they nor a cask can enter the signed platform member list.
func BindFiles(m Manifest, dir string) error {
	allowed := Members(m.Version)
	for _, n := range []string{"release-assets.json", "release-assets.json.sig", "release-assets.json.pem"} {
		if _, e := os.Lstat(filepath.Join(dir, n)); e == nil {
			allowed = append(allowed, n)
		}
	}
	if e := exactDirectory(dir, allowed); e != nil {
		return e
	}
	for _, a := range m.Assets {
		b, e := readRegular(dir, a.Name)
		if e != nil {
			return e
		}
		if Hash(b) != a.SHA256 {
			return fmt.Errorf("manifest-asset-bytes-mismatch: %s", a.Name)
		}
	}
	return nil
}
