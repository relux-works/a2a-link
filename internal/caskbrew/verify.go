// Package caskbrew checks Homebrew 7.0.13's public evaluated cask JSON. It has
// no Ruby evaluator, download, install, tap write, or authenticity bypass.
package caskbrew

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/relux-works/a2a-swarm/internal/cask"
	"github.com/relux-works/a2a-swarm/internal/sharedrelease"
)

// Verify requires the exact canonical Ruby and the fields the installer uses,
// including resolved binary targets. m must come from the authenticated manifest
// gate. Evaluation must use the pinned brew in an isolated prefix.
func Verify(raw, ruby []byte, m cask.Manifest, prefix, platform string) error {
	canonical, e := cask.Render(m)
	if e != nil {
		return e
	}
	if !bytes.Equal(ruby, canonical) {
		return errors.New("cask-derivation-mismatch")
	}
	return verifyEffective(raw, ruby, m, prefix, platform)
}

func verifyEffective(raw, ruby []byte, m cask.Manifest, prefix, platform string) error {
	var e error
	if !filepath.IsAbs(prefix) || filepath.Clean(prefix) != prefix || prefix == string(filepath.Separator) {
		return errors.New("brew-prefix-refused")
	}
	if platform != "darwin/arm64" && platform != "linux/amd64" && platform != "linux/arm64" {
		return errors.New("brew-platform-refused")
	}
	var doc map[string]json.RawMessage
	if sharedrelease.DecodeExact(raw, &doc) != nil || len(doc) != 2 {
		return errors.New("brew-json-contract")
	}
	var formulae []any
	var casks []map[string]json.RawMessage
	if json.Unmarshal(doc["formulae"], &formulae) != nil || len(formulae) != 0 || json.Unmarshal(doc["casks"], &casks) != nil || len(casks) != 1 {
		return errors.New("brew-json-contract")
	}
	c := casks[0]
	keys := strings.Fields("token full_token old_tokens tap name desc homepage url url_specs version autobump no_autobump_message skip_livecheck installed installed_time bundle_version bundle_short_version pinned pinned_version outdated sha256 artifacts caveats caveats_rosetta depends_on conflicts_with container rename auto_updates deprecated deprecation_date deprecation_reason deprecation_replacement_formula deprecation_replacement_cask deprecate_args disabled disable_date disable_reason disable_replacement_formula disable_replacement_cask disable_args tap_git_head languages ruby_source_path ruby_source_checksum variations supported_platforms")
	allowed := map[string]bool{}
	for _, k := range keys {
		allowed[k] = true
	}
	if len(c) != len(allowed) {
		return errors.New("brew-fields-closed")
	}
	for k := range c {
		if !allowed[k] {
			return errors.New("brew-fields-closed")
		}
	}
	eq := func(key string, want any) bool {
		var got any
		return json.Unmarshal(c[key], &got) == nil && reflect.DeepEqual(got, want)
	}
	if !eq("token", "a2a") || !eq("version", m.Version) || !eq("name", []any{"a2a"}) || !eq("desc", "Agent-to-agent messaging CLI") || !eq("homepage", "https://github.com/relux-works/a2a-swarm") || !eq("url_specs", map[string]any{}) || !eq("skip_livecheck", true) {
		return errors.New("brew-effective-metadata")
	}
	for _, k := range strings.Fields("caveats caveats_rosetta conflicts_with container auto_updates deprecate_args disable_args") {
		if !eq(k, nil) {
			return errors.New("brew-forbidden-stanza")
		}
	}
	var source map[string]string
	if json.Unmarshal(c["ruby_source_checksum"], &source) != nil || len(source) != 1 || source["sha256"] != sharedrelease.Hash(ruby) {
		return errors.New("brew-source-checksum")
	}
	assets := map[string]cask.Asset{}
	for _, a := range m.Assets {
		assets[a.Name] = a
	}
	check := func(v map[string]json.RawMessage, platform string) error {
		goos, arch, _ := strings.Cut(platform, "/")
		name := "a2a_" + m.Version + "_" + goos + "_" + arch + ".tar.gz"
		a, ok := assets[name]
		if !ok {
			return errors.New("brew-manifest-asset")
		}
		var url, sha, version string
		if json.Unmarshal(v["url"], &url) != nil || url != a.URL {
			return errors.New("brew-effective-url")
		}
		if json.Unmarshal(v["sha256"], &sha) != nil || sha != a.SHA256 {
			return errors.New("brew-effective-sha256")
		}
		if json.Unmarshal(v["version"], &version) != nil || version != m.Version {
			return errors.New("brew-effective-version")
		}
		var deps any
		if json.Unmarshal(v["depends_on"], &deps) != nil {
			return errors.New("brew-effective-dependencies")
		}
		wantDeps := any(map[string]any{})
		if goos == "darwin" {
			wantDeps = map[string]any{"arch": []any{map[string]any{"type": "arm", "bits": float64(64)}}}
		}
		if !reflect.DeepEqual(deps, wantDeps) {
			return errors.New("brew-effective-dependencies")
		}
		var artifacts []map[string]json.RawMessage
		if json.Unmarshal(v["artifacts"], &artifacts) != nil {
			return errors.New("brew-effective-artifacts")
		}
		want := []string{"a2a"}
		if goos == "darwin" {
			want = []string{"a2a-keychain-status", "a2a"}
		}
		if len(artifacts) != len(want)+1 {
			return errors.New("brew-effective-artifacts")
		}
		for i, n := range want {
			ar := artifacts[i]
			var source []string
			var target string
			if len(ar) != 2 || json.Unmarshal(ar["binary"], &source) != nil || len(source) != 1 || source[0] != n || json.Unmarshal(ar["target"], &target) != nil || target != filepath.Join(prefix, "bin", n) {
				return errors.New("brew-effective-binary-target")
			}
		}
		var zap []any
		if len(artifacts[len(want)]) != 1 || json.Unmarshal(artifacts[len(want)]["zap"], &zap) != nil || zap == nil || len(zap) != 0 {
			return errors.New("brew-effective-artifacts")
		}
		return nil
	}
	if e = check(c, platform); e != nil {
		return e
	}
	var variations map[string]map[string]json.RawMessage
	if json.Unmarshal(c["variations"], &variations) != nil {
		return errors.New("brew-variations")
	}
	macOS := map[string]bool{"golden_gate": true, "tahoe": true, "sequoia": true, "sonoma": true, "ventura": true, "monterey": true, "big_sur": true}
	for key, patch := range variations {
		target := "darwin/arm64"
		switch key {
		case "x86_64_linux":
			target = "linux/amd64"
		case "arm64_linux":
			target = "linux/arm64"
		default:
			osName := strings.TrimPrefix(strings.TrimPrefix(key, "arm64_"), "x86_64_")
			if !macOS[osName] {
				return errors.New("brew-variation-platform")
			}
		}
		v := map[string]json.RawMessage{}
		for k, x := range c {
			v[k] = x
		}
		for k, x := range patch {
			switch k {
			case "url", "sha256", "artifacts", "depends_on", "version":
				v[k] = x
			default:
				return errors.New("brew-variation-fields")
			}
		}
		if e = check(v, target); e != nil {
			return e
		}
	}
	var supported []string
	if json.Unmarshal(c["supported_platforms"], &supported) != nil || len(supported) == 0 {
		return errors.New("brew-supported-platforms")
	}
	seen := map[string]bool{}
	linuxAMD, linuxARM, darwin := false, false, false
	for _, p := range supported {
		if seen[p] {
			return errors.New("brew-supported-platforms")
		}
		seen[p] = true
		switch p {
		case "x86_64_linux":
			linuxAMD = true
		case "arm64_linux":
			linuxARM = true
		default:
			if !strings.HasPrefix(p, "arm64_") || !macOS[strings.TrimPrefix(p, "arm64_")] {
				return errors.New("brew-intel-macos-refused")
			}
			darwin = true
		}
	}
	if !linuxAMD || !linuxARM || !darwin {
		return errors.New("brew-supported-platforms")
	}
	// Every supported projection must be validated even when Homebrew omitted an
	// identical variation. Intel macOS may appear as a dependency-refused variant.
	for _, p := range supported {
		target := "darwin/arm64"
		if p == "x86_64_linux" {
			target = "linux/amd64"
		}
		if p == "arm64_linux" {
			target = "linux/arm64"
		}
		v := map[string]json.RawMessage{}
		for k, x := range c {
			v[k] = x
		}
		for k, x := range variations[p] {
			v[k] = x
		}
		if e = check(v, target); e != nil {
			return e
		}
	}
	return nil
}

// VerifyTapDiff accepts only the single a2a cask path; custody never changes tap policy or another product.
func VerifyTapDiff(paths []string) error {
	if len(paths) != 1 || paths[0] != "Casks/a2a.rb" {
		return errors.New("tap-diff-outside-a2a")
	}
	return nil
}
