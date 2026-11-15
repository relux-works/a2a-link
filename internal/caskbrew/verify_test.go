package caskbrew

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/a2a-swarm/internal/cask"
	"github.com/relux-works/a2a-swarm/internal/sharedrelease"
)

func brewFixture(t *testing.T) ([]byte, []byte, cask.Manifest) {
	t.Helper()
	raw, e := os.ReadFile("testdata/brew-7.0.13.json")
	if e != nil {
		t.Fatal(e)
	}
	var doc struct {
		Casks []struct {
			URL, SHA256 string
			Variations  map[string]struct{ URL, SHA256 string }
		}
	}
	if e = json.Unmarshal(raw, &doc); e != nil {
		t.Fatal(e)
	}
	c := doc.Casks[0]
	m := cask.Manifest{Schema: cask.Schema, Tag: "v0.1.1", Commit: strings.Repeat("a", 40), Version: "0.1.1"}
	for _, a := range []struct{ os, arch, url, sum string }{{"darwin", "arm64", c.URL, c.SHA256}, {"linux", "amd64", c.Variations["x86_64_linux"].URL, c.Variations["x86_64_linux"].SHA256}, {"linux", "arm64", c.Variations["arm64_linux"].URL, c.Variations["arm64_linux"].SHA256}} {
		m.Assets = append(m.Assets, cask.Asset{Name: "a2a_0.1.1_" + a.os + "_" + a.arch + ".tar.gz", URL: a.url, SHA256: a.sum})
	}
	ruby, e := cask.Render(m)
	if e != nil {
		t.Fatal(e)
	}
	var obj map[string]any
	if e = json.Unmarshal(raw, &obj); e != nil {
		t.Fatal(e)
	}
	obj["casks"].([]any)[0].(map[string]any)["ruby_source_checksum"] = map[string]string{"sha256": sharedrelease.Hash(ruby)}
	raw, e = json.Marshal(obj)
	if e != nil {
		t.Fatal(e)
	}
	return raw, ruby, m
}

// Real Homebrew's resolved target, URL, checksum, version and closed artifacts are checked beside its accepted output.
func TestBrewInstallerFields(t *testing.T) {
	for _, tc := range []struct{ name, want string }{{"valid", ""}, {"url", "brew-effective-url"}, {"sha256", "brew-effective-sha256"}, {"version", "brew-effective-metadata"}, {"binary-target", "brew-effective-binary-target"}, {"binary-source", "brew-effective-binary-target"}, {"hook-artifact", "brew-effective-artifacts"}, {"unknown-field", "brew-fields-closed"}, {"variation-sha", "brew-effective-sha256"}, {"variation-field", "brew-variation-fields"}, {"intel-macos", "brew-intel-macos-refused"}, {"ruby-change", "cask-derivation-mismatch"}} {
		t.Run(tc.name, func(t *testing.T) {
			raw, ruby, m := brewFixture(t)
			var obj map[string]any
			if e := json.Unmarshal(raw, &obj); e != nil {
				t.Fatal(e)
			}
			c := obj["casks"].([]any)[0].(map[string]any)
			switch tc.name {
			case "url":
				c["url"] = "https://example.invalid/a2a"
			case "sha256":
				c["sha256"] = strings.Repeat("0", 64)
			case "version":
				c["version"] = "0.1.2"
			case "binary-target":
				c["artifacts"].([]any)[0].(map[string]any)["target"] = "/isolated/brew/bin/other"
			case "binary-source":
				c["artifacts"].([]any)[0].(map[string]any)["binary"] = []any{"other"}
			case "hook-artifact":
				c["artifacts"] = append(c["artifacts"].([]any), map[string]any{"preflight": []any{}})
			case "unknown-field":
				c["unknown"] = true
			case "variation-sha":
				c["variations"].(map[string]any)["arm64_linux"].(map[string]any)["sha256"] = strings.Repeat("0", 64)
			case "variation-field":
				c["variations"].(map[string]any)["arm64_linux"].(map[string]any)["installer"] = true
			case "intel-macos":
				c["supported_platforms"] = append(c["supported_platforms"].([]any), "x86_64_sequoia")
			case "ruby-change":
				ruby = append(ruby, []byte("# changed\n")...)
			}
			raw, e := json.Marshal(obj)
			if e != nil {
				t.Fatal(e)
			}
			e = Verify(raw, ruby, m, "/isolated/brew", "darwin/arm64")
			if tc.want == "" {
				if e != nil {
					t.Fatal(e)
				}
			} else if e == nil || e.Error() != tc.want {
				t.Fatalf("want %s, got %v", tc.want, e)
			}
		})
	}
}

// A custody diff admits the exact a2a path and refuses another product, policy file, empty diff or extra path.
func TestCustodyTapDiff(t *testing.T) {
	for _, paths := range [][]string{{"Casks/a2a.rb"}, {"Casks/curator.rb"}, {"Casks/a2a.rb", "README.md"}, {}, {"Casks/../Casks/a2a.rb"}} {
		e := VerifyTapDiff(paths)
		if len(paths) == 1 && paths[0] == "Casks/a2a.rb" {
			if e != nil {
				t.Fatal(e)
			}
		} else if e == nil {
			t.Fatal("unsafe diff accepted", paths)
		}
	}
}

// Hosted qualification checks the pinned public brew evaluator, with no production trust or installation authority.
func TestRealBrewEvaluation(t *testing.T) {
	info := os.Getenv("A2A_BREW_INFO")
	if info == "" {
		t.Skip("pinned hosted Homebrew evaluation required")
	}
	raw, e := os.ReadFile(info)
	if e != nil {
		t.Fatal(e)
	}
	ruby, e := os.ReadFile(os.Getenv("A2A_BREW_CASK"))
	if e != nil {
		t.Fatal(e)
	}
	rawManifest, e := os.ReadFile(os.Getenv("A2A_BREW_MANIFEST"))
	if e != nil {
		t.Fatal(e)
	}
	m, e := cask.ParseManifest(rawManifest)
	if e != nil {
		t.Fatal(e)
	}
	want := os.Getenv("A2A_BREW_EXPECT_REFUSAL")
	if want == "" {
		e = Verify(raw, ruby, m, os.Getenv("A2A_BREW_PREFIX"), os.Getenv("A2A_BREW_PLATFORM"))
	} else {
		e = verifyEffective(raw, ruby, m, os.Getenv("A2A_BREW_PREFIX"), os.Getenv("A2A_BREW_PLATFORM"))
	}
	if want == "" {
		if e != nil {
			t.Fatal(e)
		}
	} else if e == nil || e.Error() != want {
		t.Fatalf("want %s, got %v", want, e)
	}
}

// The hosted evaluator fixture contains known qualification digests and never authenticates a production manifest.
func TestWriteBrewEvaluationFixture(t *testing.T) {
	dir := os.Getenv("A2A_BREW_FIXTURE_DIR")
	if dir == "" {
		t.Skip("hosted evaluator fixture output not requested")
	}
	_, ruby, m := brewFixture(t)
	raw, e := json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	for n, x := range map[string][]byte{"a2a.rb": ruby, "manifest.json": raw} {
		if e = os.WriteFile(filepath.Join(dir, n), x, 0600); e != nil {
			t.Fatal(e)
		}
	}
}

// Captured Linux brew output validates both Linux and dependency-refused macOS projections, including Homebrew's unprefixed OS variation keys.
func TestBrewLinuxEvaluatedProjection(t *testing.T) {
	_, ruby, m := brewFixture(t)
	raw, e := os.ReadFile("testdata/brew-7.0.13-linux.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = Verify(raw, ruby, m, "/isolated/brew", "linux/amd64"); e != nil {
		t.Fatal(e)
	}
}

// The concrete controller evaluator uses the pinned public brew CLI on
// canonical qualification data, with no fixture-to-production trust promotion.
func TestRealBrewControllerEvaluation(t *testing.T) {
	prefix := os.Getenv("A2A_BREW_PREFIX")
	if prefix == "" {
		t.Skip("hosted pinned brew prefix required")
	}
	raw, e := os.ReadFile(os.Getenv("A2A_BREW_MANIFEST"))
	if e != nil {
		t.Fatal(e)
	}
	m, e := cask.ParseManifest(raw)
	if e != nil {
		t.Fatal(e)
	}
	ruby, e := cask.Render(m)
	if e != nil {
		t.Fatal(e)
	}
	if e = Evaluate(context.Background(), prefix, ruby, m); e != nil {
		t.Fatal(e)
	}
}
