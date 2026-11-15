package sharedrelease

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func reviewerRoot(t *testing.T) string {
	t.Helper()
	root := os.Getenv("A2A_PACKAGE_CONTROL_BUNDLE")
	if root == "" {
		t.Skip("real-package regressions run in linux-production-packages")
	}
	return root
}

func reviewerRead(t *testing.T, path string) []byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return contents
}

func reviewerPrepare(t *testing.T, plant, name string) error {
	t.Helper()
	bundle := reviewerRoot(t)
	directory := t.TempDir()
	entries, err := os.ReadDir(bundle)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		put(t, directory, entry.Name(), reviewerRead(t, filepath.Join(bundle, entry.Name())))
	}
	if plant != "" {
		payload := reviewerPlant(t, plant, reviewerRead(t, filepath.Join(bundle, name)))
		put(t, directory, name, payload)
		var sbom map[string]any
		if err := json.Unmarshal(reviewerRead(t, filepath.Join(directory, name+".sbom.json")), &sbom); err != nil {
			t.Fatal(err)
		}
		metadata := sbom["source"].(map[string]any)["metadata"].(map[string]any)
		for _, row := range metadata["digests"].([]any) {
			digest := row.(map[string]any)
			if digest["algorithm"] == "sha256" {
				digest["value"] = Hash(payload)
			}
		}
		put(t, directory, name+".sbom.json", encode(t, sbom))
	}
	var evidence LinuxEvidence
	if err := json.Unmarshal(reviewerRead(t, filepath.Join(bundle, "linux-release-evidence.json")), &evidence); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "bundle")
	err = PrepareLinux(filepath.Join("..", ".."), directory, output, os.Getenv("A2A_PACKAGE_CONTROL_SOURCE"), evidence.Binding, evidence.SourceDateEpoch, "qualification", evidence.Tools)
	if err != nil {
		if _, statErr := os.Stat(output); !os.IsNotExist(statErr) {
			t.Fatal("refused package exposed output", statErr)
		}
	}
	return err
}

// Real hosted artifacts must pass PrepareLinux; wrong architecture and a new postinst must fail before output exposure.
func TestReviewerRealPackageControls(t *testing.T) {
	if err := reviewerPrepare(t, "", ""); err != nil {
		t.Fatal("unchanged hosted package positive control", err)
	}
	for _, test := range []struct{ plant, want string }{
		{"wrong-architecture.deb", "package-architecture-or-version"},
		{"extra-postinst.deb", "deb-maintainer-or-config-file: postinst"},
	} {
		t.Run(test.plant, func(t *testing.T) {
			err := reviewerPrepare(t, test.plant, "a2a_0.1.2_amd64.deb")
			if err == nil || err.Error() != test.want {
				t.Fatalf("expected %s, got %v", test.want, err)
			}
			t.Log("intended refusal:", err)
		})
	}
}

// RPM header install modes must not override a correct payload mode; both setuid and non-executable header plants must refuse.
func TestReviewerRPMHeaderModes(t *testing.T) {
	if err := reviewerPrepare(t, "", ""); err != nil {
		t.Fatal("unchanged RPM positive control", err)
	}
	for _, plant := range []string{"rpm-header-setuid.rpm", "rpm-header-nonexecutable.rpm"} {
		t.Run(plant, func(t *testing.T) {
			if err := reviewerPrepare(t, plant, "a2a-0.1.2-1.x86_64.rpm"); err == nil {
				t.Fatal("RPM header install-mode plant survived public PrepareLinux and was sealed into output")
			} else if err.Error() != "package-executable-mode-or-owner" {
				t.Fatal("expected install-mode refusal, got unrelated failure", err)
			} else {
				t.Log("refused:", err)
			}
		})
	}
}

// These are structure and actual-byte binding negatives, not cryptographic evidence; authentication is injected explicitly.
func TestReviewerManifestIndependentNegatives(t *testing.T) {
	directory, raw := platformFixture(t)
	if _, err := VerifyProduction(context.Background(), raw, "sig", "cert", directory, binding(), acceptBlob); err != nil {
		t.Fatal("unchanged manifest positive control", err)
	}
	t.Run("case-variant-alongside-canonical-key", func(t *testing.T) {
		changed := []byte(strings.Replace(string(raw), `"sha256":`, `"SHA256":"`+strings.Repeat("0", 64)+`","sha256":`, 1))
		manifest, err := VerifyProduction(context.Background(), changed, "sig", "cert", directory, binding(), acceptBlob)
		if err == nil || err.Error() != "manifest-malformed: json-unknown-key: SHA256" || len(manifest.Assets) != 0 {
			t.Fatal("case alias admitted or wrong refusal", err)
		}
		t.Log("intended refusal:", err)
	})
	t.Run("valid-digest-of-different-member", func(t *testing.T) {
		manifest, err := ParseManifest(raw, binding())
		if err != nil {
			t.Fatal(err)
		}
		if manifest.Assets[0].SHA256 == manifest.Assets[1].SHA256 {
			t.Fatal("fixture lacks distinct byte digests")
		}
		manifest.Assets[0].SHA256 = manifest.Assets[1].SHA256
		wanted := "manifest-asset-bytes-mismatch: " + manifest.Assets[0].Name
		result, err := VerifyProduction(context.Background(), encode(t, manifest), "sig", "cert", directory, binding(), acceptBlob)
		if err == nil || err.Error() != wanted || len(result.Assets) != 0 {
			t.Fatal("other-member digest admitted or wrong refusal", err)
		}
		t.Log("intended refusal:", err)
	})
}
