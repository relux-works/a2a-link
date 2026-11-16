package sharedrelease

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/relux-works/a2a-swarm/internal/darwinrelease"
)

// Claim: current producer, consumer, evidence policy and CI pins, including both fixture qualification jobs, use exact Go 1.26.8.
func TestQualifiedToolchainPins(t *testing.T) {
	root := filepath.Join("..", "..")
	read := func(name string) string {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	if !strings.Contains(read("go.mod"), "\ngo "+strings.TrimPrefix(qualifiedGoVersion, "go")+"\n") {
		t.Fatal("qualified compiler differs from fork module floor")
	}
	tools, err := LoadTools(root)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := darwinrelease.LoadPolicy(root)
	if err != nil || policy.GoVersion != qualifiedGoVersion || tools.Go != qualifiedGoVersion {
		t.Fatal("producer/verifier toolchain pins differ", err)
	}
	versions := regexp.MustCompile(`go-version:\s*'([^']+)'`)
	for _, name := range []string{"distribution-controls", "release-controls", "shared-release", "darwin-release"} {
		t.Run(name, func(t *testing.T) {
			matches := versions.FindAllStringSubmatch(read(".github/workflows/"+name+".yml"), -1)
			if len(matches) == 0 {
				t.Fatal("missing exact workflow compiler")
			}
			for _, m := range matches {
				if "go"+m[1] != qualifiedGoVersion {
					t.Fatal("workflow compiler differs from strict policy")
				}
			}
		})
	}
	legacy := read(".github/workflows/cask-qualification.yml")
	matches := versions.FindAllStringSubmatch(legacy, -1)
	if len(matches) != 2 {
		t.Fatal("missing Linux/macOS fixture compilers")
	}
	for _, m := range matches {
		if "go"+m[1] != qualifiedGoVersion {
			t.Fatal("fixture compiler differs from strict policy")
		}
	}
	if !strings.Contains(legacy, "GOTOOLCHAIN="+qualifiedGoVersion+" go build -p 1") {
		t.Fatal("current renderer lacks exact fork compiler")
	}
}

// Claim: the new exact compiler pin accepts its valid tuple and refuses the former compilers and an unqualified patch, without widening to a minimum-version range.
func TestQualifiedToolchainRefusesOtherVersions(t *testing.T) {
	tools, err := LoadTools(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if err = tools.Validate(); err != nil {
		t.Fatal("qualified positive refused", err)
	}
	for _, version := range []string{"go1.25.12", "go1.26.0", "go1.26.9", "go1.27.0"} {
		bad := tools
		bad.Go = version
		if err = bad.Validate(); err == nil || err.Error() != "linux-tool-policy" {
			t.Fatalf("unqualified compiler %s admitted: %v", version, err)
		}
	}
}
