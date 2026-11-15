package darwinrelease

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A scoped whole-release review is mandatory under the new policy, including
// for actual APPROVED reviews. The producer cannot turn a generic or outdated
// review into combined-release authority by reusing its marker.
func TestSharedReleaseReviewScope(t *testing.T) {
	sha := strings.Repeat("a", 40)
	marker := "Release-Review: ACCEPT " + sha
	scope := "Release-Scope: " + SharedReleaseScope
	for _, tc := range []struct {
		name, state, body string
		want              bool
	}{
		{"scoped comment", "COMMENTED", marker + "\n" + scope, true},
		{"scoped approval", "APPROVED", scope, true},
		{"old comment", "COMMENTED", marker, false},
		{"old approval", "APPROVED", "", false},
		{"wrong scope", "COMMENTED", marker + "\nRelease-Scope: darwin-only", false},
		{"wrong head", "COMMENTED", "Release-Review: ACCEPT " + strings.Repeat("b", 40) + "\n" + scope, false},
		{"withdrawn", "CHANGES_REQUESTED", marker + "\n" + scope, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := reviewAccepted(tc.state, tc.body, sha, SharedReleaseScope); got != tc.want {
				t.Fatalf("accepted %v, want %v", got, tc.want)
			}
		})
	}
}

// Actual Actions API decoding binds each mandatory check to its reviewed
// workflow. A valid-looking alternate workflow with otherwise matching job,
// run, check, source and repository associations is a specific refusal.
func TestSharedCheckWorkflowAssociation(t *testing.T) {
	for name, path := range requiredWorkflows {
		t.Run(name, func(t *testing.T) {
			sha := strings.Repeat("a", 40)
			for _, bad := range []bool{false, true} {
				workflow := path
				if bad {
					workflow = ".github/workflows/unrelated.yml"
				}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					var out any
					if strings.Contains(r.URL.Path, "/jobs/") {
						out = map[string]any{"id": 11, "run_id": 1, "name": name, "head_sha": sha, "check_run_url": "https://api.github.com/repos/relux-works/a2a-swarm/check-runs/2", "status": "completed", "conclusion": "success"}
					} else {
						out = map[string]any{"id": 1, "head_sha": sha, "head_branch": "main", "event": "push", "status": "completed", "conclusion": "success", "path": workflow, "repository": map[string]string{"full_name": "relux-works/a2a-swarm"}, "head_repository": map[string]string{"full_name": "relux-works/a2a-swarm"}}
					}
					json.NewEncoder(w).Encode(out)
				}))
				api := githubAPI{server.URL, "fixture", server.Client()}
				ok, e := api.actionsJob(context.Background(), "relux-works/a2a-swarm", sha, name, 2, fmt.Sprintf("https://github.com/relux-works/a2a-swarm/actions/runs/%d/job/%d", 1, 11), "completed", "success")
				server.Close()
				if !bad && (e != nil || !ok) {
					t.Fatal("matching workflow", e)
				}
				if bad && (e == nil || e.Error() != "required-check-workflow-mismatch" || ok) {
					t.Fatal("alternate workflow admitted", e)
				}
			}
		})
	}
}

// Missing any new or retained mandatory main check, or dropping whole-release
// scope, makes the actual source policy unloadable. The history/key pins stay.
func TestSharedReleasePolicyCannotDropGates(t *testing.T) {
	p, e := LoadPolicy(filepath.Join("..", ".."))
	if e != nil {
		t.Fatal(e)
	}
	root := t.TempDir()
	if e = os.Mkdir(filepath.Join(root, "release"), 0700); e != nil {
		t.Fatal(e)
	}
	for _, name := range append([]string{"scope"}, p.RequiredChecks...) {
		t.Run(name, func(t *testing.T) {
			plant := p
			plant.RequiredChecks = append([]string{}, p.RequiredChecks...)
			if name == "scope" {
				plant.ReviewScope = ""
			} else {
				for i, n := range plant.RequiredChecks {
					if n == name {
						plant.RequiredChecks = append(plant.RequiredChecks[:i], plant.RequiredChecks[i+1:]...)
						break
					}
				}
			}
			b, e := json.Marshal(plant)
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(filepath.Join(root, "release/policy.json"), b, 0600); e != nil {
				t.Fatal(e)
			}
			if _, e = LoadPolicy(root); e != ErrPolicy {
				t.Fatal("weakened gate admitted", e)
			}
		})
	}
}

// The partial production slice cannot publish a Darwin-only release while the
// combined assembly controller is still absent. Refusal precedes all native,
// signing and publication paths, even with no Apple configuration present.
func TestLegacyPublisherRefusesCombinedScope(t *testing.T) {
	e := RunRelease(context.Background(), filepath.Join("..", ".."), "v0.1.2", strings.Repeat("b", 40))
	if e == nil || e.Error() != "combined-release-controller-not-integrated" {
		t.Fatal(e)
	}
}
