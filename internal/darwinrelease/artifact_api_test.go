package darwinrelease

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Actual client reads require a unique successful producer job and matching immutable artifact/run/repository identities.
func TestArtifactAPIAssociation(t *testing.T) {
	for _, tc := range []struct{ name, want string }{{"valid", ""}, {"expired", "artifact-metadata-association"}, {"unknown-expiry", "artifact-metadata-association"}, {"wrong-run", "artifact-metadata-association"}, {"wrong-repository", "artifact-run-association"}, {"unknown-state", "artifact-run-state"}, {"pending-producer", "artifact-producer-job-not-success"}, {"duplicate-producer", "artifact-producer-job-ambiguous"}, {"truncated-list", "artifact-job-list-incomplete"}, {"api-error", "api-status"}} {
		t.Run(tc.name, func(t *testing.T) {
			sha := strings.Repeat("a", 40)
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.name == "api-error" {
					w.WriteHeader(503)
					return
				}
				var body any
				switch {
				case strings.Contains(r.URL.Path, "/artifacts/"):
					run := int64(2)
					if tc.name == "wrong-run" {
						run = 3
					}
					m := map[string]any{"id": 1, "name": "a2a-darwin-object", "digest": "sha256:" + strings.Repeat("a", 64), "expired": tc.name == "expired", "workflow_run": map[string]any{"id": run, "repository_id": 9, "head_repository_id": 9, "head_sha": sha, "head_branch": "v0.1.2"}}
					if tc.name == "unknown-expiry" {
						delete(m, "expired")
					}
					body = m
				case strings.HasSuffix(r.URL.Path, "/jobs"):
					state := "completed"
					conclusion := "success"
					if tc.name == "pending-producer" {
						state = "in_progress"
						conclusion = ""
					}
					j := map[string]any{"id": 3, "run_id": 2, "head_sha": sha, "name": "darwin-producer", "status": state, "conclusion": conclusion}
					list := []any{j}
					if tc.name == "duplicate-producer" {
						list = append(list, j)
					}
					count := len(list)
					if tc.name == "truncated-list" {
						count++
					}
					body = map[string]any{"total_count": count, "jobs": list}
				default:
					repo := "relux-works/a2a-swarm"
					if tc.name == "wrong-repository" {
						repo = "other/repo"
					}
					state := "in_progress"
					if tc.name == "unknown-state" {
						state = "unknown"
					}
					body = map[string]any{"id": 2, "head_sha": sha, "head_branch": "v0.1.2", "path": ".github/workflows/shared-release.yml", "event": "push", "status": state, "conclusion": "", "repository": map[string]any{"id": 9, "full_name": repo}, "head_repository": map[string]any{"id": 9, "full_name": repo}}
				}
				json.NewEncoder(w).Encode(body)
			}))
			defer s.Close()
			g := githubAPI{s.URL, "fixture", s.Client()}
			obs, e := g.observeArtifact(context.Background(), 1, 2, "darwin-producer")
			if tc.want == "" {
				if e != nil || obs.JobID != 3 || obs.Commit != sha {
					t.Fatal(obs, e)
				}
			} else if e == nil || e.Error() != tc.want {
				t.Fatalf("want %s, got %v", tc.want, e)
			}
		})
	}
}
