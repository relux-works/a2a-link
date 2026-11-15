package releasecontroller

import (
	"encoding/json"
	"testing"
	"time"
)

// Protection is based on enforced consumer rules and complete bypass/history
// evidence; same-name/evaluate/current-user-only and move-and-restore plants fail.
func TestCustodyProtectionConsumer(t *testing.T) {
	for _, target := range []string{"branch", "tag"} {
		for _, kind := range []string{"valid", "evaluate", "bypass", "bypass-hidden", "wrong-ref", "exclude", "update-missing", "fetch-merge-exception", "history-denied", "move-and-restore", "late-lock"} {
			t.Run(target+"/"+kind, func(t *testing.T) {
				ref := "refs/tags/v0.1.2"
				rules := []any{map[string]any{"type": "update"}, map[string]any{"type": "deletion"}}
				if target == "branch" {
					ref = "refs/heads/main"
					rules = append(rules, map[string]any{"type": "non_fast_forward"})
				}
				p := map[string]any{"id": 7, "target": target, "source": "relux-works/a2a-swarm", "source_type": "Repository", "enforcement": "active", "bypass_actors": []any{}, "conditions": map[string]any{"ref_name": map[string]any{"include": []string{ref}, "exclude": []string{}}}, "rules": rules}
				switch kind {
				case "evaluate":
					p["enforcement"] = "evaluate"
				case "bypass":
					p["bypass_actors"] = []any{map[string]any{"actor_id": 1, "actor_type": "RepositoryRole"}}
				case "bypass-hidden":
					delete(p, "bypass_actors")
					p["current_user_can_bypass"] = "never"
				case "wrong-ref":
					p["conditions"] = map[string]any{"ref_name": map[string]any{"include": []string{"refs/heads/other"}, "exclude": []string{}}}
				case "exclude":
					p["conditions"] = map[string]any{"ref_name": map[string]any{"include": []string{ref}, "exclude": []string{ref}}}
				case "update-missing":
					p["rules"] = rules[1:]
				case "fetch-merge-exception":
					rules[0] = map[string]any{"type": "update", "parameters": map[string]any{"update_allows_fetch_and_merge": true}}
				}
				raw, e := json.Marshal(p)
				if e != nil {
					t.Fatal(e)
				}
				history := []byte(`[{"version_id":1,"updated_at":"2026-11-15T01:00:00Z"}]`)
				switch kind {
				case "history-denied":
					history = []byte(`{"status":"403"}`)
				case "move-and-restore":
					history = []byte(`[{"version_id":3,"updated_at":"2026-11-15T02:01:00Z"},{"version_id":2,"updated_at":"2026-11-15T02:00:00Z"}]`)
				case "late-lock":
					history = []byte(`[{"version_id":1,"updated_at":"2026-11-15T03:00:00Z"}]`)
				}
				e = CheckProtection(raw, history, target, ref, 7, 1, time.Date(2026, 11, 15, 2, 0, 0, 0, time.UTC))
				if kind == "valid" {
					if e != nil {
						t.Fatal(e)
					}
				} else if e == nil || e.Error() != map[string]string{"evaluate": "custody-protection-binding", "bypass": "custody-protection-bypass-proof", "bypass-hidden": "custody-protection-bypass-proof", "wrong-ref": "custody-protection-ref", "exclude": "custody-protection-ref", "update-missing": "custody-protection-rules", "fetch-merge-exception": "custody-protection-update-exception", "history-denied": "custody-protection-history-required", "move-and-restore": "custody-protection-changed", "late-lock": "custody-protection-changed"}[kind] {
					t.Fatal("unsafe protection accepted", e)
				}
			})
		}
	}
}
