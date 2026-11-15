package releasecontroller

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Pre-producer admission keeps the default hold and, with only readiness opened, independently requires the concrete unavailable-lease refusal.
func TestPreProducerAdmissionRequiresConcreteLease(t *testing.T) {
	t.Setenv("GITHUB_REPOSITORY", "relux-works/a2a-swarm")
	t.Setenv("GITHUB_EVENT_NAME", "push")
	t.Setenv("GITHUB_REF", "refs/tags/v0.1.2")
	want := Hold
	if ProductionReady {
		want = "custody-main-lease-contract-unavailable"
	}
	if e := AdmitWorkflow(); e == nil || e.Error() != want {
		t.Fatalf("pre-producer admission requires %s, got %v", want, e)
	}
}

// A readiness-only overlay passes the real admission regression; bypassing only the concrete lease consumer kills that same regression by its named assertion.
func TestPreProducerReadinessOnlyLeaseRegression(t *testing.T) {
	flow, e := filepath.Abs("flow.go")
	if e != nil {
		t.Fatal(e)
	}
	lease, e := filepath.Abs("production.go")
	if e != nil {
		t.Fatal(e)
	}
	read := func(path, needle, replacement string) string {
		t.Helper()
		raw, e := os.ReadFile(path)
		if e != nil || strings.Count(string(raw), needle) != 1 {
			t.Fatalf("control must apply once to %s: %v", filepath.Base(path), e)
		}
		return strings.Replace(string(raw), needle, replacement, 1)
	}
	ready := read(flow, "const ProductionReady = false", "const ProductionReady = true")
	bypass := read(lease, `return errors.New("custody-main-lease-contract-unavailable")`, "return nil")
	for _, mutant := range []bool{false, true} {
		name := "readiness-only"
		if mutant {
			name = "concrete-lease-bypass"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			write := func(name, content string) string {
				t.Helper()
				p := filepath.Join(dir, name)
				if e := os.WriteFile(p, []byte(content), 0600); e != nil {
					t.Fatal(e)
				}
				return p
			}
			replace := map[string]string{flow: write("flow.go", ready)}
			if mutant {
				replace[lease] = write("production.go", bypass)
			}
			raw, e := json.Marshal(map[string]any{"Replace": replace})
			if e != nil {
				t.Fatal(e)
			}
			overlay := write("overlay.json", string(raw))
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"), "test", "-p", "1", "-parallel", "2", "-count=1", "-timeout=1m", "-overlay", overlay, "-run", "^TestPreProducerAdmissionRequiresConcreteLease$", ".")
			out, e := cmd.CombinedOutput()
			if !mutant {
				if e != nil {
					t.Fatalf("readiness alone must retain the concrete lease refusal: %v\n%s", e, out)
				}
			} else {
				exit, ok := e.(*exec.ExitError)
				if !ok || exit.ExitCode() != 1 || !strings.Contains(string(out), "--- FAIL: TestPreProducerAdmissionRequiresConcreteLease") || !strings.Contains(string(out), "pre-producer admission requires custody-main-lease-contract-unavailable, got <nil>") {
					t.Fatalf("concrete-consumer mutant must fail the named assertion: %v\n%s", e, out)
				}
			}
			t.Logf("%s: expected child result observed\n%s", name, out)
		})
	}
}
