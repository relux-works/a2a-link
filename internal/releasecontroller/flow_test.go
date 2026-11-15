package releasecontroller

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/a2a-swarm/internal/sharedrelease"
)

type fixtureOps struct {
	calls          []string
	failure        string
	leases, admits int
}

func (f *fixtureOps) step(name string) error {
	f.calls = append(f.calls, name)
	if f.failure == name {
		return errors.New("planted-" + name)
	}
	return nil
}
func (f *fixtureOps) Admit(context.Context) error {
	f.admits++
	return f.step("admit-" + string(rune('0'+f.admits)))
}
func (f *fixtureOps) Lease(context.Context) error {
	f.leases++
	return f.step("lease-" + string(rune('0'+f.leases)))
}
func (f *fixtureOps) Assemble(context.Context) error         { return f.step("assemble") }
func (f *fixtureOps) SignManifest(context.Context) error     { return f.step("manifest") }
func (f *fixtureOps) DeriveCask(context.Context) error       { return f.step("cask") }
func (f *fixtureOps) Consumer(context.Context) error         { return f.step("brew") }
func (f *fixtureOps) CaptureCandidate(context.Context) error { return f.step("capture") }
func (f *fixtureOps) Publish(context.Context) (int64, error) { e := f.step("publish"); return 7, e }
func (f *fixtureOps) Readback(context.Context, int64) error  { return f.step("readback") }

// A valid fixture crosses every ordered stage once; each planted failure stops
// at its named boundary with no later operation or repeated publication.
func TestCombinedControllerOrderedRefusals(t *testing.T) {
	expected := []string{"admit-1", "lease-1", "assemble", "manifest", "cask", "brew", "capture", "admit-2", "lease-2", "publish", "readback", "admit-3", "lease-3"}
	b := sharedrelease.Binding{Tag: "v0.1.2", Commit: strings.Repeat("a", 40), TagObject: strings.Repeat("b", 40)}
	for stop := -1; stop < len(expected); stop++ {
		name := "valid"
		if stop >= 0 {
			name = expected[stop]
		}
		t.Run(name, func(t *testing.T) {
			f := &fixtureOps{}
			if stop >= 0 {
				f.failure = name
			}
			receipt, e := run(context.Background(), b, f)
			want := expected
			if stop >= 0 {
				want = expected[:stop+1]
				if e == nil || !strings.Contains(e.Error(), "planted-"+name) {
					t.Fatal("wrong refusal", e)
				}
			} else if e != nil || receipt.ReleaseID != 7 {
				t.Fatal(receipt, e)
			}
			if !reflect.DeepEqual(f.calls, want) {
				t.Fatal("order/partial-route violation", f.calls, want)
			}
		})
	}
}

// A tag-looking dispatch, branch push, foreign repository or prerelease never
// authorizes the shared path; the valid tag-event context still hits the hold.
func TestSharedTagEventAndRetainedHold(t *testing.T) {
	for _, tc := range []struct{ name, repo, event, ref, want string }{
		{"valid", "relux-works/a2a-swarm", "push", "refs/tags/v0.1.2", ""},
		{"dispatch", "relux-works/a2a-swarm", "workflow_dispatch", "refs/tags/v0.1.2", "shared-tag-event-required"},
		{"branch", "relux-works/a2a-swarm", "push", "refs/heads/main", "shared-tag-event-required"},
		{"foreign", "other/repo", "push", "refs/tags/v0.1.2", "shared-tag-event-required"},
		{"prerelease", "relux-works/a2a-swarm", "push", "refs/tags/v0.1.2-rc.1", "shared-stable-tag-required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := eventGate(tc.repo, tc.event, tc.ref)
			if tc.want == "" {
				if e != nil {
					t.Fatal(e)
				}
			} else if e == nil || e.Error() != tc.want {
				t.Fatal(e)
			}
		})
	}
	t.Setenv("GITHUB_REPOSITORY", "relux-works/a2a-swarm")
	t.Setenv("GITHUB_EVENT_NAME", "push")
	t.Setenv("GITHUB_REF", "refs/tags/v0.1.2")
	if e := AdmitWorkflow(); e == nil || e.Error() != Hold {
		t.Fatal("partial route escaped hold", e)
	}
}

// The fixture trace is explicitly non-production evidence for every stage and
// stopping boundary; it never signs, builds Darwin, creates a tag or publishes.
func TestControllerDryRunEvidence(t *testing.T) {
	path := os.Getenv("A2A_CONTROLLER_DRY_REPORT")
	if path == "" {
		t.Skip("hosted dry-run report not requested")
	}
	b := sharedrelease.Binding{Tag: "v0.1.2", Commit: strings.Repeat("a", 40), TagObject: strings.Repeat("b", 40)}
	f := &fixtureOps{}
	receipt, e := run(context.Background(), b, f)
	if e != nil {
		t.Fatal(e)
	}
	report := map[string]any{"trust": "fixture-control-flow-only", "not_production_authority": true, "receipt": receipt, "operations": f.calls, "limits": "simulated ports; consumer/native/package/byte checks have separate real hosted witnesses"}
	raw, e := json.MarshalIndent(report, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, append(raw, byte(10)), 0600); e != nil {
		t.Fatal(e)
	}
}
