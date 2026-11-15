package releasecontroller

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func workflowContract(raw string) error {
	if !strings.Contains(raw, "  push:\n    tags: ['v*']") || strings.Contains(raw, "workflow_dispatch:") || strings.Contains(raw, "pull_request:") {
		return errors.New("workflow-tag-only")
	}
	if !strings.Contains(raw, "group: a2a-shared-production-release\n  cancel-in-progress: false") {
		return errors.New("workflow-concurrency")
	}
	if strings.Contains(raw, "secrets: inherit") {
		return errors.New("workflow-secret-boundary")
	}
	linux := strings.Split(strings.Split(raw, "\n  linux-producer:\n")[1], "\n  assemble-publish:\n")[0]
	if !strings.Contains(linux, "needs: [admission, darwin-producer]") {
		return errors.New("workflow-producer-order")
	}
	if strings.Contains(linux, "contents: write") {
		return errors.New("workflow-write-boundary")
	}
	consume := strings.Index(linux, "Consume immutable authenticated Darwin input BEFORE Linux production")
	build := strings.Index(linux, "Build and verify complete Linux outputs without publication")
	upload := strings.Index(linux, "id: bundle")
	if consume < 0 || build < 0 || upload < 0 || consume >= build || build >= upload {
		return errors.New("workflow-darwin-consumption-order")
	}
	if !strings.Contains(raw, "needs: [admission, darwin-producer, linux-producer]") {
		return errors.New("workflow-assembly-order")
	}
	if !strings.Contains(raw, "./cmd/a2a-distribution controller-admit") {
		return errors.New("workflow-production-hold-missing")
	}
	if !strings.Contains(raw, "./.github/workflows/darwin-release.yml") {
		return errors.New("workflow-native-reuse")
	}
	return nil
}

// The actual workflow is syntax-checked by pinned actionlint; these fixture
// plants independently narrow ordering, secret authority, triggers and the hold.
func TestSharedWorkflowSecurityContract(t *testing.T) {
	raw, e := os.ReadFile("../../.github/workflows/shared-release.yml")
	if e != nil {
		t.Fatal(e)
	}
	valid := string(raw)
	for _, tc := range []struct{ name, old, new, want string }{
		{"valid", "", "", ""},
		{"dispatch", "\non:\n", "\non:\n  workflow_dispatch:\n", "workflow-tag-only"},
		{"cancel", "cancel-in-progress: false", "cancel-in-progress: true", "workflow-concurrency"},
		{"native-not-ready", "needs: [admission, darwin-producer]", "needs: admission", "workflow-producer-order"},
		{"assembly-before-linux", "needs: [admission, darwin-producer, linux-producer]", "needs: [admission, darwin-producer]", "workflow-assembly-order"},
		{"linux-write", "  linux-producer:\n", "  linux-producer:\n    contents: write\n", "workflow-write-boundary"},
		{"secrets-inherit", "  linux-producer:\n", "  linux-producer:\n    secrets: inherit\n", "workflow-secret-boundary"},
		{"hold-missing", "./cmd/a2a-distribution controller-admit", "./cmd/a2a-distribution controller-event", "workflow-production-hold-missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := valid
			if tc.old != "" {
				if strings.Count(value, tc.old) != 1 {
					t.Fatal("plant not applied exactly once")
				}
				value = strings.Replace(value, tc.old, tc.new, 1)
			}
			e := workflowContract(value)
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
