//go:build linux

package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSourceOriginNarrowingPlants proves the named tests detect three removed gates; overlays leave the source untouched and restored controls must pass.
func TestSourceOriginNarrowingPlants(t *testing.T) {
	if os.Getenv("A2A_RUN_ORIGIN_PLANTS") != "1" {
		t.Skip("opt-in Source gate-removal plants")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "internal/daemon/origin_linux.go")
	original, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	plants := []struct{ name, from, to, test, witness string }{
		{"incarnation",
			"r.incarnation != s.incarnation || // incarnation gate\n\t\t\t\tr.incarnation != old.prepared.SourceIncarnation || ",
			"", "^TestSourceOriginIncarnationBinding$", "TestSourceOriginIncarnationBinding/stale-on-live-record"},
		{"capability", "return originWork{err: runorigin.ErrNotSupported}", "return originWork{}", "^TestSourceOriginCapability$", "TestSourceOriginCapability/stock-refusal"},
		{"peer", "err != nil || uid != s.cfg.Launcher.UID", "err != nil", "^TestSourceOriginPeerGate$", "TestSourceOriginPeerGate/uid"},
	}
	for _, plant := range plants {
		t.Run(plant.name, func(t *testing.T) {
			if strings.Count(string(original), plant.from) != 1 {
				t.Fatal("plant no longer applies exactly once")
			}
			mutated := bytes.Replace(original, []byte(plant.from), []byte(plant.to), 1)
			dir := t.TempDir()
			replacement := filepath.Join(dir, "origin_linux.go")
			if err := os.WriteFile(replacement, mutated, 0600); err != nil {
				t.Fatal(err)
			}
			overlay, _ := json.Marshal(map[string]any{"Replace": map[string]string{source: replacement}})
			overlayPath := filepath.Join(dir, "overlay.json")
			if err := os.WriteFile(overlayPath, overlay, 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{"test", "-overlay", overlayPath, "./internal/daemon", "-run", plant.test, "-count=1", "-v"}
			output, err := originPlantCommand(root, args...)
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 1 || !strings.Contains(string(output), "--- FAIL: "+plant.witness) || bytes.Contains(output, []byte("panic:")) || bytes.Contains(output, []byte("build failed")) {
				t.Fatalf("plant needs intended named failure, err=%v\n%s", err, output)
			}
			t.Logf("mutant=%s sha256=%x exit=1 killed-by=%s\n%s", plant.name, sha256.Sum256(mutated), plant.witness, output)
			// Running without an overlay restores the exact original source identity.
			output, err = originPlantCommand(root, "test", "./internal/daemon", "-run", plant.test, "-count=1", "-v")
			if err != nil {
				t.Fatalf("restored control failed: %v\n%s", err, output)
			}
			t.Logf("restored=%s sha256=%x exit=0\n%s", plant.name, sha256.Sum256(original), output)
			after, err := os.ReadFile(source)
			if err != nil || !bytes.Equal(after, original) {
				t.Fatal("plant changed original source")
			}
		})
	}
}

func originPlantCommand(root string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var cmd *exec.Cmd
	if envFile := os.Getenv("A2A_ORIGIN_GO_ENV"); envFile != "" {
		// Positional arguments preserve paths literally; no shell interpolation of source.
		argv := append([]string{"-c", `. "$1" && shift && exec go "$@"`, "origin-plant", envFile}, args...)
		cmd = exec.CommandContext(ctx, "bash", argv...)
	} else {
		cmd = exec.CommandContext(ctx, "go", args...)
	}
	cmd.Dir = root
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return output, fmt.Errorf("plant command deadline: %w", ctx.Err())
	}
	return output, err
}
