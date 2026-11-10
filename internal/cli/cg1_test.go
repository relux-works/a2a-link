package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/a2a-swarm/internal/config"
	"github.com/relux-works/a2a-swarm/internal/matrix"
)

// The existing golden scenarios now compare against frozen e68c9a10 output,
// independently of the candidate's nil-policy control. Do not regenerate here.
func assertBaseFixture(t *testing.T, name string, got []byte) {
	t.Helper()
	want, e := os.ReadFile(filepath.Join("testdata", "admission-base", name))
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("none diverged from e68c9a10 fixture %s", name)
	}
}

// The CLI imports the actual registration but its Matrix-only session cannot
// construct it, read CG1 config or reach any message/media operation.
func TestCG1MatrixStartupRefuses(t *testing.T) {
	a := NewApp()
	a.Stdout, a.Stderr = io.Discard, io.Discard
	s := &session{app: a, paths: config.Paths{Base: t.TempDir()}, name: "alice", creds: config.Credentials{AdmissionPolicy: "cg1"}, client: matrix.New("https://example.invalid", "")}
	err := s.openAdmission()
	if err == nil || err.Error() != "admission: policy_startup" || s.admission != nil || s.client.BeforeSend != nil || len(a.admissionSessions) != 0 {
		t.Fatalf("Matrix constructed CG1: %v", err)
	}
	if _, e := os.Stat(filepath.Join(s.paths.Base, "admission", "alice", "cg1-state")); !os.IsNotExist(e) {
		t.Fatal("Matrix touched CG1 state")
	}
}
