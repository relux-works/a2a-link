package cg1

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/relux-works/a2a-swarm/internal/admission"
	"github.com/relux-works/swarma-chain-lab/experiments/grantcheck"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
)

// A separate process holds the real CG1 lock: the parent refuses promptly,
// then recovers without losing state when that exact child releases it.
func TestProcessSafety(t *testing.T) {
	if root := os.Getenv("AL1_TEST_LOCK_ROOT"); root != "" {
		s, e := durable.Open(root, "grantcheck.lock")
		if e != nil {
			t.Fatal(e)
		}
		defer s.Close()
		if e = os.WriteFile(filepath.Join(root, "ready"), []byte("ready"), 0600); e != nil {
			t.Fatal(e)
		}
		for until := time.Now().Add(3 * time.Second); time.Now().Before(until); {
			if _, e := os.Stat(filepath.Join(root, "release")); e == nil {
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatal("parent did not release child")
	}
	root := stateDir(t)
	core, e := grantcheck.New(grantcheck.Config{ConstructionProfile: "W", Identity: "alice", AgentName: "id/test-agent", LandlordName: "id/test-landlord", IssuerPubkey: xonly(1), StateDir: root, Now: func() time.Time { return time.Unix(500, 0) }, Node: nodeFunc(func(context.Context, string, ...any) (json.RawMessage, error) { return nil, errors.New("unused") })})
	if e != nil {
		t.Fatal(e)
	}
	c := &checker{core: core, own: xonly(3), identity: "alice", timeout: time.Second}
	d, e := c.Inbound(context.Background(), incoming(c))
	want(t, d, e, admission.Exchange, "no_grant", false)
	cmd := exec.Command(os.Args[0], "-test.run=^TestProcessSafety$")
	cmd.Env = append(os.Environ(), "AL1_TEST_LOCK_ROOT="+root)
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Logf("lock child pid=%d", cmd.Process.Pid)
	joined := false
	defer func() {
		if !joined {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()
	ready := false
	for until := time.Now().Add(time.Second); time.Now().Before(until); {
		if _, e := os.Stat(filepath.Join(root, "ready")); e == nil {
			ready = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !ready {
		t.Fatal("child lock not established")
	}
	d, e = c.Inbound(context.Background(), incoming(c))
	want(t, d, e, admission.Refused, "state_unavailable", true)
	if e = os.WriteFile(filepath.Join(root, "release"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	if e = cmd.Wait(); e != nil {
		t.Fatal("child release failed")
	}
	joined = true
	d, e = c.Inbound(context.Background(), incoming(c))
	want(t, d, e, admission.Exchange, "no_grant", false)
}
