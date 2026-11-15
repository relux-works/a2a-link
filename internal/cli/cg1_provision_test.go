package cli

import (
	"context"
	"io"
	"testing"
)

// Claim: provisioning requires its exact explicit operator form and refuses daemon-dispatched calls before opening any identity or proof.
func TestCG1ProvisionCommandBoundary(t *testing.T) {
	for _, args := range [][]string{nil, {"provision"}, {"provision", "--proof"}, {"provision", "--proof", ""}, {"provision", "--proof", "proof", "--executor", "claim"}, {"inject", "--proof", "proof"}} {
		a := NewApp()
		a.Stdout, a.Stderr = io.Discard, io.Discard
		err := cmdCG1(context.Background(), a, args)
		if _, ok := err.(usageError); !ok {
			t.Fatalf("ambiguous operator form: %v", err)
		}
	}
	a := NewApp()
	a.daemonEngine = true
	err := cmdCG1(context.Background(), a, []string{"provision", "--proof", "proof"})
	r, ok := err.(*admissionRefusal)
	if !ok || r.reason != "denied" {
		t.Fatalf("daemon provisioning not refused: %v", err)
	}
}

// Claim: an ordinary none-policy identity cannot provision or send a Matrix event through this operator command.
func TestCG1ProvisionRequiresProtectedPolicy(t *testing.T) {
	e := newEnv(t)
	e.agent("alice")
	before := e.eventCount()
	e.as("alice", "cg1", "provision", "--proof", "missing").failsWith(t, ExitError, "policy_invalid")
	if e.eventCount() != before {
		t.Fatal("provisioning sent Matrix event")
	}
}
