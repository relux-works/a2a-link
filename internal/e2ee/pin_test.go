//go:build darwin || linux

package e2ee

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// pinFixture provisions a host-shaped trust root in a canonical, test-owned
// directory and returns the policy trusting the test UID.
func pinFixture(t testing.TB) (PinPolicy, *CrossSigning, string, string) {
	t.Helper()
	policy := PinPolicy{Base: filepath.Join(testRoot(t), "e2ee-trust"), TrustedUID: os.Getuid()}
	owner, _ := newCrossSigning(t, ownerMXID)
	binding := strings.Repeat("c", 64)
	path, err := PinPath(policy, binding, "agents", agentMXID, "agent")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	return policy, owner, binding, path
}

func writePin(t testing.TB, path string, raw []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, raw, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// checkUnownedPinRefused is the killer assertion for the ownership gate: a pin
// not owned by the trusted UID must be ErrPinUnsafe.
func checkUnownedPinRefused(policy PinPolicy, binding string) error {
	_, err := ReadHostPin(policy, binding, "agents", agentMXID, agentDev, "agent")
	if err != ErrPinUnsafe {
		return fmt.Errorf("pin owned by another UID not refused: %v", err)
	}
	return nil
}

// The reader accepts a trusted-UID-owned 0644 artifact under non-writable
// directories and refuses: an absent pin, an agent-writable file or directory,
// a symlinked file or directory component, an oversize file, a pin owned by a
// UID other than the trusted one, and a wrong name selecting another file.
func TestReadHostPinSafety(t *testing.T) {
	policy, owner, binding, path := pinFixture(t)
	valid := renderPin(t, owner, binding, 3, nil)
	if _, err := ReadHostPin(policy, binding, "agents", agentMXID, agentDev, "agent"); err != ErrPinUnavailable {
		t.Fatal("absent pin", err)
	}
	writePin(t, path, valid, 0644)
	pin, err := ReadHostPin(policy, binding, "agents", agentMXID, agentDev, "agent")
	if err != nil || pin.Revision != 3 || pin.Owner != ownerMXID || pin.Record.MasterPublicKey != owner.Master().Public {
		t.Fatal("valid pin", err)
	}
	if err = VerifyOwnerChain(pin); err != nil {
		t.Fatal("valid chain", err)
	}
	if _, err = ReadHostPin(policy, binding, "agents", agentMXID, agentDev, "other"); err != ErrPinUnavailable {
		t.Fatal("other name", err)
	}
	t.Run("agent-writable-file", func(t *testing.T) {
		writePin(t, path, valid, 0666)
		defer writePin(t, path, valid, 0644)
		if _, err := ReadHostPin(policy, binding, "agents", agentMXID, agentDev, "agent"); err != ErrPinUnsafe {
			t.Fatal(err)
		}
	})
	t.Run("agent-writable-directory", func(t *testing.T) {
		dir := filepath.Dir(path)
		if err := os.Chmod(dir, 0777); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(dir, 0700)
		if _, err := ReadHostPin(policy, binding, "agents", agentMXID, agentDev, "agent"); err != ErrPinUnsafe {
			t.Fatal(err)
		}
	})
	t.Run("symlinked-file", func(t *testing.T) {
		target := filepath.Join(testRoot(t), "elsewhere.pin.json")
		writePin(t, target, valid, 0644)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		defer writePin(t, path, valid, 0644)
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(path)
		if _, err := ReadHostPin(policy, binding, "agents", agentMXID, agentDev, "agent"); err != ErrPinUnsafe {
			t.Fatal(err)
		}
	})
	t.Run("symlinked-directory", func(t *testing.T) {
		otherBinding := strings.Repeat("e", 64)
		otherPath, _ := PinPath(policy, otherBinding, "agents", agentMXID, "agent")
		if err := os.Symlink(filepath.Dir(filepath.Dir(filepath.Dir(path))), filepath.Dir(filepath.Dir(filepath.Dir(otherPath)))); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadHostPin(policy, otherBinding, "agents", agentMXID, agentDev, "agent"); err != ErrPinUnsafe {
			t.Fatal(err)
		}
	})
	t.Run("oversize", func(t *testing.T) {
		writePin(t, path, append(append([]byte(nil), valid...), []byte(strings.Repeat(" ", MaxPin))...), 0644)
		defer writePin(t, path, valid, 0644)
		if _, err := ReadHostPin(policy, binding, "agents", agentMXID, agentDev, "agent"); err != ErrCapacity {
			t.Fatal(err)
		}
	})
	t.Run("not-trusted-owner", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root owns everything; the root-agent refusal is tested separately")
		}
		if err := checkUnownedPinRefused(PinPolicy{Base: policy.Base, TrustedUID: 0}, binding); err != nil {
			t.Fatal(err)
		}
	})
	if _, err := ReadHostPin(policy, binding, "agents", agentMXID, agentDev, "agent"); err != nil {
		t.Fatal("valid pin after negatives", err)
	}
	if _, err := PinPath(policy, binding, "agents", agentMXID, "../agent"); err != ErrInvalid {
		t.Fatal("path traversal admitted", err)
	}
	if HostPinPolicy().TrustedUID != 0 || !filepath.IsAbs(HostPinPolicy().Base) {
		t.Fatal("production policy is not root-anchored")
	}
}

// Plant control: with the ownership predicate bypassed, a pin owned by the test
// UID is accepted under a root-trusting policy, so the ownership negative fails;
// control: the predicate restored, the same assertion passes.
func TestPinOwnershipGatePlantKilled(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root owns the fixture; the ownership plant needs an unprivileged UID")
	}
	policy, owner, binding, path := pinFixture(t)
	writePin(t, path, renderPin(t, owner, binding, 1, nil), 0644)
	rootPolicy := PinPolicy{Base: policy.Base, TrustedUID: 0}
	if err := checkUnownedPinRefused(rootPolicy, binding); err != nil {
		t.Fatal("killer assertion must pass before the plant:", err)
	}
	original := pinOwnerCheck
	pinOwnerCheck = func(*unix.Stat_t, int) bool { return true }
	defer func() { pinOwnerCheck = original }()
	if checkUnownedPinRefused(rootPolicy, binding) == nil {
		t.Fatal("plant survived: bypassed pin ownership check was not detected")
	}
	pinOwnerCheck = original
	if err := checkUnownedPinRefused(rootPolicy, binding); err != nil {
		t.Fatal("restored predicate control:", err)
	}
}
