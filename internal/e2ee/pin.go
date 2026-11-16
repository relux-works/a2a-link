//go:build darwin || linux

package e2ee

import (
	"errors"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// pinOwnerCheck decides whether a stat'd object is owned by the trusted UID.
// A variable only so controls can plant an ownership bypass and prove the
// unsafe-pin negatives detect it; production never reassigns it.
var pinOwnerCheck = func(st *unix.Stat_t, trusted int) bool { return int(st.Uid) == trusted }

func pinStatSafe(f *os.File, trusted int, directory, anchored bool) error {
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil {
		return ErrPinUnsafe
	}
	want := uint32(unix.S_IFREG)
	if directory {
		want = unix.S_IFDIR
	}
	mode := uint32(st.Mode)
	if mode&unix.S_IFMT != want {
		return ErrPinUnsafe
	}
	if anchored {
		// Under the trust root every object is the provisioning authority's and
		// not writable by anybody else; an agent-writable bit is an unsafe pin.
		if !pinOwnerCheck(&st, trusted) || mode&0022 != 0 {
			return ErrPinUnsafe
		}
		return nil
	}
	// Above the trust root: root or the authority owns each ancestor; a
	// root-owned sticky directory (temp roots) cannot replace a child path.
	rootOwned := st.Uid == 0
	if !rootOwned && !pinOwnerCheck(&st, trusted) {
		return ErrPinUnsafe
	}
	if mode&0022 != 0 && !(rootOwned && mode&unix.S_ISVTX != 0) {
		return ErrPinUnsafe
	}
	return nil
}

// ReadHostPin opens the artifact without following any symlink, validates
// ownership and modes of every component from / down to the file, bounds the
// size, then applies parseHostPin. It never writes, creates or repairs.
func ReadHostPin(policy PinPolicy, binding, class, mxid, device, name string) (HostPin, error) {
	path, err := PinPath(policy, binding, class, mxid, name)
	if err != nil {
		return HostPin{}, err
	}
	if policy.TrustedUID == 0 && os.Geteuid() == 0 {
		// A root agent can write any pin: the artifact protects nothing then.
		return HostPin{}, ErrPinUnsafe
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	anchor := len(strings.Split(strings.TrimPrefix(policy.Base, "/"), "/"))
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return HostPin{}, ErrPinUnsafe
	}
	current := os.NewFile(uintptr(fd), "e2ee-pin-dir")
	defer func() { current.Close() }()
	for i, part := range parts {
		// current is the directory that contains part; components strictly
		// below the trust root are anchored to the trusted UID.
		if err := pinStatSafe(current, policy.TrustedUID, true, i > anchor); err != nil {
			return HostPin{}, err
		}
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		} else {
			flags |= unix.O_NONBLOCK
		}
		next, err := unix.Openat(int(current.Fd()), part, flags, 0)
		if errors.Is(err, unix.ENOENT) {
			return HostPin{}, ErrPinUnavailable
		}
		if err != nil {
			return HostPin{}, ErrPinUnsafe
		}
		current.Close()
		current = os.NewFile(uintptr(next), "e2ee-pin")
	}
	if err := pinStatSafe(current, policy.TrustedUID, false, true); err != nil {
		return HostPin{}, err
	}
	raw, err := io.ReadAll(io.LimitReader(current, MaxPin+1))
	if err != nil {
		return HostPin{}, ErrPinUnsafe
	}
	return parseHostPin(raw, binding, mxid, device)
}
