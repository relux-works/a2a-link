package darwinrelease

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
)

// PrepareBundle is the private producer boundary. It returns exactly the
// qualified six-file bundle, never a GitHub release. Admission runs before
// Prepare can read signing material; Prepare retains its original native path.
func PrepareBundle(ctx context.Context, root, tag, tagObject string) (string, error) {
	return prepareBundle(
		func() error { _, e := Admit(ctx, root, tag, tagObject); return e },
		func() (string, error) { return Prepare(ctx, root, tag, tagObject) },
		func(out string) error {
			sum := filepath.Join(out, "checksums.txt")
			c := exec.CommandContext(ctx, "cosign", "sign-blob", "--yes", "--output-signature", sum+".sig", "--output-certificate", sum+".pem", sum)
			c.Env = oidcEnvironment()
			if e := c.Run(); e != nil {
				return errors.New("private-checksum-sign")
			}
			return nil
		},
		func(out string) error { return verifySignedAssets(ctx, root, tag, out) },
	)
}

func prepareBundle(admit func() error, prepare func() (string, error), sign, verify func(string) error) (out string, err error) {
	if err = admit(); err != nil {
		return "", err
	}
	out, err = prepare()
	if err != nil {
		return "", err
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(out)
			out = ""
		}
	}()
	if err = sign(out); err != nil {
		return out, err
	}
	if err = admit(); err != nil {
		return out, err
	}
	if err = verify(out); err != nil {
		return out, err
	}
	return out, nil
}
