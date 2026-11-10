// Opt-in bounded mutation controls. Requires an exact clean signed checkout and
// all HOME/cache/temp paths under the absolute caller-owned -task-root.
package main

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type plant struct{ Name, File, Old, New, Package, Test, Failure string }
type result struct {
	Name            string
	Args            []string
	Cwd             string
	PID, Exit       int
	ExpectedFailure string
}

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	var root, out string
	flag.StringVar(&root, "task-root", "", "absolute owned scratch root")
	flag.StringVar(&out, "out", "", "fresh directory inside task root")
	flag.Parse()
	physical, e := filepath.EvalSymlinks(root)
	if e != nil || !filepath.IsAbs(root) || physical != root {
		return fmt.Errorf("invalid task root")
	}
	inside := func(p string) bool {
		r, e := filepath.Rel(root, p)
		return e == nil && filepath.IsAbs(p) && r != ".." && !strings.HasPrefix(r, ".."+string(os.PathSeparator))
	}
	if !inside(out) {
		return fmt.Errorf("output outside task root")
	}
	for _, name := range []string{"HOME", "USERPROFILE", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "GOCACHE", "GOMODCACHE", "GOPATH", "TMPDIR", "TMP", "TEMP"} {
		p := os.Getenv(name)
		actual, e := filepath.EvalSymlinks(p)
		if e != nil || actual != p || !inside(p) {
			return fmt.Errorf("unsafe isolated variable %s", name)
		}
	}
	src, e := os.Getwd()
	if e != nil {
		return e
	}
	status, e := exec.Command("git", "status", "--porcelain").Output()
	if e != nil || len(status) != 0 {
		return fmt.Errorf("source must be clean")
	}
	if e = os.Mkdir(out, 0700); e != nil {
		return e
	}
	archive, e := exec.Command("git", "archive", "HEAD").Output()
	if e != nil {
		return e
	}
	head, e := exec.Command("git", "rev-parse", "HEAD").Output()
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(out, "source-head"), head, 0600); e != nil {
		return e
	}
	plants := []plant{
		{"policy", "internal/al3smoke/smoke.go", `c.Policy != "cg1"`, `false`, `./internal/al3smoke`, `^TestConfigurationBoundary$`, `unguarded policy accepted`},
		{"relay", "internal/al3smoke/smoke.go", `urls[0] != relayURL`, `false`, `./internal/al3smoke`, `^TestConfigurationBoundary$`, `relay drift accepted`},
		{"short-write", "internal/al3smoke/smoke.go", `n != len(raw)`, `n < 0`, `./internal/al3smoke`, `^TestOutputShortWrite$`, `short output accepted`},
		{"sender", "internal/al3smoke/transcript.go", `row.Sender != from`, `row.Sender != from && false`, `./internal/al3smoke`, `^TestTranscriptRefusals$`, `invalid transcript normalized sender`},
		{"correlation", "internal/al3smoke/transcript.go", `bRows[2].ID != aRows[2].ID`, `false`, `./internal/al3smoke`, `^TestTranscriptRefusals$`, `invalid transcript normalized id`},
		{"mailbox", "internal/nostrsession/session.go", `if _, e := mb.Append(entries); e != nil {`, `if _, e := 0, error(nil); e != nil {`, `./internal/nostrsession`, `^TestMailboxBeforeCursorAndReceipt$`, `wrong crash mailbox`},
		{"premature-receipt", "internal/nostrsession/session.go", `if e := output(records); e != nil {`, `_, _ = mb.Receive(ids)
        if e := output(records); e != nil {`, `./internal/nostrsession`, `^TestAL3FailedOutputRetainsMailbox$`, `failed output receipted`},
	}
	records := []result{}
	execute := func(name, cwd, pkg, test, failure string) error {
		args := []string{"test", "-mod=readonly", "-count=1", "-timeout", "90s", "-v", pkg, "-run", test}
		cmd := exec.Command("go", args...)
		cmd.Dir = cwd
		var log bytes.Buffer
		cmd.Stdout = &log
		cmd.Stderr = &log
		if e := cmd.Start(); e != nil {
			return e
		}
		pid := cmd.Process.Pid
		e := cmd.Wait()
		code := cmd.ProcessState.ExitCode()
		records = append(records, result{name, args, cwd, pid, code, failure})
		_ = os.WriteFile(filepath.Join(out, name+".log"), log.Bytes(), 0600)
		raw, _ := json.MarshalIndent(records, "", "  ")
		_ = os.WriteFile(filepath.Join(out, "results.json"), raw, 0600)
		if failure == "" {
			if e != nil {
				return fmt.Errorf("baseline failed %s", name)
			}
		} else if code != 1 || !bytes.Contains(log.Bytes(), []byte(failure)) || bytes.Contains(log.Bytes(), []byte("build failed")) || bytes.Contains(log.Bytes(), []byte("panic:")) {
			return fmt.Errorf("plant did not cause intended test failure %s", name)
		}
		fmt.Println(name, "PASS")
		return nil
	}
	for _, group := range []struct{ name, pkg, test string }{{"baseline-smoke", "./internal/al3smoke", "."}, {"baseline-storage", "./internal/nostrsession", "TestMailboxBeforeCursorAndReceipt|TestAL3FailedOutputRetainsMailbox"}} {
		if e = execute(group.name, src, group.pkg, group.test, ""); e != nil {
			return e
		}
	}
	for _, p := range plants {
		work := filepath.Join(out, p.Name)
		if e = os.Mkdir(work, 0700); e != nil {
			return e
		}
		tr := tar.NewReader(bytes.NewReader(archive))
		for {
			h, e := tr.Next()
			if e == io.EOF {
				break
			}
			if e != nil {
				return e
			}
			path := filepath.Join(work, h.Name)
			rel, _ := filepath.Rel(work, path)
			if strings.HasPrefix(rel, "..") || filepath.IsAbs(h.Name) {
				return fmt.Errorf("unsafe archive")
			}
			switch h.Typeflag {
			case tar.TypeXGlobalHeader:
				continue // git archive commit metadata, not a filesystem member
			case tar.TypeDir:
				if e = os.MkdirAll(path, 0700); e != nil {
					return e
				}
			case tar.TypeReg:
				if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
					return e
				}
				raw, e := io.ReadAll(tr)
				if e != nil {
					return e
				}
				if e = os.WriteFile(path, raw, os.FileMode(h.Mode)); e != nil {
					return e
				}
			default:
				return fmt.Errorf("unsupported archive member")
			}
		}
		path := filepath.Join(work, p.File)
		raw, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		if bytes.Count(raw, []byte(p.Old)) != 1 {
			return fmt.Errorf("plant count %s", p.Name)
		}
		changed := bytes.Replace(raw, []byte(p.Old), []byte(p.New), 1)
		if e = os.WriteFile(path, changed, 0600); e != nil {
			return e
		}
		if e = execute(p.Name, work, p.Package, p.Test, p.Failure); e != nil {
			return e
		}
	}
	return nil
}
