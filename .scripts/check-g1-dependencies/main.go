// check-g1-dependencies verifies selected module commits by git ancestry.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const prefix = "github.com/relux-works/swarma-chain-lab/experiments/"

var required = []string{"d01e38f1c9665eccf1164b21680565d339b6f365", "e70a35a41dec"}

func main() {
	repo := flag.String("repo", "", "local chain-lab source clone (complete ancestry required)")
	flag.Parse()
	if err := run(*repo); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(repo string) error {
	if repo == "" {
		return fmt.Errorf("--repo is required")
	}
	cmd := exec.Command("go", "list", "-m", "-json", "all")
	raw, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("module graph unavailable: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	count := 0
	for dec.More() {
		var m struct {
			Path, Version string
			Replace       *struct{ Path, Version string }
		}
		if err := dec.Decode(&m); err != nil {
			return err
		}
		if !strings.HasPrefix(m.Path, prefix) {
			continue
		}
		if m.Replace != nil {
			return fmt.Errorf("%s: replacement forbidden", m.Path)
		}
		hash, err := revision(m.Version)
		if err != nil {
			return fmt.Errorf("%s: %w", m.Path, err)
		}
		out, err := exec.Command("git", "-C", repo, "rev-parse", "--verify", hash+"^{commit}").Output()
		if err != nil {
			return fmt.Errorf("%s: commit unavailable", m.Path)
		}
		exact := strings.TrimSpace(string(out))
		for _, ancestor := range required {
			if err := exec.Command("git", "-C", repo, "merge-base", "--is-ancestor", ancestor, exact).Run(); err != nil {
				return fmt.Errorf("%s %s: missing required ancestor %s", m.Path, m.Version, ancestor)
			}
		}
		fmt.Printf("%s %s %s ancestry=verified\n", m.Path, m.Version, exact)
		count++
	}
	if count < 7 {
		return fmt.Errorf("expected at least seven chain-lab modules, got %d", count)
	}
	return nil
}
func revision(version string) (string, error) {
	parts := strings.Split(version, "-")
	if len(parts) < 3 {
		return "", fmt.Errorf("pseudo-version required")
	}
	hash := parts[len(parts)-1]
	if len(hash) != 12 || strings.Trim(hash, "0123456789abcdef") != "" {
		return "", fmt.Errorf("invalid commit suffix")
	}
	// This known pre-#111 selection must never silently return to a consumer.
	if hash == "3baa201bafb6" {
		return "", fmt.Errorf("legacy pre-executor/freshness selection forbidden")
	}
	return hash, nil
}
