package originproducer

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/a2a-swarm/runorigin"
)

// Claim: the mapping is trusted only as a canonical, single-link regular file
// owned by the protected owner, not writable by anyone else, inside a directory
// with the same properties. Each weakened property refuses every Open; the
// untouched mapping opens beside it.
func TestMappingProtection(t *testing.T) {
	cases := []struct {
		name   string
		change func(t *testing.T, f *fixture)
	}{
		{"owner-mismatch", func(_ *testing.T, f *fixture) { f.producer.owner++ }},
		{"group-writable-file", func(t *testing.T, f *fixture) {
			if err := os.Chmod(f.mappingPath, 0660); err != nil {
				t.Fatal(err)
			}
		}},
		{"world-writable-file", func(t *testing.T, f *fixture) {
			if err := os.Chmod(f.mappingPath, 0646); err != nil {
				t.Fatal(err)
			}
		}},
		{"executable-file", func(t *testing.T, f *fixture) {
			if err := os.Chmod(f.mappingPath, 0700); err != nil {
				t.Fatal(err)
			}
		}},
		{"world-writable-directory", func(t *testing.T, f *fixture) {
			if err := os.Chmod(filepath.Dir(f.mappingPath), 0777); err != nil {
				t.Fatal(err)
			}
		}},
		{"hard-linked-file", func(t *testing.T, f *fixture) {
			if err := os.Link(f.mappingPath, f.mappingPath+".alias"); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlinked-file", func(t *testing.T, f *fixture) {
			real := f.mappingPath + ".real"
			if err := os.Rename(f.mappingPath, real); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(real, f.mappingPath); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlinked-directory", func(t *testing.T, f *fixture) {
			link := filepath.Join(f.root, "protected-link")
			if err := os.Symlink(filepath.Dir(f.mappingPath), link); err != nil {
				t.Fatal(err)
			}
			f.producer.mappingPath = filepath.Join(link, filepath.Base(f.mappingPath))
		}},
		{"relative-path", func(_ *testing.T, f *fixture) { f.producer.mappingPath = "origin-mapping.json" }},
		{"directory-instead-of-file", func(t *testing.T, f *fixture) {
			if err := os.Remove(f.mappingPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(f.mappingPath, 0700); err != nil {
				t.Fatal(err)
			}
		}},
		{"empty-file", func(_ *testing.T, f *fixture) { f.writeMapping(nil) }},
		{"oversize-file", func(_ *testing.T, f *fixture) { f.writeMapping(bytes.Repeat([]byte(" "), mappingLimit+1)) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			control, _ := f.session()
			control.Close()
			tc.change(t, f)
			s, err := f.producer.Open(context.Background(), f.selection)
			f.notOpened(s, err, ReasonMappingInvalid, 1)
		})
	}
}

// Claim: the production constructor trusts only a mapping owned by the
// protected owner (root). The same file that the fixture owner accepts is
// refused by New when it is owned by an ordinary account.
func TestNewRequiresProtectedOwner(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("the ordinary-owner negative needs a non-root test account")
	}
	f := newFixture(t)
	control, _ := f.session()
	control.Close()
	if p, err := newProducer(f.mappingPath, uint32(os.Getuid())); err != nil || p == nil {
		t.Fatal("valid control: fixture owner refused", err)
	}
	p, err := New(f.mappingPath)
	if err == nil || p != nil || ReasonOf(err) != ReasonMappingInvalid {
		t.Fatal("a mapping owned by an ordinary account was trusted")
	}
	if p, err = New(""); err == nil || p != nil {
		t.Fatal("an empty mapping path was trusted")
	}
}

// Claim: the mapping document is closed and exact. Unknown, duplicate,
// case-variant or missing members, trailing data, a wrong version, a zero
// principal, a relative path, a duplicated principal or identity and an empty
// agent list all refuse; the exact document parses.
func TestMappingDocumentIsClosed(t *testing.T) {
	f := newFixture(t)
	good, err := json.Marshal(f.mapping)
	if err != nil {
		t.Fatal(err)
	}
	if m, err := parseMapping(good); err != nil || len(m.Agents) != 1 || m.Agents[0] != f.mapping.Agents[0] || m.Launcher != fixtureLauncher {
		t.Fatal("valid control: exact mapping refused", err)
	}
	replace := func(from, to string) []byte {
		if strings.Count(string(good), from) != 1 {
			t.Fatalf("fixture text %q is not unique", from)
		}
		return []byte(strings.Replace(string(good), from, to, 1))
	}
	second := f.mapping.Agents[0]
	second.Identity = "carol"
	second.Input = runorigin.Principal{UID: 4300, Generation: 1}
	withAgents := func(agents ...agentEntry) []byte {
		raw, err := json.Marshal(mappingFile{Version: 1, Launcher: fixtureLauncher, Agents: agents})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if _, err = parseMapping(withAgents(f.mapping.Agents[0], second)); err != nil {
		t.Fatal("valid control: two distinct agents refused", err)
	}
	samePrincipal, sameIdentity := second, second
	samePrincipal.Input = fixtureInput
	sameIdentity.Identity = fixtureIdentity
	relative := f.mapping.Agents[0]
	relative.PolicyDir = "policy"
	unclean := f.mapping.Agents[0]
	unclean.ScopeRoot = f.scopes + "/../scopes"
	zeroGeneration := f.mapping.Agents[0]
	zeroGeneration.Input.Generation = 0
	multiline := f.mapping.Agents[0]
	multiline.Registration = "line\nbreak"
	cases := map[string][]byte{
		"unknown-member":         replace(`"version":1`, `"version":1,"extra":true`),
		"duplicate-member":       replace(`"version":1`, `"version":1,"version":1`),
		"case-variant-member":    replace(`"launcher"`, `"Launcher"`),
		"unknown-agent-member":   replace(`"identity":"alice"`, `"identity":"alice","admin":true`),
		"case-variant-identity":  replace(`"identity"`, `"Identity"`),
		"missing-launcher":       replace(`"launcher":{"uid":7001,"generation":3},`, ``),
		"principal-extra":        replace(`{"uid":7001,"generation":3}`, `{"uid":7001,"generation":3,"name":"x"}`),
		"trailing-data":          append(bytes.Clone(good), []byte(` {}`)...),
		"wrong-version":          replace(`"version":1`, `"version":2`),
		"zero-launcher-uid":      replace(`{"uid":7001,"generation":3}`, `{"uid":0,"generation":3}`),
		"negative-uid":           replace(`{"uid":7001,"generation":3}`, `{"uid":-1,"generation":3}`),
		"string-uid":             replace(`{"uid":7001,"generation":3}`, `{"uid":"7001","generation":3}`),
		"agents-not-a-list":      replace(`"agents":[`, `"agents":{"a":[`),
		"empty-agent-list":       withAgents(),
		"duplicate-principal":    withAgents(f.mapping.Agents[0], samePrincipal),
		"duplicate-identity":     withAgents(f.mapping.Agents[0], sameIdentity),
		"relative-policy-dir":    withAgents(relative),
		"unclean-scope-root":     withAgents(unclean),
		"zero-input-generation":  withAgents(zeroGeneration),
		"multiline-registration": withAgents(multiline),
		"not-json":               []byte("mapping"),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if m, err := parseMapping(raw); err == nil || len(m.Agents) != 0 {
				t.Fatal("a malformed mapping was accepted")
			}
		})
	}
}
