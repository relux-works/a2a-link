package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/a2a-swarm/internal/config"
)

// Proves only original registration refusals are definite; redirects retain the exact recovery journal/password without another attempt or credential publication.
func TestReviewRegistrationRefusalProvenance(t *testing.T) {
	for _, code := range []string{"M_UNKNOWN_TOKEN", "M_MISSING_TOKEN", "M_FORBIDDEN"} {
		for _, mode := range []string{"original", "redirected"} {
			t.Run(code+"/"+mode, func(t *testing.T) {
				f := newNamedFixture(t, false)
				profile := f.r.Profiles["alpha"]
				binding, err := profile.Binding("alice", false)
				if err != nil {
					t.Fatal(err)
				}
				passwordRef := config.SecretReference{Service: profile.Store.PasswordService, Account: binding.UserID}
				tokenRef := config.SecretReference{Service: profile.Store.AccessTokenService, Account: binding.UserID}
				var password string
				checkPassword := func(first bool) {
					t.Helper()
					f.store.mu.Lock()
					defer f.store.mu.Unlock()
					value := f.store.items[passwordRef]
					created := 0
					for _, ref := range f.store.creates {
						if ref == passwordRef {
							created++
						}
					}
					if first {
						password = value
					}
					if password == "" || value != password || created != 1 {
						t.Fatal("recovery password missing, changed or recreated")
					}
				}
				calls := 0
				a := f.app()
				a.HTTP = &http.Client{Transport: memberReadTransport(func(r *http.Request) (*http.Response, error) {
					calls++
					if calls == 1 {
						if r.Method != "POST" || r.URL.String() != profile.URL+"/_matrix/client/v3/register" {
							t.Fatal("wrong original registration request")
						}
						checkPassword(true)
						if mode == "redirected" {
							response := propertyCLIReply(r, http.StatusSeeOther, `{}`)
							response.Header.Set("Location", profile.URL+"/registration-refusal")
							return response, nil
						}
					} else if calls != 2 || mode != "redirected" || r.Method != "GET" || r.URL.String() != profile.URL+"/registration-refusal" {
						t.Fatal("unexpected request or retry")
					}
					status := http.StatusUnauthorized
					if code == "M_FORBIDDEN" {
						status = http.StatusForbidden
					}
					return propertyCLIReply(r, status, fmt.Sprintf(`{"errcode":%q,"error":"private-refusal"}`, code)), nil
				})}
				args := []string{"--profile", "alpha", "register", "alice", "--authorize-registration"}
				if a.Run(t.Context(), args) != ExitError {
					t.Fatal("registration refusal succeeded")
				}
				wantCalls := 1
				wantStage := "remote-rejected"
				wantStatus := 401
				wantCode := code
				if code == "M_FORBIDDEN" {
					wantStatus = 403
				}
				if mode == "redirected" {
					wantCalls = 2
					wantStage = "remote-outcome-ambiguous"
					wantStatus = 0
					wantCode = ""
				}
				if calls != wantCalls {
					t.Fatalf("request count=%d want=%d", calls, wantCalls)
				}
				checkPassword(false)
				paths := f.paths("alpha", false)
				journalPath := filepath.Join(paths.Base, "registration.pending.json")
				before, err := os.ReadFile(journalPath)
				if err != nil {
					t.Fatal(err)
				}
				var journal registrationJournal
				if err = json.Unmarshal(before, &journal); err != nil {
					t.Fatal(err)
				}
				if journal.Stage != wantStage || journal.HTTPStatus != wantStatus || journal.ErrCode != wantCode {
					t.Errorf("refusal classification stage=%s status=%d code=%s; want stage=%s status=%d code=%s", journal.Stage, journal.HTTPStatus, journal.ErrCode, wantStage, wantStatus, wantCode)
				}
				if !strings.Contains(f.err.String(), wantStage) {
					t.Errorf("diagnosis lacks intended stage %s", wantStage)
				}
				again := f.app()
				again.HTTP = a.HTTP
				if again.Run(t.Context(), args) != ExitError || calls != wantCalls {
					t.Fatal("reinvocation repeated a remote attempt")
				}
				after, err := os.ReadFile(journalPath)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("reinvocation changed retained journal")
				}
				checkPassword(false)
				if _, err = os.Lstat(paths.AgentFile("alice")); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("refusal published credential metadata")
				}
				f.store.mu.Lock()
				_, stored := f.store.items[tokenRef]
				createdToken := false
				for _, ref := range f.store.creates {
					createdToken = createdToken || ref == tokenRef
				}
				f.store.mu.Unlock()
				if stored || createdToken {
					t.Fatal("refusal created or stored an access token")
				}
				output := f.out.String() + f.err.String()
				for _, secret := range []string{password, "private-refusal", "isolated-bootstrap"} {
					if strings.Contains(output, secret) {
						t.Fatal("private material leaked")
					}
				}
			})
		}
	}
}
