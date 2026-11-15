package matrix

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// Proves second-stage token refusals retain ErrAuth without a password-rejection claim, beside genuine password refusal and successful UIA controls.
func TestReviewDeactivateSecondStageClassification(t *testing.T) {
	for _, code := range []string{"M_UNKNOWN_TOKEN", "M_MISSING_TOKEN", "M_FORBIDDEN", "success"} {
		t.Run(code, func(t *testing.T) {
			c := New("https://fixture.invalid", "fixture-token")
			calls := 0
			c.HTTP.Transport = propertyTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != "POST" || r.URL.String() != "https://fixture.invalid/_matrix/client/v3/account/deactivate" || calls > 2 {
					t.Fatal("wrong request or retry")
				}
				raw, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				if calls == 1 {
					if string(raw) != "{}" {
						t.Fatal("unexpected first-stage content")
					}
					return propertyReply(r, 401, `{"session":"review-session","flows":[{"stages":["m.login.password"]}]}`), nil
				}
				var request struct {
					Auth struct {
						Type       string `json:"type"`
						Session    string `json:"session"`
						Password   string `json:"password"`
						Identifier struct {
							Type string `json:"type"`
							User string `json:"user"`
						} `json:"identifier"`
					} `json:"auth"`
				}
				if json.Unmarshal(raw, &request) != nil || request.Auth.Type != "m.login.password" || request.Auth.Session != "review-session" || request.Auth.Password != "fixture-password" || request.Auth.Identifier.Type != "m.id.user" || request.Auth.Identifier.User != "@test:fixture.invalid" {
					t.Fatal("password stage was not exercised")
				}
				if code == "success" {
					return propertyReply(r, 200, `{}`), nil
				}
				return propertyReply(r, 401, fmt.Sprintf(`{"errcode":%q,"error":"private-refusal"}`, code)), nil
			})
			err := c.Deactivate(t.Context(), "@test:fixture.invalid", "fixture-password")
			if calls != 2 {
				t.Fatalf("request count=%d want=2", calls)
			}
			if code == "success" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var me *Error
			if err == nil || !errors.As(err, &me) || me.ErrCode != code || me.Status != 401 || !me.OriginalRequest {
				t.Fatalf("typed refusal lost: %v", err)
			}
			token := code != "M_FORBIDDEN"
			if errors.Is(err, ErrAuth) != token || strings.Contains(err.Error(), "password rejected by the homeserver") == token {
				t.Fatalf("second-stage classification code=%s err=%v", code, err)
			}
			if strings.Contains(err.Error(), "private-refusal") || strings.Contains(err.Error(), "fixture-password") {
				t.Fatal("private material leaked")
			}
		})
	}
}
