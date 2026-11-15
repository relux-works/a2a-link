package matrix

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// Proves both typed writes preserve each original token refusal without readback or retry.
func TestRoomPropertiesTypedTokenRefusal(t *testing.T) {
	for _, kind := range []string{"avatar", "parent"} {
		for _, code := range []string{"M_UNKNOWN_TOKEN", "M_MISSING_TOKEN"} {
			t.Run(kind+"/"+code, func(t *testing.T) {
				c := New("https://fixture.invalid", "fixture-token")
				calls := 0
				raw := fmt.Sprintf(`{"errcode":%q,"error":"private refusal"}`, code)
				c.HTTP.Transport = propertyTransport(func(r *http.Request) (*http.Response, error) {
					calls++
					if r.Method != "PUT" {
						t.Fatal("refusal triggered readback")
					}
					return propertyReply(r, 401, raw), nil
				})
				var got StateWriteResult
				var err error
				if kind == "avatar" {
					got, err = c.SetRoomAvatar(t.Context(), "!room", "mxc://media.invalid/a")
				} else {
					got, err = c.SetRoomParent(t.Context(), "!room", "!parent", []string{"fixture.invalid"}, false)
				}
				var me *Error
				if got.Outcome != "REFUSED" || got.Acknowledged || got.EventID != "" || got.Readback != "not-attempted" || calls != 1 || !errors.Is(err, ErrAuth) || !errors.As(err, &me) {
					t.Fatalf("typed refusal lost: %+v %v calls=%d", got, err, calls)
				}
				if me.Status != 401 || me.ErrCode != code || me.Message != "private refusal" || string(me.Raw) != raw || !me.OriginalRequest || !me.BodyComplete || me.control == nil || strings.Contains(err.Error(), "private refusal") {
					t.Fatal("original typed Matrix response changed or leaked")
				}
			})
		}
	}
}

// Proves the 64 KiB ACK boundary and event-ID grammar for both operations beside valid exact-bound controls.
func TestRoomPropertiesACKBounds(t *testing.T) {
	for _, kind := range []string{"avatar", "parent"} {
		for _, mode := range []string{"valid", "at-limit", "over-limit", "bad-id", "long-id"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				c := New("https://fixture.invalid", "fixture-token")
				ack := `{"event_id":"$ack","padding":""}`
				switch mode {
				case "at-limit", "over-limit":
					size := roomPropertyLimit
					if mode == "over-limit" {
						size++
					}
					ack = strings.Replace(ack, `"padding":""`, `"padding":"`+strings.Repeat("x", size-len(ack))+`"`, 1)
				case "bad-id":
					ack = `{"event_id":"not-an-event"}`
				case "long-id":
					ack = `{"event_id":"$` + strings.Repeat("x", 255) + `"}`
				}
				calls := 0
				c.HTTP.Transport = propertyTransport(func(r *http.Request) (*http.Response, error) {
					calls++
					if calls == 1 {
						if r.Method != "PUT" {
							t.Fatal("missing write")
						}
						return propertyReply(r, 200, ack), nil
					}
					if calls != 2 || r.Method != "GET" {
						t.Fatal("unexpected effect")
					}
					body := `{"url":"mxc://media.invalid/a"}`
					if kind == "parent" {
						body = `{"via":["fixture.invalid"],"canonical":false}`
					}
					return propertyReply(r, 200, body), nil
				})
				var got StateWriteResult
				var err error
				if kind == "avatar" {
					got, err = c.SetRoomAvatar(t.Context(), "!room", "mxc://media.invalid/a")
				} else {
					got, err = c.SetRoomParent(t.Context(), "!room", "!parent", []string{"fixture.invalid"}, false)
				}
				valid := mode == "valid" || mode == "at-limit"
				if valid {
					if err != nil || got.Outcome != "VERIFIED" || got.EventID != "$ack" || !got.Acknowledged || calls != 2 {
						t.Fatalf("valid ACK refused: %+v %v calls=%d", got, err, calls)
					}
				} else if err == nil || got.Outcome != "UNKNOWN" || got.Acknowledged || got.EventID != "" || got.Readback != "not-attempted" || calls != 1 {
					t.Fatalf("bad ACK accepted: %+v %v calls=%d", got, err, calls)
				}
			})
		}
	}
}

// Proves parent uncertainty retains its known event ID, exact via/canonical semantics and one-write bound.
func TestRoomPropertiesParentUncertainty(t *testing.T) {
	for _, mode := range []string{"match", "via-order", "canonical", "omitted-canonical", "extra", "lost-read", "lost-ack"} {
		t.Run(mode, func(t *testing.T) {
			c := New("https://fixture.invalid", "fixture-token")
			puts, gets := 0, 0
			c.HTTP.Transport = propertyTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path != v3+"/rooms/!child/state/m.space.parent/!parent" {
					t.Fatal("wrong room/key")
				}
				if r.Method == "PUT" {
					puts++
					if mode == "lost-ack" {
						return nil, errors.New("fixture interruption")
					}
					return propertyReply(r, 200, `{"event_id":"$parent-ack"}`), nil
				}
				if r.Method != "GET" {
					t.Fatal("unexpected method")
				}
				gets++
				body := `{"via":["first.invalid","second.invalid"],"canonical":false}`
				switch mode {
				case "via-order":
					body = `{"via":["second.invalid","first.invalid"],"canonical":false}`
				case "canonical":
					body = `{"via":["first.invalid","second.invalid"],"canonical":true}`
				case "omitted-canonical":
					body = `{"via":["first.invalid","second.invalid"]}`
				case "extra":
					body = `{"via":["first.invalid","second.invalid"],"canonical":false,"extra":{}}`
				case "lost-read":
					return nil, errors.New("fixture interruption")
				}
				return propertyReply(r, 200, body), nil
			})
			got, err := c.SetRoomParent(t.Context(), "!child", "!parent", []string{"first.invalid", "second.invalid"}, false)
			if puts != 1 {
				t.Fatalf("write count %d", puts)
			}
			if mode == "match" {
				if err != nil || got.Outcome != "VERIFIED" || got.Readback != "match" || gets != 1 {
					t.Fatalf("positive %+v %v", got, err)
				}
			} else if err == nil || got.Outcome != "UNKNOWN" {
				t.Fatalf("uncertainty %+v %v", got, err)
			}
			if mode == "lost-ack" {
				if got.Acknowledged || got.EventID != "" || gets != 0 {
					t.Fatalf("lost ACK %+v", got)
				}
			} else if !got.Acknowledged || got.EventID != "$parent-ack" || gets != 1 {
				t.Fatalf("lost evidence %+v", got)
			}
		})
	}
}

// Proves shared token unwrapping does not turn plain token refusals into UIA progress or another request.
func TestRoomPropertiesTokenLegacyCalls(t *testing.T) {
	for _, method := range []string{"register", "probe", "deactivate", "admin-register"} {
		for _, code := range []string{"M_UNKNOWN_TOKEN", "M_MISSING_TOKEN"} {
			t.Run(method+"/"+code, func(t *testing.T) {
				c := New("https://fixture.invalid", "fixture-token")
				calls := 0
				c.HTTP.Transport = propertyTransport(func(r *http.Request) (*http.Response, error) {
					calls++
					return propertyReply(r, 401, fmt.Sprintf(`{"errcode":%q,"error":"private"}`, code)), nil
				})
				var err error
				switch method {
				case "admin-register":
					_, err = c.ForAdminRegistration().Register(context.Background(), "test", "fixture-password", "fixture-bootstrap", "test")
				case "register":
					_, err = c.Register(context.Background(), "test", "fixture-password", "fixture-bootstrap", "test")
				case "probe":
					_, err = c.UserExists(context.Background(), "test")
				case "deactivate":
					err = c.Deactivate(context.Background(), "@test:fixture.invalid", "fixture-password")
				}
				var me *Error
				if calls != 1 || errors.Is(err, ErrAuth) != (method != "admin-register") || !errors.As(err, &me) || me.ErrCode != code || !me.OriginalRequest || strings.Contains(err.Error(), "private") {
					t.Fatalf("legacy refusal calls=%d err=%v", calls, err)
				}
			})
		}
	}
}

// Proves a readback token refusal remains UNKNOWN with its ACK/event ID and typed error, rather than becoming a zero-effect refusal.
func TestRoomPropertiesReadbackTokenRefusal(t *testing.T) {
	for _, kind := range []string{"avatar", "parent"} {
		for _, code := range []string{"M_UNKNOWN_TOKEN", "M_MISSING_TOKEN"} {
			t.Run(kind+"/"+code, func(t *testing.T) {
				c := New("https://fixture.invalid", "fixture-token")
				puts, gets := 0, 0
				c.HTTP.Transport = propertyTransport(func(r *http.Request) (*http.Response, error) {
					if r.Method == "PUT" {
						puts++
						return propertyReply(r, 200, `{"event_id":"$ack"}`), nil
					}
					if r.Method != "GET" {
						t.Fatal("unexpected method")
					}
					gets++
					return propertyReply(r, 401, fmt.Sprintf(`{"errcode":%q,"error":"private"}`, code)), nil
				})
				var got StateWriteResult
				var err error
				if kind == "avatar" {
					got, err = c.SetRoomAvatar(t.Context(), "!room", "mxc://media.invalid/a")
				} else {
					got, err = c.SetRoomParent(t.Context(), "!room", "!parent", []string{"fixture.invalid"}, false)
				}
				var me *Error
				if got.Outcome != "UNKNOWN" || !got.Acknowledged || got.EventID != "$ack" || got.Readback != "unavailable" || puts != 1 || gets != 1 || !errors.Is(err, ErrAuth) || !errors.As(err, &me) || me.ErrCode != code || !me.OriginalRequest || strings.Contains(err.Error(), "private") {
					t.Fatalf("readback refusal %+v %v puts=%d gets=%d", got, err, puts, gets)
				}
			})
		}
	}
}

// Proves ordinary token refusals cannot become UIA progress even when the same response carries otherwise valid flows.
func TestRoomPropertiesTokenUIACompatibility(t *testing.T) {
	for _, method := range []string{"register", "probe", "deactivate"} {
		for _, code := range []string{"M_UNKNOWN_TOKEN", "M_MISSING_TOKEN"} {
			t.Run(method+"/"+code, func(t *testing.T) {
				c := New("https://fixture.invalid", "fixture-token")
				calls := 0
				stage := "m.login.dummy"
				if method == "deactivate" {
					stage = "m.login.password"
				}
				c.HTTP.Transport = propertyTransport(func(r *http.Request) (*http.Response, error) {
					calls++
					return propertyReply(r, 401, fmt.Sprintf(`{"errcode":%q,"error":"private","session":"fixture-session","flows":[{"stages":[%q]}]}`, code, stage)), nil
				})
				var err error
				switch method {
				case "register":
					_, err = c.Register(t.Context(), "test", "fixture-password", "fixture-bootstrap", "test")
				case "probe":
					_, err = c.UserExists(t.Context(), "test")
				case "deactivate":
					err = c.Deactivate(t.Context(), "@test:fixture.invalid", "fixture-password")
				}
				if calls != 1 || !errors.Is(err, ErrAuth) || strings.Contains(err.Error(), "private") {
					t.Fatalf("token refusal entered UIA: calls=%d err=%v", calls, err)
				}
			})
		}
	}
}
