package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/a2a-swarm/internal/admission/testdata/policy"
)

// Proves directory redirects stop before a second request, beside successful alias controls in TestRoomPropertyCLISet.
func TestRoomPropertyAliasRedirect(t *testing.T) {
	for _, kind := range []string{"avatar", "parent"} {
		t.Run(kind, func(t *testing.T) {
			f := newNamedFixture(t, true)
			a := f.app()
			calls := 0
			a.HTTP = &http.Client{Transport: memberReadTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if calls != 1 || r.Method != "GET" || !strings.Contains(r.URL.Path, "/directory/room/") {
					t.Fatal("followed directory redirect or attempted state")
				}
				resp := propertyCLIReply(r, 307, `{}`)
				resp.Header.Set("Location", f.r.Profiles["alpha"].URL+"/redirected")
				return resp, nil
			})}
			args := []string{"room", "avatar", "set", "#target:fixture.invalid", "--expect-room-id", "!target", "--mxc", "mxc://media.invalid/a", "--json"}
			if kind == "parent" {
				args = []string{"room", "parent", "set", "!target", "--parent", "#space:fixture.invalid", "--expect-child-id", "!target", "--expect-parent-id", "!space", "--via", "fixture.invalid", "--canonical", "false", "--json"}
			}
			before := memberFiles(t, f.root)
			if code := a.Run(context.Background(), args); code != ExitError || calls != 1 || f.out.Len() != 0 || !strings.Contains(f.err.String(), "resolution unverified") || !reflect.DeepEqual(before, memberFiles(t, f.root)) {
				t.Fatalf("redirect refusal code=%d calls=%d out=%s err=%s", code, calls, f.out.String(), f.err.String())
			}
		})
	}
}

// Proves CLI token refusals retain REFUSED and credential guidance without retries, local changes or private response text.
func TestRoomPropertyCLITokenRefusal(t *testing.T) {
	for _, kind := range []string{"avatar", "parent"} {
		for _, tokenCode := range []string{"M_UNKNOWN_TOKEN", "M_MISSING_TOKEN"} {
			t.Run(kind+"/"+tokenCode, func(t *testing.T) {
				f := newNamedFixture(t, true)
				a := f.app()
				before := memberFiles(t, f.root)
				calls := 0
				a.HTTP = &http.Client{Transport: memberReadTransport(func(r *http.Request) (*http.Response, error) {
					calls++
					if r.Method != "PUT" {
						t.Fatal("refusal triggered readback")
					}
					return propertyCLIReply(r, 401, `{"errcode":"`+tokenCode+`","error":"private-refusal"}`), nil
				})}
				args := []string{"room", "avatar", "set", "!target", "--expect-room-id", "!target", "--mxc", "mxc://media.invalid/a", "--json"}
				if kind == "parent" {
					args = []string{"room", "parent", "set", "!target", "--parent", "!space", "--expect-child-id", "!target", "--expect-parent-id", "!space", "--via", "fixture.invalid", "--canonical", "false", "--json"}
				}
				code := a.Run(t.Context(), args)
				var got roomPropertyResult
				if err := json.Unmarshal(f.out.Bytes(), &got); err != nil {
					t.Fatal(err)
				}
				if code != ExitError || calls != 1 || got.Outcome != "REFUSED" || got.Acknowledged || got.EventID != "" || !strings.Contains(f.err.String(), "ask the keeper to rotate credentials") || strings.Contains(f.out.String()+f.err.String(), "private-refusal") || !reflect.DeepEqual(before, memberFiles(t, f.root)) {
					t.Fatalf("code=%d calls=%d out=%s err=%s", code, calls, f.out.String(), f.err.String())
				}
			})
		}
	}
}

// Proves today's admission startup guards apply while property commands leave mailbox, Seen-by and message-admission state untouched.
func TestRoomPropertyAdmissionAndSeenBy(t *testing.T) {
	for _, selected := range []string{"none", policy.Name, "unsupported-property-policy"} {
		for _, kind := range []string{"avatar", "parent"} {
			t.Run(selected+"/"+kind, func(t *testing.T) {
				f := newNamedFixture(t, true)
				seedMemberState(t, f)
				paths := f.paths("alpha", false)
				setAdmissionPolicy(t, paths, "alice", selected)
				// An opaque existing receipt ledger must not be read, repaired or advanced by a property operation.
				if err := os.WriteFile(paths.ReadReceiptsFile("alice"), []byte("preserved-seen-by-ledger"), 0600); err != nil {
					t.Fatal(err)
				}
				before := memberFiles(t, f.root)
				p := policy.Get(filepath.Join(paths.Base, "admission", "alice"))
				a := f.app()
				calls := 0
				a.HTTP = &http.Client{Transport: memberReadTransport(func(r *http.Request) (*http.Response, error) {
					calls++
					expected := "/_matrix/client/v3/rooms/!target/state/m.room.avatar/"
					if kind == "parent" {
						expected = "/_matrix/client/v3/rooms/!target/state/m.space.parent/!space"
					}
					if r.Method != "GET" || r.URL.Path != expected {
						t.Fatal("unrelated state or receipt request")
					}
					return propertyCLIReply(r, 200, `{}`), nil
				})}
				args := []string{"room", "avatar", "get", "!target", "--json"}
				if kind == "parent" {
					args = []string{"room", "parent", "get", "!target", "--parent", "!space", "--json"}
				}
				code := a.Run(t.Context(), args)
				if selected == "unsupported-property-policy" {
					if code != ExitError || calls != 0 || f.out.Len() != 0 {
						t.Fatalf("unsupported policy bypass: code=%d calls=%d", code, calls)
					}
				} else if code != ExitOK || calls != 1 {
					t.Fatalf("valid policy failed: code=%d calls=%d err=%s", code, calls, f.err.String())
				}
				if !reflect.DeepEqual(before, memberFiles(t, f.root)) {
					t.Fatal("property operation changed local state")
				}
				p.Mu.Lock()
				defer p.Mu.Unlock()
				if p.InCalls != 0 || p.OutCalls != 0 || (selected == policy.Name && p.Closes != 1) {
					t.Fatalf("message admission or close changed: in=%d out=%d closes=%d", p.InCalls, p.OutCalls, p.Closes)
				}
			})
		}
	}
}

// Proves invalid opaque positional/parent IDs refuse before credentials or HTTP without narrowing valid opaque IDs.
func TestRoomPropertyOpaquePreflight(t *testing.T) {
	for _, id := range []string{"!", "!" + strings.Repeat("x", 255), "!\xff"} {
		for _, kind := range []string{"avatar", "parent"} {
			for _, op := range []string{"get", "set"} {
				for _, target := range []string{"room", "parent"} {
					if kind == "avatar" && target == "parent" {
						continue
					}
					t.Run(kind+"/"+op+"/"+target+"/"+strings.ReplaceAll(id, "\xff", "invalid-utf8"), func(t *testing.T) {
						f := newNamedFixture(t, true)
						args := []string{"room", kind, op, id, "--json"}
						if kind == "parent" {
							child, parent := id, "!space"
							if target == "parent" {
								child, parent = "!target", id
							}
							args = []string{"room", kind, op, child, "--parent", parent, "--json"}
						}
						if op == "set" {
							if kind == "avatar" {
								args = append(args, "--expect-room-id", "!target", "--mxc", "mxc://media.invalid/a")
							} else {
								args = append(args, "--expect-child-id", "!target", "--expect-parent-id", "!space", "--via", "fixture.invalid", "--canonical", "false")
							}
						}
						before := memberFiles(t, f.root)
						if code := f.app().Run(t.Context(), args); code != ExitUsage || f.effects() != 0 || f.out.Len() != 0 || !strings.Contains(f.err.String(), "invalid opaque room ID") || !reflect.DeepEqual(before, memberFiles(t, f.root)) {
							t.Fatalf("opaque preflight code=%d effects=%d out=%s err=%s", code, f.effects(), f.out.String(), f.err.String())
						}
					})
				}
			}
		}
	}
}

// Proves cancellation or connection drift before the first property request emits no operation result or state request.
func TestRoomPropertyFirstRequestGuard(t *testing.T) {
	for _, kind := range []string{"avatar", "parent"} {
		for _, op := range []string{"get", "set"} {
			for _, mode := range []string{"cancelled", "selected-change"} {
				t.Run(kind+"/"+op+"/"+mode, func(t *testing.T) {
					f := newNamedFixture(t, true)
					a := f.app()
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					room := "!target"
					calls := 0
					if mode == "selected-change" {
						room = "#target:fixture.invalid"
					} else {
						cancel()
					}
					a.HTTP = &http.Client{Transport: memberReadTransport(func(r *http.Request) (*http.Response, error) {
						calls++
						if mode != "selected-change" || calls != 1 || r.Method != "GET" || !strings.Contains(r.URL.Path, "/directory/room/") {
							t.Fatal("first guard allowed a property request")
						}
						c := f.r.Profiles["alpha"]
						c.URL += "/changed"
						f.r.Profiles["alpha"] = c
						f.save()
						return propertyCLIReply(r, 200, `{"room_id":"!target"}`), nil
					})}
					args := []string{"room", kind, op, room, "--json"}
					if kind == "parent" {
						args = append(args, "--parent", "!space")
					}
					if op == "set" {
						if kind == "avatar" {
							args = append(args, "--expect-room-id", "!target", "--mxc", "mxc://media.invalid/a")
						} else {
							args = append(args, "--expect-child-id", "!target", "--expect-parent-id", "!space", "--via", "fixture.invalid", "--canonical", "false")
						}
					}
					wantCalls := 0
					if mode == "selected-change" {
						wantCalls = 1
					}
					if code := a.Run(ctx, args); code != ExitError || calls != wantCalls || f.out.Len() != 0 || !strings.Contains(f.err.String(), "no property request attempted") {
						t.Fatalf("first guard code=%d calls=%d out=%s err=%s", code, calls, f.out.String(), f.err.String())
					}
				})
			}
		}
	}
}

// Proves cancellation during exact readback retains a valid ACK/event ID and never retries either typed write.
func TestRoomPropertyContextAfterACK(t *testing.T) {
	for _, kind := range []string{"avatar", "parent"} {
		t.Run(kind, func(t *testing.T) {
			f := newNamedFixture(t, true)
			a := f.app()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			puts, gets := 0, 0
			a.HTTP = &http.Client{Transport: memberReadTransport(func(r *http.Request) (*http.Response, error) {
				if r.Method == "PUT" {
					puts++
					return propertyCLIReply(r, 200, `{"event_id":"$retained"}`), nil
				}
				if r.Method != "GET" {
					t.Fatal("unexpected method")
				}
				gets++
				cancel()
				return propertyCLIReply(r, 200, `{}`), nil
			})}
			args := []string{"room", "avatar", "set", "!target", "--expect-room-id", "!target", "--mxc", "mxc://media.invalid/a", "--json"}
			if kind == "parent" {
				args = []string{"room", "parent", "set", "!target", "--parent", "!space", "--expect-child-id", "!target", "--expect-parent-id", "!space", "--via", "fixture.invalid", "--canonical", "false", "--json"}
			}
			code := a.Run(ctx, args)
			var got roomPropertyResult
			if err := json.Unmarshal(f.out.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if code != ExitError || puts != 1 || gets != 1 || got.Outcome != "UNKNOWN" || !got.Acknowledged || got.EventID != "$retained" || got.Readback != "unavailable" {
				t.Fatalf("after ACK code=%d puts=%d gets=%d out=%s err=%s", code, puts, gets, f.out.String(), f.err.String())
			}
		})
	}
}
