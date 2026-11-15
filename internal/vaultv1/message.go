package vaultv1

import "regexp"

// Op is the closed release-role operation set. The adapter has no hello,
// management, enrollment or migration operation.
type Op string

const (
	OpRegister     Op = "register"
	OpRelease      Op = "release"
	OpCloseSession Op = "close_session"
)

const (
	// ProtocolVersion is the proposed native protocol integer. It is distinct
	// from the backend label vault-v1 and never negotiated down.
	ProtocolVersion   uint64 = 2
	MaxSecret                = 16384
	SessionLifetimeMS uint64 = 900000
	maxUint63         uint64 = 1<<63 - 1
)

var hex32RE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Request is one logical RequestV2. ID is a fresh random Hex32 per request;
// it is never reused across requests, sessions or connections.
type Request struct {
	ID   string
	Op   Op
	Body Value
}

// Value returns the logical RequestV2 dictionary for the driver to encode.
func (r Request) Value() Value {
	return Dict(F("v", Uint(ProtocolVersion)), F("request_id", String(r.ID)), F("op", String(string(r.Op))), F("body", r.Body))
}

// Session is SessionV1. It lives only in process memory for one connection;
// it is never written to the home, environment, argv or metadata.
type Session struct {
	Epoch      string
	ID         string
	Generation uint64
}

func identityValue(id Identity) Value {
	origin := Null()
	if id.Origin != nil {
		origin = Dict(F("host_id", String(id.Origin.HostID)), F("project_id", String(id.Origin.ProjectID)), F("profile_id", String(id.Origin.ProfileID)))
	}
	return Dict(F("domain", String(id.Domain)), F("kind", String(id.Kind)), F("name", String(id.Name)), F("origin", origin))
}

func bindingValue(b ConsumerBinding) Value {
	return Dict(F("binding_v", Uint(b.BindingV)), F("kind", String(b.Kind)), F("purpose", String(b.Purpose)),
		F("a2a_selector", String(b.A2ASelector)), F("user_id", String(b.UserID)),
		F("homeserver_url", String(b.HomeserverURL)), F("server_name", String(b.ServerName)))
}

func sessionValue(s Session) Value {
	return Dict(F("epoch", String(s.Epoch)), F("session_id", String(s.ID)), F("generation", Uint(s.Generation)))
}

func registerRequest(id string, identity Identity) Request {
	return Request{ID: id, Op: OpRegister, Body: Dict(F("identity", identityValue(identity)))}
}

func releaseRequest(id string, identity Identity, session *Session, binding ConsumerBinding) Request {
	s := Null()
	if session != nil {
		s = sessionValue(*session)
	}
	return Request{ID: id, Op: OpRelease, Body: Dict(F("identity", identityValue(identity)), F("session", s), F("expected_binding", bindingValue(binding)))}
}

// classify validates the common SuccessV2/RefusalV2 envelope of a submitted
// reply against its request. It returns the operation result dictionary for a
// success, REFUSED only for a well-formed matching RefusalV2 with a known code,
// and UNKNOWN for everything else. It never reads reply bytes into an error.
func classify(req Request, reply Value) (Value, *Refusal) {
	if ok, overLimit := reply.admitted(1); !ok { // the top-level dictionary is nesting level 1
		if overLimit {
			return Value{}, unknown(DiagLimit)
		}
		return Value{}, unknown(DiagMalformed)
	}
	m, success := reply.closed("v", "request_id", "op", "ok", "result")
	if !success {
		var ok bool
		if m, ok = reply.closed("v", "request_id", "op", "ok", "error"); !ok {
			return Value{}, unknown(DiagMalformed)
		}
	}
	v, rid, op, okv := m["v"], m["request_id"], m["op"], m["ok"]
	if v.kind != KindUint || rid.kind != KindString || op.kind != KindString || okv.kind != KindBool || okv.b != success {
		return Value{}, unknown(DiagMalformed)
	}
	if v.u != ProtocolVersion || rid.s != req.ID || op.s != string(req.Op) {
		return Value{}, unknown(DiagMismatch)
	}
	if success {
		return m["result"], nil
	}
	e, ok := m["error"].closed("code")
	if !ok || e["code"].kind != KindString || !Code(e["code"].s).Known() {
		return Value{}, unknown(DiagMalformed)
	}
	return Value{}, refused(Code(e["code"].s))
}

func parseIdentity(v Value) (Identity, bool) {
	m, ok := v.closed("domain", "kind", "name", "origin")
	if !ok || m["domain"].kind != KindString || m["kind"].kind != KindString || m["name"].kind != KindString {
		return Identity{}, false
	}
	id := Identity{Domain: m["domain"].s, Kind: m["kind"].s, Name: m["name"].s}
	switch o := m["origin"]; o.kind {
	case KindNull:
	case KindDict:
		om, ok := o.closed("host_id", "project_id", "profile_id")
		if !ok || om["host_id"].kind != KindString || om["project_id"].kind != KindString || om["profile_id"].kind != KindString {
			return Identity{}, false
		}
		id.Origin = &SyntheticContext{HostID: om["host_id"].s, ProjectID: om["project_id"].s, ProfileID: om["profile_id"].s}
	default:
		return Identity{}, false
	}
	return id, true
}

func parseBinding(v Value) (ConsumerBinding, bool) {
	m, ok := v.closed("binding_v", "kind", "purpose", "a2a_selector", "user_id", "homeserver_url", "server_name")
	if !ok || m["binding_v"].kind != KindUint {
		return ConsumerBinding{}, false
	}
	for _, k := range []string{"kind", "purpose", "a2a_selector", "user_id", "homeserver_url", "server_name"} {
		if m[k].kind != KindString {
			return ConsumerBinding{}, false
		}
	}
	return ConsumerBinding{BindingV: m["binding_v"].u, Kind: m["kind"].s, Purpose: m["purpose"].s, A2ASelector: m["a2a_selector"].s,
		UserID: m["user_id"].s, HomeserverURL: m["homeserver_url"].s, ServerName: m["server_name"].s}, true
}

// parseRegister accepts only the closed register Result for the latched
// identity. A release- or close-shaped result is UNKNOWN.
func parseRegister(result Value, want Identity) (Session, *Refusal) {
	m, ok := result.closed("identity", "session", "lifetime_ms")
	if !ok {
		return Session{}, unknown(DiagMalformed)
	}
	id, ok := parseIdentity(m["identity"])
	if !ok {
		return Session{}, unknown(DiagMalformed)
	}
	sm, ok := m["session"].closed("epoch", "session_id", "generation")
	if !ok || sm["epoch"].kind != KindString || sm["session_id"].kind != KindString || sm["generation"].kind != KindUint || m["lifetime_ms"].kind != KindUint {
		return Session{}, unknown(DiagMalformed)
	}
	s := Session{Epoch: sm["epoch"].s, ID: sm["session_id"].s, Generation: sm["generation"].u}
	if !hex32RE.MatchString(s.Epoch) || !hex32RE.MatchString(s.ID) || s.Generation < 1 || s.Generation > maxUint63 {
		return Session{}, unknown(DiagMalformed)
	}
	if !id.Equal(want) || m["lifetime_ms"].u != SessionLifetimeMS {
		return Session{}, unknown(DiagMismatch)
	}
	return s, nil
}

// parseRelease accepts only the closed release Result whose identity and
// ACTUAL protected binding equal the latched values, with revision and secret
// bounds. The returned secret aliases the reply buffer.
func parseRelease(result Value, want Identity, binding ConsumerBinding) ([]byte, uint64, *Refusal) {
	m, ok := result.closed("identity", "consumer_binding", "record_revision", "secret")
	if !ok || m["record_revision"].kind != KindUint || m["secret"].kind != KindBytes {
		return nil, 0, unknown(DiagMalformed)
	}
	id, ok := parseIdentity(m["identity"])
	if !ok {
		return nil, 0, unknown(DiagMalformed)
	}
	b, ok := parseBinding(m["consumer_binding"])
	if !ok {
		return nil, 0, unknown(DiagMalformed)
	}
	rev, secret := m["record_revision"].u, m["secret"].bytes
	if len(secret) > MaxSecret {
		return nil, 0, unknown(DiagLimit)
	}
	if rev < 1 || rev > maxUint63 || len(secret) < 1 {
		return nil, 0, unknown(DiagMalformed)
	}
	if !id.Equal(want) || b != binding {
		return nil, 0, unknown(DiagMismatch)
	}
	return secret, rev, nil
}
