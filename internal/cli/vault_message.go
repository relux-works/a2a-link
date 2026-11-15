package cli

import "regexp"

// vaultOp is the closed release-role operation set. The adapter has no hello,
// management, enrollment or migration operation.
type vaultOp string

const (
	vaultOpRegister     vaultOp = "register"
	vaultOpRelease      vaultOp = "release"
	vaultOpCloseSession vaultOp = "close_session"
)

const (
	// vaultProtocolVersion is the proposed native protocol integer. It is distinct
	// from the backend label vault-v1 and never negotiated down.
	vaultProtocolVersion   uint64 = 2
	vaultMaxSecret                = 16384
	vaultSessionLifetimeMS uint64 = 900000
	vaultMaxUint63         uint64 = 1<<63 - 1
)

var vaultHex32RE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// vaultRequest is one logical RequestV2. ID is a fresh random Hex32 per request;
// it is never reused across requests, sessions or connections.
type vaultRequest struct {
	id   string
	op   vaultOp
	body vaultValue
}

func (r vaultRequest) Value() vaultValue {
	return vaultDict(vaultF("v", vaultUint(vaultProtocolVersion)), vaultF("request_id", vaultString(r.id)), vaultF("op", vaultString(string(r.op))), vaultF("body", r.body))
}
func (r vaultRequest) clone() vaultRequest { r.body = r.body.clone(); return r }

// vaultSession is private to one attempt/connection; it is not persisted.
type vaultSession struct {
	Epoch      string
	ID         string
	Generation uint64
}

func vaultIdentityValue(id vaultIdentity) vaultValue {
	origin := vaultNull()
	if id.Origin != nil {
		origin = vaultDict(vaultF("host_id", vaultString(id.Origin.HostID)), vaultF("project_id", vaultString(id.Origin.ProjectID)), vaultF("profile_id", vaultString(id.Origin.ProfileID)))
	}
	return vaultDict(vaultF("domain", vaultString(id.Domain)), vaultF("kind", vaultString(id.Kind)), vaultF("name", vaultString(id.Name)), vaultF("origin", origin))
}

func vaultBindingValue(b vaultConsumerBinding) vaultValue {
	return vaultDict(vaultF("binding_v", vaultUint(b.BindingV)), vaultF("kind", vaultString(b.Kind)), vaultF("purpose", vaultString(b.Purpose)),
		vaultF("a2a_selector", vaultString(b.A2ASelector)), vaultF("user_id", vaultString(b.UserID)),
		vaultF("homeserver_url", vaultString(b.HomeserverURL)), vaultF("server_name", vaultString(b.ServerName)))
}

func vaultSessionValue(s vaultSession) vaultValue {
	return vaultDict(vaultF("epoch", vaultString(s.Epoch)), vaultF("session_id", vaultString(s.ID)), vaultF("generation", vaultUint(s.Generation)))
}

func vaultRegisterRequest(id string, identity vaultIdentity) vaultRequest {
	return vaultRequest{id: id, op: vaultOpRegister, body: vaultDict(vaultF("identity", vaultIdentityValue(identity)))}
}

func vaultReleaseRequest(id string, identity vaultIdentity, session *vaultSession, binding vaultConsumerBinding) vaultRequest {
	s := vaultNull()
	if session != nil {
		s = vaultSessionValue(*session)
	}
	return vaultRequest{id: id, op: vaultOpRelease, body: vaultDict(vaultF("identity", vaultIdentityValue(identity)), vaultF("session", s), vaultF("expected_binding", vaultBindingValue(binding)))}
}

// vaultClassify validates the common SuccessV2/RefusalV2 envelope of a submitted
// reply against its request. It returns the operation result dictionary for a
// success, REFUSED only for a well-formed matching RefusalV2 with a known code,
// and UNKNOWN for everything else. It never reads reply bytes into an error.
func vaultClassify(req vaultRequest, reply vaultValue) (vaultValue, *vaultFailure) {
	if ok, overLimit := reply.admitted(1); !ok { // the top-level dictionary is nesting level 1
		if overLimit {
			return vaultValue{}, vaultUnknownFailure(vaultDiagLimit)
		}
		return vaultValue{}, vaultUnknownFailure(vaultDiagMalformed)
	}
	m, vaultSuccess := reply.closed("v", "request_id", "op", "ok", "result")
	if !vaultSuccess {
		var ok bool
		if m, ok = reply.closed("v", "request_id", "op", "ok", "error"); !ok {
			return vaultValue{}, vaultUnknownFailure(vaultDiagMalformed)
		}
	}
	v, rid, op, okv := m["v"], m["request_id"], m["op"], m["ok"]
	if v.kind != vaultKindUint || rid.kind != vaultKindString || op.kind != vaultKindString || okv.kind != vaultKindBool || okv.b != vaultSuccess {
		return vaultValue{}, vaultUnknownFailure(vaultDiagMalformed)
	}
	if v.u != vaultProtocolVersion || rid.s != req.id || op.s != string(req.op) {
		return vaultValue{}, vaultUnknownFailure(vaultDiagMismatch)
	}
	if vaultSuccess {
		return m["result"], nil
	}
	e, ok := m["error"].closed("code")
	if !ok || e["code"].kind != vaultKindString || !vaultCode(e["code"].s).Known() {
		return vaultValue{}, vaultUnknownFailure(vaultDiagMalformed)
	}
	return vaultValue{}, vaultRefusedFailure(vaultCode(e["code"].s))
}

func vaultParseIdentity(v vaultValue) (vaultIdentity, bool) {
	m, ok := v.closed("domain", "kind", "name", "origin")
	if !ok || m["domain"].kind != vaultKindString || m["kind"].kind != vaultKindString || m["name"].kind != vaultKindString {
		return vaultIdentity{}, false
	}
	id := vaultIdentity{Domain: m["domain"].s, Kind: m["kind"].s, Name: m["name"].s}
	switch o := m["origin"]; o.kind {
	case vaultKindNull:
	case vaultKindDict:
		om, ok := o.closed("host_id", "project_id", "profile_id")
		if !ok || om["host_id"].kind != vaultKindString || om["project_id"].kind != vaultKindString || om["profile_id"].kind != vaultKindString {
			return vaultIdentity{}, false
		}
		id.Origin = &vaultSyntheticContext{HostID: om["host_id"].s, ProjectID: om["project_id"].s, ProfileID: om["profile_id"].s}
	default:
		return vaultIdentity{}, false
	}
	return id, true
}

func vaultParseBinding(v vaultValue) (vaultConsumerBinding, bool) {
	m, ok := v.closed("binding_v", "kind", "purpose", "a2a_selector", "user_id", "homeserver_url", "server_name")
	if !ok || m["binding_v"].kind != vaultKindUint {
		return vaultConsumerBinding{}, false
	}
	for _, k := range []string{"kind", "purpose", "a2a_selector", "user_id", "homeserver_url", "server_name"} {
		if m[k].kind != vaultKindString {
			return vaultConsumerBinding{}, false
		}
	}
	return vaultConsumerBinding{BindingV: m["binding_v"].u, Kind: m["kind"].s, Purpose: m["purpose"].s, A2ASelector: m["a2a_selector"].s,
		UserID: m["user_id"].s, HomeserverURL: m["homeserver_url"].s, ServerName: m["server_name"].s}, true
}

// vaultParseRegister accepts only the closed register result for the latched
// identity. A release- or close-shaped result is UNKNOWN.
func vaultParseRegister(result vaultValue, want vaultIdentity) (vaultSession, *vaultFailure) {
	m, ok := result.closed("identity", "session", "lifetime_ms")
	if !ok {
		return vaultSession{}, vaultUnknownFailure(vaultDiagMalformed)
	}
	id, ok := vaultParseIdentity(m["identity"])
	if !ok {
		return vaultSession{}, vaultUnknownFailure(vaultDiagMalformed)
	}
	if r := vaultIdentityShapeLimits(id); r != nil && r.Code == vaultELimit {
		return vaultSession{}, vaultUnknownFailure(vaultDiagLimit)
	}
	sm, ok := m["session"].closed("epoch", "session_id", "generation")
	if !ok || sm["epoch"].kind != vaultKindString || sm["session_id"].kind != vaultKindString || sm["generation"].kind != vaultKindUint || m["lifetime_ms"].kind != vaultKindUint {
		return vaultSession{}, vaultUnknownFailure(vaultDiagMalformed)
	}
	s := vaultSession{Epoch: sm["epoch"].s, ID: sm["session_id"].s, Generation: sm["generation"].u}
	if !vaultHex32RE.MatchString(s.Epoch) || !vaultHex32RE.MatchString(s.ID) || s.Generation < 1 || s.Generation > vaultMaxUint63 {
		return vaultSession{}, vaultUnknownFailure(vaultDiagMalformed)
	}
	if !id.Equal(want) || m["lifetime_ms"].u != vaultSessionLifetimeMS {
		return vaultSession{}, vaultUnknownFailure(vaultDiagMismatch)
	}
	return s, nil
}

// vaultParseRelease accepts only the closed release result whose identity and
// ACTUAL protected binding equal the latched values, with revision and secret
// bounds. The returned secret aliases the reply buffer.
func vaultParseRelease(result vaultValue, want vaultIdentity, binding vaultConsumerBinding) ([]byte, uint64, *vaultFailure) {
	m, ok := result.closed("identity", "consumer_binding", "record_revision", "secret")
	if !ok || m["record_revision"].kind != vaultKindUint || m["secret"].kind != vaultKindBytes {
		return nil, 0, vaultUnknownFailure(vaultDiagMalformed)
	}
	id, ok := vaultParseIdentity(m["identity"])
	if !ok {
		return nil, 0, vaultUnknownFailure(vaultDiagMalformed)
	}
	b, ok := vaultParseBinding(m["consumer_binding"])
	if !ok {
		return nil, 0, vaultUnknownFailure(vaultDiagMalformed)
	}
	if r := vaultIdentityShapeLimits(id); r != nil && r.Code == vaultELimit {
		return nil, 0, vaultUnknownFailure(vaultDiagLimit)
	}
	if r := vaultBindingLimits(b); r != nil {
		return nil, 0, vaultUnknownFailure(vaultDiagLimit)
	}
	rev, secret := m["record_revision"].u, m["secret"].bytes
	if len(secret) > vaultMaxSecret {
		return nil, 0, vaultUnknownFailure(vaultDiagLimit)
	}
	if rev < 1 || rev > vaultMaxUint63 || len(secret) < 1 {
		return nil, 0, vaultUnknownFailure(vaultDiagMalformed)
	}
	if !id.Equal(want) || b != binding {
		return nil, 0, vaultUnknownFailure(vaultDiagMismatch)
	}
	return secret, rev, nil
}
