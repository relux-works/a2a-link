//go:build darwin || linux

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/relux-works/a2a-swarm/internal/config"
	"github.com/relux-works/a2a-swarm/internal/e2ee"
	"github.com/relux-works/a2a-swarm/internal/matrix"
)

// U2a (docs/e2ee.md sections 3, 4 and 10): cross-signing bootstrap under a2ad
// custody and public identity evidence. No room, send, ingress or decrypt code,
// no device admission (Q4), no lifecycle (U2b), no activation and no pin writing.

const e2eeUsage = "usage: a2a e2ee init [--json] | a2a e2ee identity show [--json]"

// e2eeRefusal is the only error shape these commands emit for a typed gate: a
// fixed code with no value, so no key, password or server text can ride along.
type e2eeRefusal struct{ code string }

func (e e2eeRefusal) Error() string { return "e2ee: " + e.code }

func cmdE2EE(ctx context.Context, a *App, args []string) error {
	if len(args) == 0 {
		return usagef("%s", e2eeUsage)
	}
	fs := newFlagSet("e2ee")
	asJSON := fs.Bool("json", false, "machine-readable public evidence")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if a.human {
		return usagef("e2ee is agent-only; human accounts have no a2ad custody")
	}
	switch {
	case len(pos) == 1 && pos[0] == "init":
		return a.e2eeWrap(a.e2eeInit(ctx, *asJSON))
	case len(pos) == 2 && pos[0] == "identity" && pos[1] == "show":
		return a.e2eeWrap(a.e2eeIdentityShow(ctx, *asJSON))
	}
	return usagef("%s", e2eeUsage)
}

// e2eeWrap maps every failure to a typed refusal or a scrubbed transport line.
func (a *App) e2eeWrap(err error) error {
	if err == nil {
		return nil
	}
	var code e2ee.Code
	if errors.As(err, &code) {
		return e2eeRefusal{string(code)}
	}
	var ue usageError
	if errors.As(err, &ue) || errors.Is(err, flag.ErrHelp) || errors.Is(err, matrix.ErrAuth) {
		return err
	}
	switch {
	case errors.Is(err, matrix.ErrUIARequired), errors.Is(err, matrix.ErrUIARejected):
		return e2eeRefusal{string(e2ee.ErrUIAUnavailable)}
	case errors.Is(err, matrix.ErrKeyQueryIncomplete):
		return e2eeRefusal{"e2ee_key_query_incomplete"}
	case errors.Is(err, matrix.ErrSignatureUploadFailed):
		return e2eeRefusal{"e2ee_signature_upload_failed"}
	}
	return errors.New("e2ee: " + a.e2eeSecrets().Scrub(sanitizeLine(err.Error())))
}

func (a *App) e2eeSecrets() *e2ee.Inventory {
	if a.e2eeInventory == nil {
		a.e2eeInventory = new(e2ee.Inventory)
	}
	return a.e2eeInventory
}

// e2eeCustodyAvailable is the A1 gate: custody exists only for the dedicated
// a2ad service user. No environment variable, flag, home or local-base fallback
// can open it. nil seam selects the real check.
func (a *App) e2eeCustodyAvailable() error {
	if a.e2eeCustodyGate != nil {
		return a.e2eeCustodyGate()
	}
	return e2eeServiceUserCheck()
}

// e2eeServiceUserCheck requires the effective user to be the provisioned a2ad
// service account (_a2a uid 401 on macOS; a2a on Linux), never root.
func e2eeServiceUserCheck() error {
	euid := os.Geteuid()
	if euid == 0 {
		return e2ee.ErrCustodyUnavailable
	}
	name := "a2a"
	if runtime.GOOS == "darwin" {
		name = "_a2a"
		if euid != 401 {
			return e2ee.ErrCustodyUnavailable
		}
	}
	if verifyServiceAccount(name, uint32(euid), uint32(os.Getegid())) != nil {
		return e2ee.ErrCustodyUnavailable
	}
	return nil
}

// e2eeContext binds one identity to its custody namespace, connection binding
// digest and custody root. Device may be empty before registration.
type e2eeContext struct {
	name, mxid, device, class string
	binding                   string
	namespace                 e2ee.Namespace
	reserved                  []string
	root                      string
}

func (a *App) e2eeContext(p config.Paths, name, mxid, device, endpoint, server string) (*e2eeContext, error) {
	if !strings.HasPrefix(mxid, "@") || server == "" || endpoint == "" || p.Base == "" {
		return nil, e2ee.ErrIdentityMismatch
	}
	backend, err := a.selectedStore()
	if err != nil {
		return nil, err
	}
	c, err := a.selectedConnection()
	if err != nil {
		return nil, err
	}
	// One custody directory per identity under its own config base, so a legacy
	// base shared by several identities never shares a generation or root.
	ec := &e2eeContext{name: name, mxid: mxid, device: device, class: "agents", root: filepath.Join(p.Base, "e2ee-"+e2ee.TupleHash(mxid)[:32])}
	reserved := []string{e2ee.LegacyTokenService, e2ee.PasswordService}
	if c != nil {
		b, err := c.Binding(name, false)
		if err != nil {
			return nil, err
		}
		if b.UserID != mxid {
			return nil, e2ee.ErrIdentityMismatch
		}
		ec.binding = b.Fingerprint()
		token := c.Store.AccessTokenService
		if token == "" {
			// Backends without a token service name the backend itself; the
			// connection ID already separates profiles in the tuple.
			token = c.Store.Backend
		}
		ec.namespace = e2ee.Namespace{Endpoint: c.URL, Server: c.ServerName, Connection: c.ID, Backend: c.Store.Backend, TokenService: token, PasswordService: c.Store.PasswordService, Class: ec.class, MXID: mxid}
		root, err := config.ResolvePaths(a.Getenv)
		if err != nil {
			return nil, err
		}
		registry, err := config.LoadConnections(root)
		if err != nil {
			return nil, err
		}
		if registry != nil {
			for _, profile := range registry.Profiles {
				for _, service := range []string{profile.Store.AccessTokenService, profile.Store.PasswordService} {
					if service != "" {
						reserved = append(reserved, service)
					}
				}
				if profile.RegistrationTokenRef != nil && profile.RegistrationTokenRef.Service != "" {
					reserved = append(reserved, profile.RegistrationTokenRef.Service)
				}
			}
		}
	} else {
		ec.binding = e2ee.LegacyBinding(endpoint, server, backend, ec.class, mxid)
		ec.namespace = e2ee.Namespace{Endpoint: endpoint, Server: server, Connection: "legacy", Backend: backend, TokenService: e2ee.LegacyTokenService, Class: ec.class, MXID: mxid}
	}
	ec.reserved = reserved
	if _, err := ec.namespace.Digest(); err != nil {
		return nil, err
	}
	return ec, nil
}

type e2eeCustody struct {
	store   *e2ee.FileStore
	lease   *e2ee.LockedStore
	custody *e2ee.FileCustody
	inv     *e2ee.Inventory
}

func (a *App) e2eeOpenCustody(ctx context.Context, ec *e2eeContext) (*e2eeCustody, error) {
	if err := a.e2eeCustodyAvailable(); err != nil {
		return nil, err
	}
	store, err := e2ee.OpenFileStore(ec.root)
	if err != nil {
		return nil, err
	}
	lockCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	lease, err := store.Lock(lockCtx)
	if err != nil {
		store.Close()
		return nil, err
	}
	inv := a.e2eeSecrets()
	custody, err := e2ee.NewFileCustody(lease, ec.namespace, ec.reserved, inv)
	if err != nil {
		lease.Close()
		store.Close()
		return nil, err
	}
	return &e2eeCustody{store, lease, custody, inv}, nil
}
func (c *e2eeCustody) close() {
	c.lease.Close()
	c.store.Close()
}

// e2eeAccountPassword is the Q2 onboarding/registration wiring. Under a2ad
// custody it returns the identity's fixed-section password: an existing section
// is reused (a retried registration keeps the account password it may already
// have set), otherwise the freshly generated value is stored create-only before
// any network call. Outside a2ad there is no custody and the generated value is
// returned unchanged; the second result reports whether custody holds it.
func (a *App) e2eeAccountPassword(ctx context.Context, p config.Paths, name, mxid, endpoint, server, generated string) (string, bool, error) {
	if err := a.e2eeCustodyAvailable(); err != nil {
		return generated, false, nil
	}
	ec, err := a.e2eeContext(p, name, mxid, "", endpoint, server)
	if err != nil {
		return "", false, err
	}
	c, err := a.e2eeOpenCustody(ctx, ec)
	if err != nil {
		return "", false, err
	}
	defer c.close()
	existing, err := c.lease.ReadPassword(mxid, c.inv)
	if err == nil {
		a.secrets.Add(string(existing))
		return string(existing), true, nil
	}
	if err != e2ee.ErrUnavailable {
		return "", false, err
	}
	if err = c.lease.CreatePassword(mxid, []byte(generated), c.inv); err != nil {
		return "", false, err
	}
	return generated, true, nil
}

func (a *App) e2eePinPolicyFor() e2ee.PinPolicy {
	if a.e2eePinPolicy != nil {
		return *a.e2eePinPolicy
	}
	return e2ee.HostPinPolicy()
}

// e2eeReadPin reopens and validates the host pin and verifies the pinned owner
// MSK signature over the pinned USK. It runs before every trusted operation.
func (a *App) e2eeReadPin(ec *e2eeContext) (e2ee.HostPin, error) {
	pin, err := e2ee.ReadHostPin(a.e2eePinPolicyFor(), ec.binding, ec.class, ec.mxid, ec.device, ec.name)
	if err != nil {
		return e2ee.HostPin{}, err
	}
	if err := e2ee.VerifyOwnerChain(pin); err != nil {
		return e2ee.HostPin{}, err
	}
	return pin, nil
}

// e2eeIdentity is one loaded bootstrap: custody lease, roots, sealed snapshot,
// restored account and the cross-signing keys re-derived from the root seeds.
type e2eeIdentity struct {
	ec       *e2eeContext
	c        *e2eeCustody
	engine   *e2ee.Engine
	pointer  e2ee.Pointer
	root     e2ee.Root
	codec    *e2ee.Codec
	snapshot e2ee.Snapshot
	working  *e2ee.Working
	keys     *e2ee.CrossSigning
	device   e2ee.DeviceKeys
	evidence e2ee.IdentityEvidence
	own      *matrix.OwnKeys
}

func (id *e2eeIdentity) queryOwn(ctx context.Context, client *matrix.Client) (matrix.OwnKeys, error) {
	if id.own != nil {
		return *id.own, nil
	}
	own, err := client.QueryOwnKeys(ctx, id.ec.mxid)
	if err != nil {
		return own, err
	}
	id.own = &own
	return own, nil
}

// requireUnpublished refuses to mint or re-mint local roots when the server
// already publishes keys for this device or user: that needs explicit recovery.
func (id *e2eeIdentity) requireUnpublished(ctx context.Context, client *matrix.Client) error {
	own, err := id.queryOwn(ctx, client)
	if err != nil {
		return err
	}
	if own.MasterKey != nil || own.DeviceKeys[id.ec.device] != nil {
		return e2ee.ErrRecoveryRequired
	}
	return nil
}

// e2eeLoad opens or creates the local bootstrap. With a nil client it is
// read-only: nothing is created and no request is sent; an absent identity is
// ErrUnavailable. With a client, missing pointer/root/state are created in the
// section 4 order (pointer, create-only root, first sealed state) only after a
// complete key query shows nothing published for this device or user.
func (a *App) e2eeLoad(ctx context.Context, ec *e2eeContext, c *e2eeCustody, pin e2ee.HostPin, client *matrix.Client) (*e2eeIdentity, error) {
	id := &e2eeIdentity{ec: ec, c: c, engine: e2ee.NewEngine(c.inv)}
	expected := e2ee.Binding{Binding: ec.binding, Identity: ec.mxid, Device: ec.device}
	pointer, err := c.custody.ReadPointer(expected)
	switch {
	case err == nil:
	case err == e2ee.ErrUnavailable:
		if client == nil {
			return nil, e2ee.ErrUnavailable
		}
		if err = id.requireUnpublished(ctx, client); err != nil {
			return nil, err
		}
		if pointer, err = e2ee.NewPointer(ec.namespace, ec.binding, ec.device); err != nil {
			return nil, err
		}
		if err = c.custody.CreatePointer(pointer); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	id.pointer = pointer
	root, err := c.custody.ReadRoot(pointer)
	switch {
	case err == nil:
	case err == e2ee.ErrUnavailable:
		if client == nil {
			return nil, e2ee.ErrUnavailable
		}
		if err = id.requireUnpublished(ctx, client); err != nil {
			return nil, err
		}
		if root, err = e2ee.NewRoot(pointer, c.inv); err != nil {
			return nil, err
		}
		if err = c.custody.CreateRoot(pointer, root); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	id.root = root
	wrap, err := root.WrappingKey(c.inv)
	if err != nil {
		return nil, err
	}
	if id.codec, err = e2ee.NewCodec(wrap, c.inv); err != nil {
		return nil, err
	}
	if id.keys, err = e2ee.DeriveCrossSigning(root, c.inv); err != nil {
		return nil, err
	}
	snapshot, err := c.lease.LoadSnapshot(id.codec, pointer.Binding)
	switch {
	case err == nil:
		if snapshot.Identity == nil {
			return nil, e2ee.ErrIntegrity
		}
		if id.working, err = id.engine.Restore(snapshot.Engine, wrap); err != nil {
			return nil, err
		}
		if id.device, err = id.working.DeviceKeys(ec.mxid, ec.device); err != nil {
			return nil, err
		}
		id.evidence = *snapshot.Identity
		// Re-derived keys must be exactly the persisted public material; a
		// mismatch is never repaired by rotation.
		if err = id.evidence.MatchesKeys(id.keys, id.device); err != nil {
			return nil, err
		}
	case err == e2ee.ErrUnavailable:
		if client == nil {
			return nil, e2ee.ErrUnavailable
		}
		if err = id.requireUnpublished(ctx, client); err != nil {
			return nil, err
		}
		if id.working, err = id.engine.New(); err != nil {
			return nil, err
		}
		if id.device, err = id.working.DeviceKeys(ec.mxid, ec.device); err != nil {
			return nil, err
		}
		state, err := id.working.Checkpoint(wrap)
		if err != nil {
			return nil, err
		}
		if id.evidence, err = e2ee.NewIdentityEvidence(id.keys, id.device, pin, a.Now().UnixMilli()); err != nil {
			return nil, err
		}
		evidence := id.evidence
		snapshot = e2ee.Snapshot{Version: 1, Revision: 1, Engine: state, Identity: &evidence}
		if err = c.lease.SaveSnapshot(id.codec, pointer.Binding, snapshot, true); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	id.snapshot = snapshot
	return id, nil
}

func (id *e2eeIdentity) persist(nowMS int64) error {
	id.snapshot.Revision++
	id.evidence.ObservedMS = nowMS
	evidence := id.evidence
	id.snapshot.Identity = &evidence
	return id.c.lease.SaveSnapshot(id.codec, id.pointer.Binding, id.snapshot, false)
}

// enter records a state transition and returns refusal, or the persist error
// when the transition itself could not be sealed.
func (id *e2eeIdentity) enter(a *App, state string, refusal error) error {
	id.evidence.State = state
	if err := id.persist(a.Now().UnixMilli()); err != nil {
		return err
	}
	return refusal
}

// password reads the Q2 section only when the server has demanded UIA. A
// missing section is awaiting-uia, never an owner prompt or an empty password.
func (id *e2eeIdentity) password(a *App) func(context.Context) (string, error) {
	return func(context.Context) (string, error) {
		value, err := id.c.lease.ReadPassword(id.ec.mxid, id.c.inv)
		if err != nil {
			return "", e2ee.ErrUIAUnavailable
		}
		a.secrets.Add(string(value))
		return string(value), nil
	}
}

// advance runs the section 3 machine from the persisted state. Every trusted
// step reopens and compares the pin first. Persisted public material is
// re-uploaded exactly; conflicts enter changed; UIA shortfalls stop at
// awaiting-uia; a verified owner USK signature over the master ends at
// owner-verified, otherwise awaiting-owner is a successful stop.
func (id *e2eeIdentity) advance(ctx context.Context, a *App, client *matrix.Client, pin e2ee.HostPin) error {
	ev := &id.evidence
	if ev.State == e2ee.StateChanged {
		return e2ee.ErrTrustChanged
	}
	if err := ev.ComparePin(pin); err != nil {
		return id.enter(a, e2ee.StateChanged, e2ee.ErrTrustChanged)
	}
	recheck := func() error {
		fresh, err := a.e2eeReadPin(id.ec)
		if err != nil {
			return err
		}
		if fresh.Revision != pin.Revision || fresh.Digest != pin.Digest {
			return id.enter(a, e2ee.StateChanged, e2ee.ErrTrustChanged)
		}
		return nil
	}
	if ev.State == e2ee.StateLocalReady || ev.State == e2ee.StateAwaitingUIA {
		if err := recheck(); err != nil {
			return err
		}
		id.own = nil
		own, err := id.queryOwn(ctx, client)
		if err != nil {
			return err
		}
		if own.MasterKey != nil {
			if err := e2ee.SameMasterKey(*ev, id.ec.mxid, own.MasterKey); err != nil {
				return id.enter(a, e2ee.StateChanged, e2ee.ErrPublishedConflict)
			}
		}
		if published, ok := own.DeviceKeys[id.ec.device]; ok {
			if err := e2ee.SameDeviceKeys(*ev, id.ec.mxid, id.ec.device, published); err != nil {
				return id.enter(a, e2ee.StateChanged, e2ee.ErrPublishedConflict)
			}
		} else {
			raw, err := json.Marshal(id.device)
			if err != nil {
				return e2ee.ErrCodec
			}
			if err = client.UploadDeviceKeys(ctx, raw); err != nil {
				return err
			}
		}
		if own.MasterKey == nil {
			upload, err := id.crossSigningUpload()
			if err != nil {
				return err
			}
			err = client.UploadCrossSigningKeys(ctx, id.ec.mxid, upload, id.password(a))
			if errors.Is(err, matrix.ErrUIARequired) || errors.Is(err, matrix.ErrUIARejected) || errors.Is(err, e2ee.ErrUIAUnavailable) {
				return id.enter(a, e2ee.StateAwaitingUIA, e2ee.ErrUIAUnavailable)
			}
			if err != nil {
				return err
			}
		}
		signed, err := id.keys.SignDevice(id.device)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(signed)
		if err != nil {
			return e2ee.ErrCodec
		}
		if err = client.UploadSignatures(ctx, id.ec.mxid, id.ec.device, raw); err != nil {
			return err
		}
		if err = id.enter(a, e2ee.StatePublished, nil); err != nil {
			return err
		}
		id.own = nil
	}
	if ev.State == e2ee.StatePublished || ev.State == e2ee.StateAwaitingOwner {
		if err := recheck(); err != nil {
			return err
		}
		own, err := id.queryOwn(ctx, client)
		if err != nil {
			return err
		}
		if own.MasterKey == nil {
			return id.enter(a, e2ee.StateChanged, e2ee.ErrPublishedConflict)
		}
		signature, err := e2ee.OwnerSignatureOnMaster(pin, id.ec.mxid, *ev, own.MasterKey)
		switch {
		case err == nil:
			ev.OwnerUserSigningKeyID = pin.Record.UserSigningKeyID
			ev.OwnerSignature = signature
			return id.enter(a, e2ee.StateOwnerVerified, nil)
		case errors.Is(err, e2ee.ErrAwaitingOwner):
			if ev.State != e2ee.StateAwaitingOwner {
				return id.enter(a, e2ee.StateAwaitingOwner, nil)
			}
			return nil
		case errors.Is(err, e2ee.ErrPublishedConflict):
			return id.enter(a, e2ee.StateChanged, err)
		default:
			if ev.State != e2ee.StateAwaitingOwner {
				return id.enter(a, e2ee.StateAwaitingOwner, err)
			}
			return err
		}
	}
	if ev.State == e2ee.StateOwnerVerified {
		return e2ee.VerifyStoredOwnerSignature(pin, id.ec.mxid, *ev)
	}
	return e2ee.ErrUnavailable
}

func (id *e2eeIdentity) crossSigningUpload() (matrix.CrossSigningUpload, error) {
	var out matrix.CrossSigningUpload
	master, err := id.keys.MasterKey(id.ec.mxid)
	if err != nil {
		return out, err
	}
	self, err := id.keys.SelfSigningKey(id.ec.mxid)
	if err != nil {
		return out, err
	}
	user, err := id.keys.UserSigningKey(id.ec.mxid)
	if err != nil {
		return out, err
	}
	for _, pair := range []struct {
		dst *json.RawMessage
		obj e2ee.SignedKey
	}{{&out.MasterKey, master}, {&out.SelfSigningKey, self}, {&out.UserSigningKey, user}} {
		raw, err := json.Marshal(pair.obj)
		if err != nil {
			return out, e2ee.ErrCodec
		}
		*pair.dst = raw
	}
	return out, nil
}

func (a *App) e2eeInit(ctx context.Context, asJSON bool) error {
	s, err := a.session()
	if err != nil {
		return err
	}
	ec, err := a.e2eeContext(s.paths, s.name, s.creds.UserID, s.creds.DeviceID, s.client.BaseURL, s.server)
	if err != nil {
		return err
	}
	if ec.device == "" {
		return e2ee.ErrIdentityMismatch
	}
	// The pin and its owner chain gate everything: no custody is touched and
	// no request is sent for an identity whose host has not pinned its owner.
	pin, err := a.e2eeReadPin(ec)
	if err != nil {
		return err
	}
	who, err := s.client.Whoami(ctx)
	if err != nil {
		return err
	}
	if who.UserID != ec.mxid || who.DeviceID != ec.device {
		return e2ee.ErrIdentityMismatch
	}
	c, err := a.e2eeOpenCustody(ctx, ec)
	if err != nil {
		return err
	}
	defer c.close()
	id, err := a.e2eeLoad(ctx, ec, c, pin, s.client)
	if err != nil {
		return err
	}
	if err = id.advance(ctx, a, s.client, pin); err != nil {
		return err
	}
	public, err := id.evidence.Public(ec.mxid, ec.device, "")
	if err != nil {
		return err
	}
	return a.e2eePrint(public, asJSON)
}

func (a *App) e2eeIdentityShow(ctx context.Context, asJSON bool) error {
	s, err := a.sessionMetadata()
	if err != nil {
		return err
	}
	ec, err := a.e2eeContext(s.paths, s.name, s.creds.UserID, s.creds.DeviceID, s.client.BaseURL, s.server)
	if err != nil {
		return err
	}
	if err = a.e2eeCustodyAvailable(); err != nil {
		return err
	}
	absent := e2ee.PublicIdentity{Type: "e2ee_identity", MXID: ec.mxid, DeviceID: ec.device, State: e2ee.StateAbsent}
	if _, err := os.Lstat(ec.root); errors.Is(err, os.ErrNotExist) {
		return a.e2eePrint(absent, asJSON)
	}
	pin, pinErr := a.e2eeReadPin(ec)
	c, err := a.e2eeOpenCustody(ctx, ec)
	if err != nil {
		return err
	}
	defer c.close()
	id, err := a.e2eeLoad(ctx, ec, c, pin, nil)
	if err == e2ee.ErrUnavailable {
		return a.e2eePrint(absent, asJSON)
	}
	if err != nil {
		return err
	}
	if pinErr != nil {
		// Evidence exists but readiness is blocked: the pin must be restored
		// by the host before any state can be reported as trusted.
		return pinErr
	}
	state := id.evidence.State
	if state != e2ee.StateChanged && id.evidence.ComparePin(pin) != nil {
		state = e2ee.StateChanged
	}
	if state == e2ee.StateOwnerVerified {
		if err := e2ee.VerifyStoredOwnerSignature(pin, ec.mxid, id.evidence); err != nil {
			return err
		}
	}
	public, err := id.evidence.Public(ec.mxid, ec.device, state)
	if err != nil {
		return err
	}
	return a.e2eePrint(public, asJSON)
}

// e2eePrint emits public evidence only: identifiers, key IDs, SHA256
// fingerprints, state and pin revision. It is also the grant key-binding input.
func (a *App) e2eePrint(p e2ee.PublicIdentity, asJSON bool) error {
	if asJSON {
		return json.NewEncoder(a.Stdout).Encode(p)
	}
	a.printf("identity: %s\ndevice: %s\nstate: %s\n", sanitizeLine(p.MXID), sanitizeLine(p.DeviceID), p.State)
	if p.State == e2ee.StateAbsent {
		return nil
	}
	a.printf("pin_revision: %d\nowner: %s\n", p.PinRevision, sanitizeLine(p.Owner))
	for _, key := range []struct {
		label string
		key   e2ee.PublicKey
	}{{"master", p.Master}, {"self_signing", p.SelfSigning}, {"user_signing", p.UserSigning}} {
		a.printf("%s: %s sha256:%s\n", key.label, key.key.ID, key.key.SHA256)
	}
	return nil
}
