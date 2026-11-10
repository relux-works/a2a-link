# Host-selected Nostr session (AL2)

This fork can open a genuine NIP-17 identity using the published
`github.com/relux-works/a2a-transport-nostr v0.3.0` dependency. It retains the
`github.com/relux-works/a2a-swarm` module path so both packages share one transport
type identity. There are no replacements or copied transport implementations.
Matrix identities retain their existing paths and bytes; Matrix still refuses
CG1. This is a bounded messaging session, not Matrix feature parity.

## Host provisioning and selection

The host provisions `<A2A_CONFIG_DIR>/nostr/<name>/session.json`. The identity
directory must be an absolute physical directory, mode 0700 and owned by the
current user. The file must be a regular owned single-link mode 0600 file,
without symlinks, duplicate keys, unknown fields or trailing JSON. Its maximum
size is 65536 bytes. An existing invalid namespace fails closed; it never falls
back to a Matrix identity. Same-named `agents/<name>.json` or `humans/<name>.json`
metadata is ambiguous and refused. `--profile`, `--connection-fingerprint` and
human selection are unsupported for a Nostr session.

Example public configuration (replace the relay before use):

```json
{
  "version": 1,
  "admission_policy": "cg1",
  "settings": {
    "read_relays": "[\"wss://relay.example.invalid\"]"
  }
}
```

The policy must explicitly be `none` or `cg1`; omission never selects `none`.
Settings are the transport's explicit JSON-array strings: `read_relays`,
`write_relays`, `dm_relays`, `discovery_relays`, `blossom_servers`. They cannot
select a private key or an external state path. Media remains unsupported even
when a Blossom server is configured. There is no policy flag or peer override.

The transport owns `<identity>/transport/identity.key` and creates a new key if
none exists. An existing transport identity/state must never be replaced to
retry an operation. Host key provisioning, if needed, is private and must follow
the transport's key-file contract; no key is accepted through a CLI flag.
`whoami` prints the authenticated public key. CG1 configuration belongs at
`<identity>/admission/cg1.json`, with the existing
[read-only verifier configuration](cg1-foundation.md#host-provisioning).
The host is responsible for choosing the correct agent/landlord/issuer pins.

An optional `presentation` field contains the typed `swarma.grant.v1` object:
`v:1`, a lowercase 64-hex `grant_id`, and `bytes` as standard padded base64 of
the complete certificate JSON (1..16384 decoded bytes). It is untrusted proof,
not permission. The carrier is separate from human text. Transport v0.3.0 refuses
duplicate or escaped carrier keys, including a single escaped spelling. Session
also checks every object in the decoded certificate,
including objects in arrays, for duplicate keys after JSON unescaping. A single
escaped certificate key is normalized only for that comparison; certificate
bytes are never rewritten and CG1/K1 still validates their meaning. Both
duplicate orderings are refused. Explicit malformed proof never
falls back to an admitted cache. The transport additionally enforces its original
ordinary-extension and message budgets and real nested NIP-17 size limits.

The identity holds the transport's exclusive process lock. Operations recheck
that session.json still matches the bytes read at open; changing configuration
requires closing and reopening the session. No persistent daemon is installed.
Existing anonymous Matrix routing inspections, local Courier/enrollment and
environment-free negotiation protocols
keep their own routing contract; this feature does not migrate a Courier station.

## Commands

Use the existing `A2A_AGENT=<name>` or `--as <own-name>` identity selection:

```text
a2a whoami
a2a post <peer[,peer]> --txn-id ID [--to peer[,peer]] [--kind K] [--re ID] [--thread ID] [--subject S] <text|@file|->
a2a sync [--json]
a2a inbox [--limit N] [--json]
a2a status [--json]
a2a status admission --json
```

Peers are lowercase x-only public keys. The first post argument defines the
conversation participants; `--to` optionally selects an explicit subset. The
transport canonicalizes participants and always includes its required own copy.
Every post requires a stable transaction ID. Reuse it only for the identical
request. ACK prints the authenticated event ID; UNKNOWN/REFUSED print the closed
outcome and exit nonzero. UNKNOWN means publication may have occurred. Recheck
or retry with the same ID and identical request; do not invent another ID to
conceal uncertainty.

`sync` prints only dropped counts and closed gap metadata. `inbox` syncs first,
prints up to 50 pending ordinary records, then durably receipts exactly those
records. JSON output is an array of untrusted peer records. Text output uses
the existing untrusted-event frame and prefixes every peer-content line.
`status` prints public identity, selected policy, pending count and closed
admission counters; it never exports proof, private queues or RPC diagnostics.

Room/account operations, registration, bind/hooks, subscriptions, history,
attachments, uploads, downloads and voice are unsupported by this session.
Unsupported commands refuse before adapter construction. No raw adapter, signer,
upload method or callable trusted-input admission hook is exposed by Session.

## Admission and durability

Before the single adapter.Send call, Session validates all explicit recipients
against the adapter's conversation and calls Outbound for every distinct
external delivery target. One refusal prevents the entire attempt before
signing, encryption, discovery, journal creation or publication. The check runs
again on every invocation, including ACK and UNKNOWN retries. A prior successful
result does not grant permission for a later retry. CG1 checks are bounded fresh
observations; they cannot make several recipients' chain observations atomic
with each other or with subsequent publication.

Only the exact authenticated local key's transport copy is bookkeeping and
excluded from ordinary inbound processing. An external sender addressing this
identity still requires admission. Verified transport Events supply seal sender,
rumor ID and sender-provided Unix-second timestamp; local adapter Self supplies
recipient. Message.Text, Message.To and the outer wrapper's signer never supply
trusted identity. CG1 remains message admission metadata, not execution authority.

Inbound processing persists Live items to the mailbox, retryable refusals to
the private held queue, and Exchange items to the private exchange spool before
moving the sync cursor. A later sync rechecks held items. Durable event-ID dedup
makes mailbox replay harmless after interruption between append and cursor save.
Exchange telemetry may repeat after interruption; this is not an exactly-once
exchange guarantee. Failed output retains pending inbox records. Close cancels
in-flight checks before waiting for the operation lock. OS-stalled filesystem
calls and hostile same-UID replacement races remain outside this guarantee.

## Validation and limits

Run from a source checkout inside task-owned scratch with absolute physical
HOME/cwd/config/cache/temp directories under that same root. Use Go 1.26 or later;
do not redirect test HOME or caches into the SDK. Commands:

```text
go test -race -count=1 ./internal/nostrsession ./internal/cg1 ./internal/admission
go test -race -count=1 -run 'Test(NostrCLI|Admission|CG1|TransportGolden)' ./internal/cli
CG1_REGTEST=1 CG1_RUN_ROOT=<new-absolute-path-in-scratch> CG1_CORE_DAEMON=<pinned-namecoind> CG1_CORE_CLI=<pinned-namecoin-cli> go test -race -count=1 -timeout 5m -run '^TestCoreNostrSession$' -v ./internal/cg1
go vet ./...
go build ./...
go mod verify
go mod tidy -diff
```

Session/CLI fixtures use the published transport and a real loopback relay.
Wiring spies prove call ordering/target coverage only. The separately opt-in Core
test uses the production session constructor and actual published CG1/K1,
genuine issuer and hash-pinned isolated regtest node, with no checker or clock
injection. It covers live admission/reply/restart and missing, expired, wrong
grantee, forged rumor author, wrong-recipient ciphertext, duplicate certificate,
mixed recipients and revoked retries. It records/stops the owned node PID.
Never include its private custody directory in delivery artifacts.

Transport v0.3.0 checks original event/envelope/extension JSON before map decoding.
Duplicate or escaped keys and typed-field aliases refuse at that boundary;
ordinary escaped string values remain legal. Rejected inbound envelopes may
increment transport drop/checkpoint bookkeeping, but never reach the session's
ordinary mailbox. The decoded base64 certificate remains opaque to transport,
so the session's duplicate check and CG1/K1 validation remain required.

Upgrade compatibility: v0.2.0 accepted single escaped carrier keys; v0.3.0
returns a presentation refusal. Legal literal `<`, `>` and `&` extension keys
now round-trip without HTML escaping. Previously escaped wire/cache keys are
still refused. Ordinary extension keys requiring mandatory JSON escapes also
refuse. Corrupt or newly-invalid durable records may refuse retry/read; preserve
the identity key, journal and cursor for diagnosis rather than deleting state.
Retry comparison hashes keep their previous encoding. Tests cover malformed
inbound neighbors, legal key send/receive, restart retries and a deliberately
corrupt journal with no publication or state rewrite followed by valid repair.

No deployment, mainnet, S1 resolver, owner bypass, full room parity or media
authorization is claimed. Required independent review and hosted checks remain
separate from producer-local evidence.
