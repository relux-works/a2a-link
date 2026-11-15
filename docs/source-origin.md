# P17-A Source run-origin seam (review candidate)

This implements the upstream part of Source proposal r2
(SHA-256 `3687f08991c035232b1348b4c40715f3e650ca1e62b97df6790cbb2525cc3a89`)
and Curator hooks r1.2
(`15e7e393b4254f9f6ef2ef211667d203204d095e8b83f71e696dc03673b4f021`).
The start authorization is co-lead event `$RgZz8SfH` (P17-A: keeper staffs,
Source owns and reviews). This source candidate does not activate a service.

## Build boundary

`runorigin.Producer` is an optional, explicit typed dependency. It is unrelated
to the generic `admission.Checker`/`Decision` registry. No producer is linked or
registered in stock upstream. `daemon.NewOriginService` and `Serve` are Linux
library entry points; no existing daemon/CLI path calls them. A stock library
endpoint constructed without a producer advertises no operations and returns
`origin_not_supported` on a well-formed authenticated prepare.

A future reviewed downstream service must construct ONE `OriginService` at
process start from protected `OriginConfig`: SourceControlDir, pinned launcher
UID/generation, current `GenerationAuthority`, and its qualified Producer. It
must also establish the Source A account/image/generation/service binding for
the launcher. This candidate does not infer those from a self-reported hash,
station secret, checker name, runtime token or Matrix author.

`Producer.Open` receives only authenticated launcher, retained-event reference
and input principal. The downstream implementation must independently resolve
identity, connection, Matrix user, policy and Keymaker registration from its
protected mapping, read the retained event itself, and construct an OWNED
checker with its own private scope. It must verify the exact signed inner
request/profile, grant and current tip. A missing mapping/fact refuses. It
returns a new `Session` for that preparation; it never borrows another
invocation's session token or checker. The upstream server calls `Prepare`, then
`Validate` for fresh admission/pin checks, then `Close`. Close also runs on
replacement, disconnect, malformed traffic, refusal, lost reply or timeout.
The downstream must honor context cancellation and implement prompt local Close.

A `Result` contains the protected registration plus a typed six-member Origin.
Upstream checks shape and exact immutable equality on revalidation. It cannot
prove cryptographic truth supplied by a malicious linked producer. In
particular, a syntactically valid forged signed-inner-request claim is a
**downstream producer qualification obligation**. Upstream tests reject a
caller-injected origin, malformed producer origin, Matrix `$` ID and changed
recheck facts; they do not implement or simulate a rich cryptographic checker.

## Candidate wire details requiring Source/client pinning

The accepted inputs name payload/result fields but do not define envelope,
hello/error encoding or all scalar types. The following minimal choices are
explicit review candidates, not previously accepted interoperability claims.

Framing is the existing 4-byte big-endian length, `1..65536` UTF-8 JSON bytes.
Only framing is shared with station traffic; this protocol has its own closed
JSON decoder. No station hello, HMAC, argv, identity, secret or session parser
is used. The socket is exclusively `<SourceControlDir>/origin.sock`.

After kernel/current-generation authentication, Source sends exactly:

```json
{"capabilities":["source.origin.prepare/1","source.origin.validate/1"],"source_incarnation":"0123456789abcdef0123456789abcdef"}
```

With no producer, `capabilities` is `[]`. These are announcements, not peer
credentials. Unauthorized peers instead receive a fixed code/incarnation frame
and the connection closes, before any event read or checker/prepared work.

Each request envelope contains exactly `op` and `params`:

```json
{"op":"source.origin.prepare/1","params":{"request_id":"request-1","launch_nonce":"nonce-1","event_ref":{"room_id":"!room:example","event_id":"$matrix-event"},"input_principal":{"uid":4242,"generation":19}}}
```

```json
{"op":"source.origin.validate/1","params":{"request_id":"request-1","launch_nonce":"nonce-1","prepared_id":"0123456789abcdef0123456789abcdef","source_incarnation":"fedcba9876543210fedcba9876543210"}}
```

Both successful operations return exactly `runorigin.PreparedOrigin`'s seven
fields. Validate repeats the original request ID and every preparation binding:

```json
{"request_id":"request-1","launch_nonce":"nonce-1","input_principal":{"uid":4242,"generation":19},"identity_registration_number":"protected-registration","source_incarnation":"fedcba9876543210fedcba9876543210","prepared_id":"0123456789abcdef0123456789abcdef","origin":{"kind":"admission","event_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","grant_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","tip_hash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","mode":"enforcing","command_id":""}}
```

Candidate scalar rules: UID is a JSON uint32; generation is a nonzero JSON
uint64. Request ID, nonce and event references are nonempty strings of at most
4096 UTF-8 bytes with no NUL/CR/LF. Registration is a nonempty bounded string
from the producer; its canonical domain is still a downstream/client pinning
question. Incarnation and prepared ID are independently random nonzero 128-bit
values encoded as 32 lowercase hex characters. The three Origin IDs are exactly
64 lowercase hex characters. The event reference may contain a Matrix ID;
Origin.event_id must describe the verified inner request and cannot contain one.

Every object is closed, including the envelope and both nested prepare objects.
Missing, unknown, duplicate (including escaped aliases), case-variant and
wrong-type fields refuse. There are no additional operations. Failures contain
exactly `code` and current `source_incarnation`; they close the connection:

```json
{"code":"run_origin_refused","source_incarnation":"fedcba9876543210fedcba9876543210"}
```

Only names from the accepted texts are emitted: `origin_not_supported` is a
definite refusal; malformed/unauthorized/path/origin/correlation failures use
`run_origin_refused`; explicitly classified dependency failures and timeouts use
`run_origin_unavailable`. Arbitrary producer error text is suppressed and
unclassified errors refuse. There are no invented path/parse/nonce/timeout
subcodes. Bind/end UNKNOWN belongs to the launcher/Keymaker, not this endpoint.

## Authentication, records and budgets

The server checks real Linux SO_PEERCRED against the protected launcher UID,
then consults injected CURRENT generation authority and compares the protected
launcher generation. It checks again for every prepare/validate before calling
the producer. A denied UID does not even reach the generation dependency.
Input/caller fields cannot authenticate a connection.

SourceControlDir must already exist, be A-owned exactly 0711, and have no
symlink components. Its ancestors must be operator-qualified protected paths;
this library checks no-follow traversal, not host ACL/group membership policy.
The newly created socket is A-owned exactly 0666, a single-link socket. Existing
paths, including stale sockets, are refused without repair/removal. Only a new
socket is chmodded; cleanup compares the held directory and created inode.
Directory/socket identity, owner, type, links and modes are rechecked before
protected operations. Path changes refuse. No account/group/ACL is created.

A fresh incarnation is generated with crypto/rand at service construction and
is immutable. Serve is single-use. Records are connection-local memory only,
with at most one outstanding preparation per connection. A fresh prepare
replaces/closes the old session. The record binds launcher (immutable
configuration plus current peer checks), Source incarnation, request ID, nonce,
input principal, mapping/session and immutable Origin. Validate on that same
live connection consumes it before recheck; a failure cannot reuse it. Another
connection or service instance has no authority to adopt the ID. Disconnect,
idle expiry or service shutdown closes an unconsumed session. Nothing restores
records after process restart.

Each prepare and validate has an independent five-second budget, including its
frame read and dependency work. Late results are discarded and late sessions
closed. Worker slots remain occupied until the dependency actually returns,
bounding even a broken cancellation-ignoring dependency to 64 outstanding
workers. There are at most 64 live client connections, no unbounded prepared
map, and a bounded one-second error write. A disconnected/timeout operation
never becomes an accepted preparation later. Network delivery can still be
lost: the client must restart from H1, compare every successful binding to its
current authenticated hello and never reuse an old prepared ID/response.

Source incarnation fences H1–H2 only. There is no Source-driven ending or
revalidation after Keymaker bind. H3–H6, durable launcher records, isolation,
FD/input-release gates and all Keymaker operations are outside P17-A. Per the
co-lead's ruling, H6 v1 never rebinds and hosted/Werkstatt enforcing refuses;
this source candidate adds no alternative route.

## Tools and verification

Use the task's admitted Go environment before every Go/gofmt invocation. No
telemetry command or persistent Go environment change is needed. Ordinary
entry points (logs under `.temp/P17-A/`, fixtures in test temp dirs):

```sh
go test ./internal/daemon -run '^TestSourceOrigin' -race -count=1 -v
A2A_RUN_ORIGIN_PLANTS=1 go test ./internal/daemon -run '^TestSourceOriginNarrowingPlants$' -count=1 -v
go test ./... -race
go vet ./...
go build ./...
```

The opt-in plant runner uses Go overlays, checks exact named test failures and
exit 1 (rejecting compile errors/panics as evidence), then reruns unchanged
source at exit 0. `A2A_ORIGIN_GO_ENV=/absolute/env.sh` optionally requires the
subprocesses to source the same admitted environment explicitly.

For this producer's write-confined run, each command is prefixed with
`. /home/agent/Werkstatt/keeper-p17a-dev/.goenv/env.sh && umask 022 &&` and runs
inside this wrapper before its `go ...` arguments:

```sh
bwrap --ro-bind / / --dev /dev \
  --bind /home/agent/Werkstatt/keeper-p17a-dev /home/agent/Werkstatt/keeper-p17a-dev \
  --bind /home/agent/Werkstatt/keeper-p17a-dev/.goenv/tmp /tmp \
  --setenv TMPDIR /tmp --setenv GOMAXPROCS 4 -- go test ./... -race
```

This keeps existing absolute `/tmp` fixtures physically within the authorized
task root while preserving short Unix socket paths. No shared service is
activated. Same-UID fixtures with synthetic wrong-owner metadata and a fake
generation authority do not qualify distinct-UID deployment, protected pins,
FD theft exclusion, actual Matrix/rich-checker signatures, Keymaker final
release, client response-replay comparison or production startup.
