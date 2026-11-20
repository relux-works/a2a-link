# G1-GATE-1: Matrix CG1 admission, Track A

This downstream-only v3 regtest policy is registered as `cg1-matrix` through
`internal/admission`. It verifies the unchanged Ed25519 `swarm-envelope/2`, then
a per-message BIP-340 co-signature over its exact bytes, then calls grantcheck.
The BIP-340 key that actually verifies the co-signature is the only inbound
`SenderProof.Key`. A Matrix id, display name, message claim or a protected
binding alone cannot supply that authority.

The base catch-up is PR #5 at `7fec353d1c781226d295f616e96f6d380147e7a8`, merging
upstream `86c2c30872a1e763ff87db91cf4cbe2688e37b1c` with AL1/AL2/AL2B intact.
The Nostr-only `cg1` policy remains separately registered. Upstream a2a and the
shared envelope format are unchanged. PR #4 remains independent.

## Source pins and scope

- Every chain-lab requirement in the consumer's `go.mod` is pinned to
  `09586168b906fcd700edf9a8c024190546d7d1eb`; grantcheck is
  `v0.1.2-0.20261116161722-09586168b906`. Historical exclusions remain
  exclusions, not selected versions. No other dependency is changed.
- Existing envelope library: `e38510c503d266d36a275a5976f933e10fae4060`, pinned as
  `v0.0.0-20261108162913-e38510c503d2`. Its complete `VerifyMessage` pipeline
  checks the existing schema, every Ed25519/approved approver signature,
  admitted author, root-signed attestation, active generation, signed revocation
  snapshot, audience, delivery/text, window and exact-byte id history.
- W construction, issuer/agent/landlord pins and the configured genesis stay with
  grantcheck/K1. Both inbound and outbound calls check freshly. No cached Live
  result permits another attempt. The dependency adds an immutable transport pin;
  existing unpinned Nostr state is refused unchanged. This PR performs no live
  state migration or installed adoption. The retained Nostr constructor and
  genuine-Core fixture now pass W explicitly.

This is message admission, not execution authority. The fixed consumer action
below dispatches no tools or effects. J7 enforcing key custody, mainnet, the
real owner key, v4 and T19 remain outside this slice. Track B may later replace
the co-signature with a reviewed BIP-340 envelope-author profile; the small
`cg1cosign.Verifier` interface isolates that change.

## Fork co-signature format

Matrix event content retains the existing `works.relux.swarm.envelope` string:
canonical unpadded base64url of the **original complete envelope bytes** E.
The sibling member `works.relux.cg1.cosignature` is exactly this closed object:

```json
{"version":"a2a-link-cg1-cosignature/1","key":"bip340:<64 lowercase hex>","sig":"<128 lowercase hex>"}
```

The angle-bracket values are schematic. Key bytes are a 32-byte secp256k1
x-only BIP-340 public key, lifted to its even-y point. Signature bytes are the
64-byte BIP-340 `r || s`. Encodings must be lowercase hex, with no prefix on
`sig`. Compressed 02/03 keys, algorithm aliases, wrong-curve keys, invalid
points, noncanonical scalars and algorithm substitution refuse. Duplicate or
unknown JSON members refuse. JSON object order/whitespace carries no authority.

The fixed domain is exact ASCII `a2a-link cg1 cosignature/1`. Let:

```text
T = SHA256(ASCII("a2a-link cg1 cosignature/1"))
M = SHA256(T || T || uint64_be(len(E)) || E)
co_signature = BIP340.Sign(grant_named_key, M)
```

E is 1..65536 bytes. The length occupies exactly eight big-endian bytes. No
terminating NUL or LF is appended. No envelope canonicalization, trimming,
re-encoding, content-id substitution or signature-list editing occurs. The
unchanged envelope's own Ed25519 signing preimage still comes from its existing
library. Standard BIP-340 internal nonce/challenge domains remain unchanged.
The co-signature does not replace that first verification.

The pinned btcec parser reduces overflowing `s` modulo the curve order. The
single `canonicalSignature` helper therefore checks the raw encoding **before**
`ParseSignature`: exactly 64 bytes, unsigned big-endian `r < p` and `s < n`,
where `p=fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f`
and `n=fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141`.
It then delegates parsing and the unchanged signature equation to the library.
There is no low-s policy: a fully verifying scalar greater than n/2 is an
explicit positive control. Short/long bytes, r>=p and s>=n refuse unchanged.

`TestCoSignatureMalleatedScalar` constructs a 64-byte `(r,1+n)` only after
checking `1+n < 2^256`, and shows the pinned parser maps it to `(r,1)` while
this helper refuses it. That scalar-one pair is an **encoding-only** witness,
not a claim of a mathematically valid low-s signature. Its adjacent real high-s
signature does fully verify. `TestCoSignatureOddY` retains its separate
mathematical odd-y witness; verification is never re-implemented here.

The committed public [vector](../internal/cg1/testdata/matrix-cosignature-v1.json)
contains a complete Ed25519 envelope, its raw SHA-256, co-signature digest, key
and signature. It is tested through the full adapter with protected test
attestation/revocation evidence. Its byte values are fixed:

| Value | Hex |
| --- | --- |
| SHA256(E) | `8b6ac80fc3e5ee36c82a7b80f61b5c1fddedec5c8b3a6cd92d02dbff8465d9e6` |
| M | `6b01983f16ebb80fe37dba7afc6bf432c2fdc562e223ac13f905690f534ccab0` |

## Signed presentation and delivery

The selected message uses existing `message/1` fields with
`action: "a2a.message"`, `target: {"kind":"station","id":"cg1"}` and exactly
one argument member, `cg1`. This is a consumer action schema inside the existing
arguments object; it changes no shared envelope field or algorithm.

- `arguments: {"cg1": null}` means no explicit presentation. Grantcheck may use
  only previously live-admitted public proof bytes, rechecking K1 freshly.
- Otherwise `cg1` has exactly `grant_id` (64 lowercase hex) and `proof` (an array
  of 1..6 canonical unpadded-base64url string chunks). All but the final chunk
  have exactly 4096 characters; the last has 1..4096. Concatenate, decode and
  require exact re-encoding. Complete decoded bytes must be 1..16384; they are
  never truncated or reconstructed. Grantcheck validates canonical v3 proof
  semantics. Explicit invalid/oversized proof never falls back to cache.

Chunking respects the existing envelope's 8192-byte string bound. The existing
24576-byte signing-preimage, 65536-byte envelope and 61440-byte Matrix content
budgets also apply. The co-signature binds the presentation because it signs
E containing these arguments.

Actual room, exact UTF-8 text and the local recipient are supplied separately
to `VerifyMessage`; received `room`, `to` and `body_sha256` cannot replace them.
Inbound additionally requires the credential-bound sender's protected peer
constraint to match the verified Ed25519 author and verified BIP-340 co-signer.
That pin only narrows a mathematically verified signature; it cannot replace it.

Outbound has **one envelope per recipient**. Its signed `body.to` selects an
exact authenticated configuration row, never room membership. That row's one
BIP-340 key goes to `OutboundFrom(RecipientProof{SwarmEnvelopeV2, [key]})`.
The envelope author/co-signer must be the local pinned identity. Missing or
mismatched pins refuse definitely. The counterpart's proof must already have
been admitted on this identity's inbound path or through protected provisioning
below. Both routes verify the full admission rules before caching proof bytes.
A future LIP-0015 section 6 certificate-statement resolver may replace the pin
once implemented/reviewed (grant-key signature, highest seq, open window).

## Per-identity protected configuration

Select `admission_policy: "cg1-matrix"` in the identity credential metadata.
Provision `cg1-matrix.json` under the engine-derived
`<identity-base>/admission/<identity>/`. The directory must be mode 0700 and
canonical; the configuration must be an owner-owned **regular mode-0700 file**,
with one link, at most 256 KiB. Symlinks, hardlinks, permissive or differently
mode-set files refuse; the factory never repairs them. The file mode follows
the slice-1 addendum. No CLI command manufactures trusted pins or live evidence.

Closed top-level fields:

| Field | Meaning |
| --- | --- |
| `version` | Integer 1 (legacy pay) or 2 (explicit binding) |
| `profile` | Version 2 REQUIRED: exactly `pay` or `trust`; forbidden in version 1 |
| `network` | Version 2 REQUIRED: exactly `regtest` or `main`; forbidden in version 1 |
| `genesis` | Version 2 REQUIRED: the exact lowercase genesis hash for the selected network; forbidden in version 1 |
| `identity`, `user_id` | Exact session name and credential-bound local Matrix id |
| `audience` | Exact consuming-installation audience |
| `construction_profile` | Exactly `W` |
| `agent_name`, `landlord_name`, `issuer_pubkey` | Grantcheck's protected names and lowercase BIP-340 issuer key |
| `executor_key` | REQUIRED member: valid consumer x-only BIP-340 key for pay; exactly the empty string for trust |
| `max_tip_age_seconds` | REQUIRED integer A > 0, at most 9223372036 seconds (duration representation limit) |
| `max_future_skew_seconds` | REQUIRED integer F from 0 through 600 seconds; 600 is a BENCH ceiling |
| `minimum_height` | REQUIRED integer FLOOR from 0 through 2147483647 |
| `terms` | REQUIRED nonempty map (at most 64 entries) from contract SHA256 to canonical unpadded-base64url contract bytes |
| `timeout_ms` | 1..5000, shared per-check budget |
| `rpc` | Existing Route shape: loopback IP, port, exact `w3-observer` username, read-only node password |
| `pins` | Exact carrier id to `{key, author}`; key is lowercase BIP-340 x-only hex, author is canonical Ed25519 key id; includes the local identity |
| `envelope_evidence` | Host-authenticated snapshots described below |
| `initial_watermark` | Exact UTC seconds timestamp for a newly provisioned state namespace |

Version 1 retains exactly the original pay meaning and serialized binding:
`pay`, `regtest` and the regtest genesis from `single-use.RegtestGenesis`.
The previous grantcheck constructor supplied these implicitly. Version 1
refuses all three new members, even if they name that same binding. Version 2
requires all three; a missing, null, empty, duplicate, case-variant or unknown
member/value refuses the whole policy as a configuration error. No trust
network or genesis default exists. The only admitted pairs are `regtest` with
`single-use.RegtestGenesis` and `main` with `grantcheck.MainGenesis`
(`000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770`).

Matrix, origin and Nostr share one backend construction path. The three values
are passed unchanged to CG1's `ContractProfile`, `Network` and `Genesis`;
`construction_profile: "W"` is a separate witness-construction pin. Before any
version-2 grant check, each route freshly reads the node's chain and block-zero
hash and compares both with policy. A mismatched or unreadable node observation
is retryable `verifier_unavailable`, preserving CG1's node-chain and genesis
refusal classification. Grant/configuration binding mismatches remain distinct
from node-observation failures. CG1 also retains its own chain and grant checks.

For trust, only bounded hash-addressed objects are loaded at startup. The
pinned CG1 implementation, not a second local parser, validates canonical
LIP-0013 /1 or a LIP-0014 /2 root at depth zero and binds every contract field
to Grant v3 on every admission check. Cross-profile or malformed contracts
refuse as `terms_invalid`; binding differences and empty or populated landlord
`holders` refuse as `binding_mismatch`. A nonempty trust executor refuses
construction. Children, re-delegation and unresolved scope text remain refused.
The origin mapping's `terms_profile` must agree with this protected policy.

The executor, A, F and FLOOR have **no defaults**. Missing, null, aliases,
wrong types and out-of-range values refuse startup before checker state exists.
Explicit zero F and FLOOR are valid. Pay terms are hash-checked and
re-encoded for byte equality at startup, then looked up without I/O by the
signed grant's contract hash. The grantcheck admission path compares their
executor against `executor_key` and returns `executor_mismatch` by name.
The terms map is part of this Matrix namespace's immutable configuration binding.
Provision all needed counterpart terms before opening a fresh namespace.

The **interim v3 bench rule, superseded by LIP-0022 once accepted**, is:

```text
headers == blocks
height >= FLOOR
trusted_now - tip_header_time <= A
tip_header_time <= trusted_now + F
```

The hidden age bound is **A + F**, not A. Headers ahead/behind refuse as
retryable `node_not_synced`; below-floor and old tips refuse as retryable
`tip_below_floor` and `tip_stale`. A future tip outside F refuses as `tip_future`.
The boundary exactly A is admitted; A + 1 second is refused. The underlying
checker also checks the last trusted-clock sample before committing admission.
A tight bench F can refuse consensus-valid tips: production A/F values remain
unset pending a real-node runtime probe. These settings are operator inputs,
not production recommendations or values inferred from a received message.

The retained Nostr `cg1.json` uses the same version rule and grant-policy fields,
and passes them into the sole constructor too; it retains its existing mode-0600 and 8192-byte
configuration limits. New trust/freshness pins are bound by grantcheck's durable
identity. Old state cannot reopen under changed pins; there is no automatic
migration and no instruction here to discard established state.

### Protected first-message provisioning

```sh
a2a --as IDENTITY cg1 provision --proof counterpart-presentation.json
```

This local operator command requires the selected identity's protected
`cg1-matrix` configuration. It reads one bounded regular proof file, derives
its signed-grant ID, and calls grantcheck's `Provision(ctx, Presentation)`.
There is no pin/clock/policy override flag, daemon-dispatch route or Matrix send.
It verifies canonical signed-grant and terms hashes, the **on-chain issuance
commitment**, signatures, executor, names, unspent seal, windows and fresh own-node
observations before accepting any cache bytes. A well-signed uncommitted hash
refuses as `issuance_mismatch`; no caller-provided hash establishes commitment.

Every admitted/refused provisioning attempt reaching an available checker is
recorded in its bounded durable `provisioning` audit ring (newest 64 attempts)
inside `matrix-grantcheck-state/grantcheck.json`, with grant ID, SHA256 of proof
bytes, timestamp and result. Busy/unavailable state or cancellation cannot promise
a durable record. Proof-file/open/startup failures are reported on stderr before
Provision and do not create a provisioning audit. Successful checker output is
JSON `{grant_id,result,retryable}`; exit 0 means admitted, exit 1 means refusal.
On refusal the **proof cache** is unchanged; a refusal audit and clock high-water
may change. A subsequent send still rechecks the on-chain grant from scratch.
The protected owner DM bypass retains its existing independent audience checks.

`envelope_evidence` supports only `service_root`, `agent_revocation_root`,
`attestations`, `active_generations`, `revocations`, `time`, and optional
`operator_root`, `operator_owner`, `operator_attestations`, `signer_facts`.
Use the unchanged [verifier context shapes](https://github.com/relux-works/swarma-envelope/blob/e38510c503d266d36a275a5976f933e10fae4060/verifier/README.md).
In this local file only, attestation values and each revocation `snapshot` are
canonical unpadded-base64url of their complete original signed bytes. Integers
remain exact integers. These are authenticated host inputs, not received event
fields, fetched URLs or assertions copied from a message.

The host must provide genuine trusted/fresh time authority and current signed
revocation/generation evidence. The adapter samples the current clock, rejects
rollback below its durable watermark, and supplies the qualified sample to the
verifier. It does not synthesize trusted/fresh or current-generation assertions.
Signed snapshot age remains at most the existing 60-second limit. There is no
automatic evidence fetch: refresh the private host evidence or admission holds.
All supported evidence slots and their nested field types are validated at startup;
unknown slots and malformed root, generation, revocation, time or optional device
facts refuse before any policy state is created. Signed evidence keeps its original
bounded bytes; message-time signature, authority and freshness checks still run.

The signed evidence body gate follows [the pinned specification, section 2.6](https://github.com/relux-works/swarma-envelope/blob/e38510c503d266d36a275a5976f933e10fae4060/spec/swarm-envelope-2.md#26-root-signed-attestations-and-shared-revocation):
attestation bodies have exactly type, issuer, subject, key_class, purpose, roles,
actions, iat, exp and binding. Subject algorithm/key-id/public-bytes must agree;
agent and service validity is positive and at most 86400 seconds. Agent bindings
close all six generation fields and their integer/text bounds; device and service
bindings close the one owner field. Device validity is positive, with any further
expiry restriction left to protected runtime policy. Revocations close type,
issuer, issued_at, complete=true and up to 64 closed kind/id/from entries, checking
all entries and the key-vs-content-id distinction. Empty complete snapshots are
well shaped. Unknown/missing members, wrong nested types and out-of-range values
refuse before either binding is persisted.

This is **shape only**. It does not verify signatures, recompute content ids,
resolve issuing-root authority or current generations, or establish freshness.
The original signed bytes are never normalized, replaced or re-signed. The full
runtime verifier still owns those checks; a well-shaped bad signature can pass
startup but cannot reach grantcheck. This consumer recognizes the section-2.6
Ed25519 agent, P-256 operator-device and Ed25519 service body profiles. The
section-3.5 Mac-agent and grant-revocation-publisher extensions are unsupported
by this Ed25519 Matrix slice and refuse rather than taking a partial shape path.

`TestMatrixSignedEvidenceBodies` pairs each field/profile refusal with a valid
same-namespace startup control; its field-level source-overlay plants retain the
outer signed carrier. Boundary controls cover numeric/text maxima and minima,
exact 86400-second windows, 64 entries and empty snapshots. The registration
integer above 2^53-1 is also rejected by the shared CCJ reader before body intake;
a typed helper control checks that upper bound without pretending it can be
encoded as a valid CCJ-1 record.
The file is read afresh for each check and again before accepting a Live result.
Grant work crossing an envelope/evidence expiry cannot use that result.

All immutable route, issuer, identity, audience, key and root pins bind the
private journal. Changing those pins inside an existing state namespace refuses;
this is not a silent key-rotation or cache-adoption mechanism. Time/snapshot and
attestation evidence may refresh within those pins. The node client retains the
read-only method allowlist, redirect refusal, regtest/genesis checks in K1,
bounded cooperative context and explicit Close lifetime.

## Durable history and owner DM

The identity owns separate mode-0700 directories:

- `matrix-cg1-state/`: private lock, watermark and up to 256 accepted envelope-id
  records, plus exact original envelope byte files; mode-0600 durable files.
- `matrix-grantcheck-state/`: grantcheck/K1's exclusive state namespace and its
  transport-pinned admitted-public-proof cache. An envelope ledger is never
  placed in grantcheck's initially empty namespace.

Startup serializes construction, validates any existing journal binding without
rewriting it, and constructs the real backend before atomically committing a new
envelope binding. A rejected first startup removes only its newly created binding
files; existing accepted history is never reset. Correcting an invalid backend
configuration can therefore start in that same previously unopened namespace.

Persist exact bytes/id/watermark before permitting mailbox delivery or sending.
A different wire encoding for an accepted id, replay as another event, or a
transaction switching to a different signed record refuses. The same exact
event/transaction retry remains eligible only after all checks run freshly.
The identity key is the signed envelope id/content, never co-signature bytes.
`TestMatrixCosignatureIndependentReplay` signs the same exact envelope twice
with distinct nonce inputs and verifies both BIP-340 signatures. Inbound and
outbound each retain one ledger/byte record: a second event/transaction refuses
as replay, while the same delivery retry freshly rechecks without creating a
new message identity. The control covers the adapter ledger, not a separate
claim about downstream mailbox exactly-once delivery.
Missing/corrupt state, interrupted writes, lock contention and capacity refuse;
no automatic eviction or history reset creates permission. Retention is bounded
for this test bench; reaching 256 records needs explicit owner recovery or a
new properly provisioned namespace. This is not a qualified anti-rollback store
against same-UID/root restoration.

Owner DM remains outside peer admission using the existing protected owner pin
and active exact room, current private two-party audience and, inbound, the
actual pinned owner sender. No event flag, another sender/room, pending binding
or changed audience can obtain that bypass. Other policies retain their existing
routing. The CG1 adapter itself has no owner-bypass message field.

## Fixture helper and CLI carrier

Only deliberately public fixture scalars `alice=1`, `bob=2` are compiled into the
helper. It accepts no private-key path, environment key or real identity. Do not
use these fixtures for real grants or enforcing mode. The helper signs opaque
bytes only; the receiver still performs full envelope verification.

```sh
go run -p 1 ./cmd/g1-fixture-sign --fixture bob --envelope envelope.json > cosignature.json
a2a post ROOM --topic TOPIC --envelope @envelope.json --cg1-cosignature @cosignature.json 'exact text'
```

`--cg1-cosignature` requires one explicit `@file` beside `--envelope`, bounded to
2048 bytes and strict object JSON. It is not accepted with durable plain-post
mode; existing voice/envelope exclusions apply. The daemon uses the existing
explicit input-streaming boundary for both files, never an ambient station path.
The ordinary no-co-signature carrier remains byte-compatible. Selecting the
policy supplies authentication, not the flag alone.

## Validation tools and limits

The envelope unit fixtures use a synthetic logical clock and a generous real
30-second operation budget so hosted race contention does not invalidate positive
clock-progress and transaction-retry controls. Reopened fixtures inherit that
budget. `TestMatrixPositiveControlSlowGrant` witnesses work beyond one second;
`TestMatrixRecheckAfterGrant/deadline` still explicitly sets one second and proves
retryable refusal with unchanged history. Production timeouts are unchanged.

Every added test has a claim comment. Positive/negative controls use real
existing envelope verification and BIP-340 signatures. The plainly named
`fakeGrantcheckVerdicts` isolates the adapter boundary; it is never constructed
by production registration and does not attest a live chain grant. The actual
factory constructs the pinned `NewForTransport(..., SwarmEnvelopeV2)` backend.

Run with task-owned caches/temp, Go `-p 1 -parallel 2`, and umask 022 for the
existing permission-refusal fixtures. The fixed mutation runner uses source
overlays, records each child PID/exit, rejects unrelated failures, verifies
source hashes, and requires restored positives. It never edits product sources.

```sh
go test -p 1 -parallel 2 -race -count=1 ./internal/cg1 ./internal/cg1cosign ./internal/admission ./internal/nostrsession ./cmd/g1-fixture-sign -skip '^TestCore(Admission|NostrSession)$'
go test -p 1 -parallel 2 -race -count=1 ./internal/cli ./internal/daemon -run '^(TestCG1Matrix|TestCG1Cosignature)'
go run -p 1 ./.scripts/g1-matrix-mutants --root . --out .temp/g1-matrix-mutants
go build -p 1 ./...
go vet -p 1 ./...
go mod verify
go run -p 1 ./.scripts/check-g1-dependencies --repo CHAIN_LAB_CHECKOUT
```

Use a fresh mutation output directory; its baseline, mutant and restored logs
and `results.json` are the evidence. A survivor must retain its explicit bound.
The scalar-format regression was added after an initial plant survived because
signature math still refused its test input; later controls target the encoding
gate directly. An unrelated compile error does not count as a killed mutant.

Two-consumer Phase A acceptance is separate from these adapter regressions.
Full terminal/native daemon qualification, independent review, hosted checks,
deployment and two-consumer live acceptance remain separate gates. The brief
has no surface table; that gap does not claim coverage outside the listed tests.

## Executor, freshness and provisioning validation

```sh
go run -p 1 ./.scripts/check-g1-dependencies --repo CHAIN_LAB_CHECKOUT
go test -p 1 -parallel 2 -count=1 ./.scripts/check-g1-dependencies
go test -p 1 -parallel 2 -race -count=1 -timeout 5m ./internal/cg1 ./internal/cg1cosign ./internal/cli -run '^(TestMatrix|TestCoSignature|TestFixture|TestCG1|TestRequiredGrantPolicy|TestGrantPolicy|TestReasonMapping)'
go build -p 1 -o .temp/g1/a2a ./cmd/a2a
CG1_REGTEST=1 CG1_RUN_ROOT=NEW_ABSOLUTE_SCRATCH CG1_CORE_DAEMON=PINNED_NAMECOIND CG1_CORE_CLI=PINNED_NAMECOIN_CLI CG1_A2A_BINARY=ABSOLUTE_BUILT_A2A go test -p 1 -parallel 2 -count=1 -timeout 5m -run '^TestCoreMatrixPolicy$' -v ./internal/cg1
```

Use a fresh `CG1_RUN_ROOT` for each of `TestCoreMatrixPolicy`,
`TestCoreAdmission` and `TestCoreNostrSession`. The harness refuses unknown or
mixed Core binary pairs. It accepts the retained macOS pair and the official
Core 28 Linux pair, pinned by SHA256 in `core_helpers_test.go`. Each isolated
node is started, signaled and joined by its exact owned PID. Only generated
fixture custody is used; private Core directories must not be published.

`TestCoreMatrixPolicy` uses the real `admission.Open("cg1-matrix")` factory,
Ed25519 envelopes and BIP-340 co-signatures against genuine Core grants. The
headers test alters only the RPC header-count observation. The frozen-floor
test records public answers, mines a newer real block and replays that old
consistent view; its trusted floor distinguishes the new view from the old.
The age equality test uses a controlled trusted-clock sample with recorded
real Core RPCs, live at A and refused at A+1 second after a newer block is mined;
that clock seam is not a wall-clock runtime qualification. Provisioning tests
use the factory's wall clock and both populated and cold cache controls; the
uncommitted witness is re-signed by the genuine fixture issuer but retains an
issuance locator committing to another hash. The command test invokes the
fresh production binary, never a stub. With no binary variable it explicitly
skips that subtest; with no `CG1_REGTEST=1` the entire Core suite explicitly skips.
The owner-DM test remains `TestCG1MatrixOwnerDMBypass`.

The full terminal/daemon suite is separate: some inherited fixtures invoke
terminal multiplexers or hard-code scratch outside a selected root. These
focused commands do not qualify installed adoption, a live Matrix exchange,
terminal delivery, mainnet, production A/F, or the later Phase A rerun.

The genuine-Core policy controls use the selected grantcheck module via Go source
overlays, never edits to its cache:

```sh
CG1_REGTEST=1 CG1_CORE_DAEMON=PINNED_NAMECOIND CG1_CORE_CLI=PINNED_NAMECOIN_CLI CG1_A2A_BINARY=ABSOLUTE_BUILT_A2A go run -p 1 ./.scripts/g1-matrix-mutants --root . --out .temp/g1-policy-mutants --core-policy
```

Go forbids module-cache overlays, so this mode copies the exact selected module
into its private fixture, compares the planted files with their originals, and
uses a replacement only in an alternate test modfile. Product `go.mod` and the
module cache stay untouched. The runner allocates a fresh `CG1_RUN_ROOT` for each baseline, mutant and restored
child, records exact PIDs/exits and named failure diagnostics, and verifies all
original source hashes. It refuses a missing opt-in/binary environment. The
seven fixed plants cover executor, header equality, trusted floor, frozen-view
age A+1, a genuine two-hour-future Core tip, cache preservation on a refused spent
proof, and durable provisioning audit. An unrelated build/setup failure or a
skip is never a successful control. The original mode retains its 76 controls.


## Current identity expiry and RPC error classification

Either current identity expiring yields `Refused / identity_expired`, nonretryable,
with grantcheck's closed bit required on both adapters and both directions.
Cached proof re-checks make a fresh chain observation. This closure describes the
current identity observation; it does not permanently revoke the grant. A
same-value `name_update` before expiry renews the identity without invalidating
the admitted grant. Core does not permit ordinary renewal after expiration.

The session-owned RPC client matches #116's strict JSON-RPC 1.0 envelope rule:
exactly `id`, `result`, `error`; integer id 1; explicitly null result beside a
non-null error; a valid integer code and string message; strict JSON including
duplicate-member and trailing-data rejection. A complete error is an application
answer even at HTTP 500/503. Only Core's exact code -4 expired-name messages on
`name_show` establish expiry. Other application errors remain typed, never logged
as remote text, and retain the existing definite policy-failure mapping.
Transport failure, malformed bodies and success-shaped non-200 replies remain
retryable `verifier_unavailable`. Matrix's envelope-clock/evidence unavailable
classification remains `dependency_unavailable`.

At this snapshot the kernel recognizes the successful `allowExpired` name
projection, but its receipt boundary reduces a typed RPC application error to
`check_failed`. A request-local, atomic typed-answer marker preserves an exact
expired-name answer through that boundary. It refines only an existing definite
`Refused / check_failed` to closed `identity_expired`; it cannot turn any refusal
into Live, overwrite another failure, survive another request, or bypass the
backend check. It contains no name, credential, proof bytes or remote text.
Cancellation/lifetime checks still precede message admission. Protected
provisioning uses the same refusal classifier; grantcheck retains its own audit
of the underlying refusal and accepts no proof from that refusal.

```sh
go test -p 1 -parallel 2 -race ./internal/cg1 ./internal/admission
CG1_REGTEST=1 CG1_RUN_ROOT=NEW_ABSOLUTE_SCRATCH CG1_CORE_DAEMON=PINNED_NAMECOIND CG1_CORE_CLI=PINNED_NAMECOIN_CLI go test -p 1 -parallel 2 -race -count=1 -timeout 5m -run '^TestCoreIdentityExpired$' -v ./internal/cg1
CG1_REGTEST=1 CG1_CORE_DAEMON=PINNED_NAMECOIND CG1_CORE_CLI=PINNED_NAMECOIN_CLI go run -p 1 ./.scripts/g1-matrix-mutants --root . --out .temp/identity-mutants --identity
```

`TestCoreIdentityExpired` exercises the real registered Nostr and Matrix factories,
real issued grants, mined identity expiry and same-value renewal, signed Matrix
envelopes/co-signatures, cached re-checks and a stopped Core node. Both identity
roles have independent isolated Core instances. Its explicitly declared HTTP
`name_show` fault seam compares missing-result, non-null-result and missing-id
refusals with complete expired and unrelated application-error controls; all
other RPCs and grant issuance remain genuine Core. After each fault, the same
checkers must admit the real live chain again. The broader RPC unit matrix checks
HTTP 200/500/503, duplicate/trailing JSON, malformed error fields and matching id.
`TestNodeAnswerScope` bounds the refusal marker to one call and one classification.

The `--identity` mutation suite names each intended failure in `results.json`,
checks restored positives and unchanged source hashes, and covers RPC expiry,
missing/null result, missing id, strict JSON, HTTP-success status, exact expiry
code, closed expiry routing, node-down routing and request isolation. Core is
opt-in and otherwise explicitly skipped; hosted ordinary Go tests do not claim
Core coverage. No real owner identity, live transport delivery or installed
adoption is exercised by these fixtures.
