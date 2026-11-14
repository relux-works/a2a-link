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

- Grantcheck PR #100: `f2a20c40a817b650585c568104fd331d6c6348db`, pinned as
  `v0.1.2-0.20261114114327-f2a20c40a817`. This is an under-review dependency,
  not a main adoption claim; re-pin through review after its main landing.
- Existing envelope library: `e38510c503d266d36a275a5976f933e10fae4060`, pinned as
  `v0.0.0-20261108162913-e38510c503d2`. Its complete `VerifyMessage` pipeline
  checks the existing schema, every Ed25519/approved approver signature,
  admitted author, root-signed attestation, active generation, signed revocation
  snapshot, audience, delivery/text, window and exact-byte id history.
- W construction, issuer/agent/landlord pins and regtest genesis stay with
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

The btcec parser reduces `s` modulo the curve order. This verifier additionally
requires `ParseSignature(raw).Serialize() == raw` before signature math, so the
fork never silently admits a normalized wire scalar. `TestCoSignatureOddY`
constructs a correctly encoded odd-y R witness under this exact M; the scalar
regression separately tests encoding refusal rather than relying on a later
mathematical failure.

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
been admitted on this identity's inbound path; there is no bootstrap bypass.
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
| `version` | Integer 1 |
| `identity`, `user_id` | Exact session name and credential-bound local Matrix id |
| `audience` | Exact consuming-installation audience |
| `construction_profile` | Exactly `W` |
| `agent_name`, `landlord_name`, `issuer_pubkey` | Grantcheck's protected names and lowercase BIP-340 issuer key |
| `timeout_ms` | 1..5000, shared per-check budget |
| `rpc` | Existing Route shape: loopback IP, port, exact `w3-observer` username, read-only node password |
| `pins` | Exact carrier id to `{key, author}`; key is lowercase BIP-340 x-only hex, author is canonical Ed25519 key id; includes the local identity |
| `envelope_evidence` | Host-authenticated snapshots described below |
| `initial_watermark` | Exact UTC seconds timestamp for a newly provisioned state namespace |

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

Persist exact bytes/id/watermark before permitting mailbox delivery or sending.
A different wire encoding for an accepted id, replay as another event, or a
transaction switching to a different signed record refuses. The same exact
event/transaction retry remains eligible only after all checks run freshly.
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
go mod tidy -diff
```

Use a fresh mutation output directory; its baseline, mutant and restored logs
and `results.json` are the evidence. A survivor must retain its explicit bound.
The scalar-format regression was added after an initial plant survived because
signature math still refused its test input; later controls target the encoding
gate directly. An unrelated compile error does not count as a killed mutant.

Real opensource PR #101 bench end-to-end acceptance is omitted in this PR.
No always-skipping integration placeholder is added. Existing genuine-Core,
full terminal/native daemon qualification, independent review, hosted checks,
deployment and two-consumer live acceptance remain separate gates. The brief
has no surface table; that gap does not claim coverage outside the listed tests.
