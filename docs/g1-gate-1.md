# G1-GATE-1: catch-up and Matrix admission prerequisites

This first draft brings a2a-link onto the exact upstream a2a-swarm commit
`86c2c30872a1e763ff87db91cf4cbe2688e37b1c`, retaining the published AL1, AL2 and
AL2B history through a merge. It preserves Nostr CG1 admission and opaque Matrix
envelope carriage. It does not enable CG1 on Matrix.

The merge retains the fork's Go 1.26 floor, Nostr transport v0.3.0 and grantcheck
v0.1.0 dependencies, and upstream's E2EE dependencies and x/net v0.58.0 update.
The CLI selection guard uses the upstream daemon name/engine after the Courier
rename. PR #4 remains independent and must be refreshed and revalidated by its
owner after the catch-up lands.

## Matrix prerequisite and exact interface

T23 permits grant admission over Matrix only from the BIP-340 key that actually
verified the signed swarm-envelope/2, never from Matrix sender/display metadata.
The approved outbound rule requires every signed addressee key to pass a fresh
live grant check on every attempt; no addressees means definite refusal.

The current [waggle message schema](https://github.com/relux-works/waggle/blob/e38510c503d266d36a275a5976f933e10fae4060/spec/swarm-envelope-2.md#21-closed-schemas-and-limits)
requires an Ed25519 author, one opaque carrier recipient identifier, and a closed
message body. Its [signature profiles](https://github.com/relux-works/waggle/blob/e38510c503d266d36a275a5976f933e10fae4060/spec/swarm-envelope-2.md#24-exact-domain-registry-and-key-profiles)
do not admit BIP-340. The [Matrix carrier](cli.md#carrying-a-swarm-envelope---envelope-file)
only carries opaque bytes and publishes no alternate signature, addressee-key
or canonical v3 grant-presentation schema. Neither an Ed25519-to-BIP-340
conversion nor an invented envelope extension establishes the required sender.

A proposed recipient-side design resolves the one signed `body.to` through a
host-authenticated per-identity exact carrier-id to BIP-340 key pin, with one
envelope per recipient and definite refusal for absent or mismatched binding.
It fits the recipient API without room membership or a new key-array field.
A future LIP-0015 certificate-statement lookup can replace that pin after its
implementation and review. This binding is distinct from grant authority.

The sender requirement remains unresolved: a looked-up BIP-340 grant key is not
the Ed25519 key that verified the envelope. Before the adapter can be implemented,
the protocol owner must identify or approve a reviewed BIP-340 envelope profile,
or explicitly change that sender acceptance contract. The consumer also needs
the reviewed presentation-carriage schema, signature preimage/canonicalization,
delivery binding and replay rules. The proof limit is
16384 decoded bytes. No Matrix CG1 registration, fake production Live verdict,
or replacement wire format is introduced by this catch-up.

The requested grantcheck API is:

```go
func NewForTransport(Config, Transport) (*Checker, error)
func (*Checker) InboundFrom(context.Context, SenderProof, *Presentation) Verdict
func (*Checker) OutboundFrom(context.Context, RecipientProof) Verdict
func (Verdict) A2ADecision() (verdict, reason string, retryable bool)
```

Construct with `SwarmEnvelopeV2`; use its immutable provenance pin for both
`SenderProof.Key` and every `RecipientProof.Keys` entry. The proposed API in
chain-lab PR #100 fits these requirements, provided the envelope-profile
lifecycle mapping is corrected as below. The legacy Nostr API remains separate.

| Envelope-profile result | a2a verdict | Reason | Retryable |
| --- | --- | --- | --- |
| Valid fresh Live | Live | allowed | false |
| Explicit permitted inbound-only | Exchange inbound; Refused outbound | exchange; exchange_outbound | false |
| Missing grant, not yet valid, expired, spent seal, landlord rotated/changed | Refused | denied | false |
| Binding mismatch, invalid peer/presentation, oversized proof, missing/bad envelope, replay | Refused | denied | false |
| Verifier unavailable, stale node/height, invalid clock, cancellation, busy, identity/grant pending | Refused | dependency_unavailable | true |
| State unavailable | Refused | storage_error | true |
| Known definite internal check failure | Refused | policy_error | false |
| Unknown or inconsistent tuple | Refused | policy_invalid | false |

A legacy lifecycle Exchange is not permission to turn an expired or spent grant
into an envelope-profile Exchange. Unknown combinations fail closed.

## Follow-up acceptance

The host-provisioned W profile needs `admission_policy`, issuer/agent/landlord
pins, the issuer public key, a separate 0700 state directory per identity and
transport pin, 0600 metadata and read-only regtest RPC through `w3-observer`.
The existing owner-DM route must remain outside peer grant admission. No live
credentials, services, owner keys, mainnet or installations are changed here.

After the wire contract is resolved, the Matrix adapter needs positive controls
beside missing envelope, bad signature, Matrix-id substitution, oversized proof
and owner-DM bypass checks, plus a narrowing mutant for each check. It also needs
all-addressee, no-addressee, fresh-retry and binding/replay controls. Fake
**grantcheck verdict** sources belong only in explicitly named tests and cannot
stand in for a verified-envelope parser. A live integration test must use the
opensource regtest bench and real grantcheck; only absent bench may skip. No
placeholder integration test claims that acceptance in this catch-up.

The supplied brief contains no surface table. This is a brief gap; this draft
claims only merge compatibility, not Matrix admission coverage. No contract rows
are silently treated as implemented or out of contract.

## Validation tools

Run with task-owned caches and temporary files. These checks do not qualify
Matrix live-grant acceptance or native daemon deployment:

```sh
# The permission-refusal fixture needs a permissive requested file to stay permissive.
umask 022
go test -p 1 -parallel 2 -race -count=1 -timeout 5m -json ./internal/cg1 ./internal/admission ./internal/nostrsession
go test -p 1 -parallel 2 -race -count=1 -timeout 5m -json ./internal/cli -run '^(TestAdmission|TestCG1|TestNostr|TestEnvelope|TestPostEnvelope|TestReadEnvelope|TestVerificationInputUnaffectedByEnvelopeMode)' -skip '^TestAdmission(DaemonIdentity|OutboundJournalRefused)$'
go test -p 1 -parallel 2 -race -count=1 -timeout 5m -json ./internal/matrix
go build -p 1 ./...
go vet -p 1 ./...
go mod verify
go mod tidy -diff
git diff --check
```

The two excluded CLI functions were run and failed under the assigned workspace: `TestAdmissionDaemonIdentity` refuses unsafe enrollment ancestry; `TestAdmissionOutboundJournalRefused` refuses the group-writable journal ancestry and reproduces at the original fork head `eb2c77b`. These results remain failing evidence, not passing checks. Further daemon execution is excluded because its fixtures hard-code scratch directories outside the assigned write root. The focused rerun is only the compatible subset.

Logs and JSON test counts belong in task-owned `.temp/` evidence. The gated real
Core tests remain skipped unless their isolated bench is provisioned. Terminal
fixtures are not run by these focused commands. Full hosted checks, designated
review and keeper landing remain independent gates.

The added `TestNostrNamespacePreservesDaemonRouting` runs a valid daemon help
control, invalid enrollment refusal and an unprovisioned daemon-engine identity
refusal, both before and after adding malformed Nostr host metadata. It checks
that the result stays identical and no Nostr transport or metadata mutation
occurs. It does not qualify authenticated daemon enrollment or live traffic.

| Narrowing mutant | Gate narrowed to | Named failing test | Result |
| --- | --- | --- | --- |
| Remove daemon-command exclusion from Nostr selection | Local daemon argv bypass | `TestNostrNamespacePreservesDaemonRouting/help` and `/invalid-enrollment` | Killed, intended routing assertion, exit 1 |
| Remove daemon-engine exclusion from Nostr selection | Authenticated engine bypass | `TestNostrNamespacePreservesDaemonRouting/engine` | Killed, intended routing assertion, exit 1 |

The unmodified controls pass before the overlays and on a separate restored
run. The overlays do not alter product source. There are no surviving mutants
in this two-mutant catch-up check; none of the planned Matrix admission mutants
has been implemented or run.
