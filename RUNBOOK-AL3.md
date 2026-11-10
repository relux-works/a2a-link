# AL3: two-process CG1 session smoke

AL3 prepares a local laboratory and a parameterized worker for two remote hosts.
Only local loopback runs are producer-qualified. Infra owns all VM provisioning,
transfer, service policy and remote execution. Remote targets are two approved
rt-* VMs using rt-demo's relay; a later public demo1 relay is a separate run.
No host action is performed by this harness.

## Accepted boundary

Both measured workers use production `nostrsession.Open/Send/Sync/ReadInbox` with
CG1. Real reciprocal regtest grants and admission are mandatory preconditions.
The local test registers both agents on one genuine Namecoin chain, issues
through real K1 `rental.IssueGrant`, and bootstraps by authentic proof-bearing
NIP17 messages into production CG1 Sync. Only this explicit provisioning phase
uses raw transport. No fabricated cache, trusted-tuple injection or policy-none
session establishes CG1 admission. Fresh guarded outbound refuses `no_grant`.

Pinned swarma-relay v0.2.0 does not store kinds10002/10050 (`store.go:40`).
Discovery publication is **not exercised**. All read/write/dm/discovery relay
arrays contain exactly the supplied URL, the route queries return empty, and
transportv0.3.0 uses its existing configured-write fallback. The ACKed send
journal supplies the observed selected routes. This is observed-only routing,
not an enforced egress allowlist. RL2 owns replaceable-event relay support;
TN3/TN4 separately own routing pinning and more detailed transport codes.

The worker requires an empty ordinary inbox at start. A receives one pong; B
receives one ping and replies. Evidence is fsynced before inbox receipt. Success
means peer production inbox delivery and relay ACK, not human display. A process
failure after output but before receipt may leave output and a pending record;
preserve both and investigate rather than reuse a run ID or delete state.

## Source and binary pins

- a2a-link: the exact signed AL3 delivery head recorded in REPORT and source.bundle;
  parent `eb2c77b43c5bf627397402934564dede2e40a060`.
- Published transport dependency: v0.3.0; no replace or vendored workaround.
- Relay source: signed `experiments/relay/v0.2.0`, tag object
  `1e297dbc224d4d0f2ed54d8e0b25b1d46b01262a`, commit
  `59773ed1becce26b8696a64f4db2969219c5aac5` in swarma-chain-lab.
- Published Linux relay artifact: `swarma-relay-linux-amd64`, SHA256
  `33d50b8d7c791b24ccc4d9a0958e009cd3605114a05900f5d35a443f252d5070`,
  release <https://github.com/relux-works/swarma-chain-lab/releases/tag/experiments/relay/v0.2.0>.
- Local Darwin relay is built from that exact source and independently hashed;
  its bytes must never be compared to the Linux artifact as if interchangeable.
- Go1.26.8; build commands below use CGO_ENABLED=0, -trimpath, -buildvcs=false.
  No Linux binary is executed on the producer Mac.

## Local laboratory mode

Use a new absolute physical task root, with clean source checkouts under
`$AL3_ROOT/work` (accepted AL3 head) and `$AL3_ROOT/relay` (exact relay tag).
All HOME/config/cache/temp directories and the module cache belong beneath
this root. Start with a sanitized environment, GOTOOLCHAIN=local, GOENV/GOWORK=off,
GOTELEMETRY=off and the Go1.26.8 SDK read-only. Supply only the pinned external
Core binaries as read-only inputs. Keep one cache per unit, inspect its size at
phase boundaries, and trim completed caches after evidence is sealed.

From the clean AL3 checkout, with the isolated environment already established:

```sh
go build -mod=readonly -trimpath -buildvcs=false -o "$AL3_ROOT/bin/al3-smoke" ./cmd/al3-smoke
go build -mod=readonly -trimpath -buildvcs=false -o "$AL3_ROOT/bin/al3-verify" .scripts/al3-verify.go
go -C "$AL3_ROOT/relay/experiments/relay" build -mod=readonly -trimpath -buildvcs=false -o "$AL3_ROOT/bin/swarma-relay" ./cmd/swarma-relay
```

Set these non-secret test inputs to exact paths/hashes:

```sh
export AL3_LOCAL=1 CG1_REGTEST=1
export CG1_RUN_ROOT="$AL3_ROOT/local-run-01"
export CG1_CORE_DAEMON=/absolute/pinned/namecoind
export CG1_CORE_CLI=/absolute/pinned/namecoin-cli
export AL3_WORKER_BINARY="$AL3_ROOT/bin/al3-smoke"
export AL3_RELAY_BINARY="$AL3_ROOT/bin/swarma-relay"
export AL3_WORKER_BINARY_SHA256="$(shasum -a 256 "$AL3_WORKER_BINARY" | cut -d ' ' -f 1)"
export AL3_RELAY_BINARY_SHA256="$(shasum -a 256 "$AL3_RELAY_BINARY" | cut -d ' ' -f 1)"
go test -mod=readonly -count=1 -timeout 5m -v ./internal/cg1 -run '^TestCoreAL3TwoProcess$'
```

The helper pins Core daemon SHA256
`86b85483da23c83f7de134a5bf28bad8e3c6a8dbfe2af71a5e889a7b1547787f`
and CLI `5cccdfe19aef6b427373c200bda72d4dd66b5be2c5f93b7e8b08b9d6a81fdd4d`.
An unrelated installed version must not silently replace them. The test creates
`local-run-01-first` and `local-run-01-second`, refusing existing roots. It binds
Core RPC and relay only to127.0.0.1; Core P2P is disabled. Generated fixture keys
and credentials stay in private task scratch and are never exported. The public
issuance/presentation evidence contains grant IDs and issuance txids. Public
outputs include both worker transcripts, selected route observations, normalized
results, process PIDs and a bounded negative-control summary. The two fresh runs
must independently validate and then yield identical normalized output.

The standalone swarma-relay process is used for the positive exchange and
outsider/replay/wrong-recipient/forged-rumor checks. A separately labelled
malicious-response WebSocket fixture returns a forged signature plus duplicate
valid events, paired with a real-grant valid neighbor. It is not the relay under
qualification. Ordinary mailbox/output remains unchanged for rejected traffic;
authenticated drop/dedup checkpoint bookkeeping may advance. Existing AL2 fault
seams test before/after mailbox append, restart and receipt-after-output.

## Remote prerequisites — Infra must supply these first

Each host needs an approved fresh existing Nostr identity, its private
`<config-root>/nostr/<identity>/` directory0700, session.json0600,
transport/identity.key0600, and admission/cg1.json0600. Use native host
provisioning; do not put private bytes in flags, terminal output or transcripts.
Each cg1.json names its own actual chain agent, landlord/issuer key and a
read-only localhost observer route. Both names and both unspent grants must be
live on the same approved regtest chain. No mainnet defaults or fabricated cache.

session.json must select `admission_policy: "cg1"`; its host presentation must
be the real grant authorizing this identity at the other peer. Each of
`read_relays`, `write_relays`, `dm_relays`, `discovery_relays` is the JSON-encoded
single-element array of the supplied relay URL. Remote use normally supplies
`wss://...`; plaintext ws is accepted only for literal127.0.0.1. The endpoint must
support the NIP17 relay subset and empty discovery query behavior above.

Both peers must already have received and verified each other's proof through
production CG1 Sync, as in the explicit local provisioning phase. Archive their
public grant IDs, issuance txids and presentation hashes. Consume only the
identified provisioning records through normal successful output/receipt, so
ordinary inboxes are empty. This smoke worker does not provision remote custody,
issue remote grants, copy admission stores or bypass Outbound. If Infra has no
authorized provisioning procedure satisfying this precondition, stop there;
remote qualification is unavailable until that procedure is provided.

Install only verified signed-packet binaries. Build the worker/verifier for
linux/amd64 from the accepted AL3 head using the same flags, then record hashes;
producer cross-builds are compilation evidence, not Linux runtime acceptance.
No existing host identity, binder or service may be stopped to claim a fresh run.

## Exact worker commands per host

Agree one fresh16-hex run ID, each public key, and the approved relay URL.
`CONFIG_A`, `CONFIG_B`, `OUTPUT_A`, `OUTPUT_B` are canonical absolute paths;
output files must not exist. Identity namespaces must already satisfy the
prerequisites. Run B and then A within the bounded60-second window. In the
owning shell on host B:

```sh
/absolute/bin/al3-smoke -config-root "$CONFIG_B" -identity "$IDENTITY_B" -peer "$PUB_A" -relay "$RELAY_URL" -role b -run-id "$RUN_ID" -timeout 60s -output "$OUTPUT_B" > "$LOG_B" 2>&1 &
AL3_B_PID=$!
printf '%s\n' "$AL3_B_PID" > "$PID_FILE_B"
wait "$AL3_B_PID"
```

On host A:

```sh
/absolute/bin/al3-smoke -config-root "$CONFIG_A" -identity "$IDENTITY_A" -peer "$PUB_B" -relay "$RELAY_URL" -role a -run-id "$RUN_ID" -timeout 60s -output "$OUTPUT_A" > "$LOG_A" 2>&1 &
AL3_A_PID=$!
printf '%s\n' "$AL3_A_PID" > "$PID_FILE_A"
wait "$AL3_A_PID"
```

Both exit0. A's JSONL sequence is ready, sent:ping, received:pong, complete;
B's is ready, received:ping, sent:pong, complete. Each received ID equals the
other worker's sent ID, sender/recipient match the agreed keys, sent routes
contain exactly self/peer mapped to the supplied relay, and pending is0.
Collect only the two public JSONL files through approved transfer, then:

```sh
/absolute/bin/al3-verify -a "$OUTPUT_A" -b "$OUTPUT_B" -a-key "$PUB_A" -b-key "$PUB_B" -relay "$RELAY_URL" -run-id "$RUN_ID" > "$NORMALIZED_OUTPUT"
```

The verifier refuses missing/duplicate/reordered rows, mismatched IDs, wrong
sender/recipient/payload, remaining pending work and route drift before
normalization. An identical string alone is not acceptance. Remote provenance,
TLS and host isolation remain Infra evidence, not producer conclusions.

## Failure, stop and cleanup

Closed error `al3: smoke refused` intentionally withholds private details.
Preserve output, journal and logs; inspect through approved private tooling.
Do not delete an inbox or receipt to get a passing rerun. A partial run uses
fresh reviewed output paths only after its durable state is understood.

The local test records each owned PID and terminates only those processes during
cleanup. For a remote emergency stop, the owning host/operator verifies its
recorded live PID, then uses `kill -TERM "$AL3_A_PID"` or the corresponding B PID
and waits for it. Never kill by name/pattern or stop a peer host's service. Relay
and Core lifetime belongs to Infra, not the worker. Preserve task evidence and
private custody until reviewed; remove only explicitly owned disposable scratch
and caches after sealing, never live identity directories.

## Guard calibration and limits

From an exact clean accepted checkout under the isolated environment:

```sh
go run .scripts/al3-guards.go -task-root "$AL3_ROOT" -out "$AL3_ROOT/guards-01"
go test -mod=readonly -count=1 ./internal/nostrsession ./internal/al3smoke
```

The guard runner archives exact HEAD into separate owned mutant trees and
requires intended failing assertions, not compilation errors/crashes. Positive
baselines run first. It records commands, PIDs, exits and logs. It never mutates
source or remote status. Producer acceptance is independent-review pending;
publication and landing belong to the orchestrator.
