# Origin producer qualification (downstream)

`docs/source-origin.md` names the cryptographic truth of a produced origin as a
**downstream producer qualification obligation**. This document states which
of those obligations the downstream tests cover and which they do not. An
obligation that is not covered stays open. Nothing here enables the endpoint,
installs a service or turns enforcement on.

## What is built

| Part | Location |
| --- | --- |
| Producer and session (`runorigin.Producer`, `runorigin.Session`) | `internal/originproducer/producer.go` |
| Protected host mapping | `internal/originproducer/mapping.go` |
| Retained-event store (the agent's durable mailbox) | `internal/originproducer/store.go` |
| Contract profile seam `termsProfile`, pay profile only | `internal/originproducer/terms.go` |
| Typed refusals | `internal/originproducer/refusal.go` |
| Single construction point with the refusing default (Linux) | `internal/originproducer/service_linux.go` |
| Read-only origin checker on the existing Matrix admission path | `internal/cg1/origin.go` |

No command, daemon path or installer calls the construction point. It is a
constructor only. Without a complete protected configuration it links no
producer, and the upstream endpoint then advertises no operation and answers
`origin_not_supported`.

## Protected mapping

One JSON document, version 1, closed and exact:

```json
{"version":1,"launcher":{"uid":7001,"generation":3},"agents":[{"input_principal":{"uid":4242,"generation":19},"identity":"alice","connection":"example","matrix_user_id":"@alice:example.invalid","policy":"cg1-matrix","terms_profile":"pay","keymaker_registration":"opaque-registration","store_base":"/absolute/store","policy_dir":"/absolute/policy","scope_root":"/absolute/scopes"}]}
```

The file must be a canonical path without links, a regular single-link file
owned by root, of at most 256 KiB, readable by its owner and writable by nobody
else, inside a directory owned by root that only root can write. Every member
is mandatory. The launcher pin must equal the authenticated launcher exactly.
`policy_dir` holds the existing `cg1-matrix.json` under its existing protection
checks. `scope_root` is an existing private directory of the service account;
each session creates and removes one fresh subdirectory in it.

`connection` selects an exact profile in the public `connections.json`, never
its `current` default. The registry must meet the mapping file's protection
rules. `store_base` must be the named agent store returned by the existing
`Connection.Paths` loader: `<root>/connections/<connection_id>/identities/agents/<user_hash>`.
The producer derives that root from the named-store layout, reads only the
public registry, and requires both `Connection.Binding`'s expected Matrix user
and `Connection.Paths`'s store to equal the mapping. It does not read credential
files or use an ambient configuration root. Legacy stores without a public
named connection refuse. This binding is rechecked on every evaluation.

## Behaviour that follows from the design

* A session's checker starts from an empty private scope, so it holds no
  provisioned grant. The grant must be presented inside the signed inner
  request; a request without a presentation refuses as `grant_absent`.
* The origin `event_id` is the content ID of the verified inner request, the
  `grant_id` is the ID of the presented grant that was checked Live, and the
  `tip_hash` is the best block read before and after the grant check. The grant
  backend does not attest the tip it used. If the two reads differ the check
  returns retryable `tip_moved`. Equality leaves the A to B to A residual:
  the backend could check on B between two reads of A, binding A to a verdict
  from B. The bracket is not backend attestation.
* `Validate` freshly rechecks the mapping, connection, retained event, terms,
  signed request, grant and tip, but not the ingest journal or its watermark.
  When the fresh Live Result differs ONLY in `Origin.TipHash`, it returns
  retryable `tip_moved` (`ErrUnavailable`) without a Result; restart at Prepare.
  An unchanged Result validates. Every other Result difference still refuses
  as `changed_since_prepare`, and a changed grant state keeps its typed refusal.
* The retained event is verified again at preparation time. An inner request
  that has expired since it was admitted refuses.
* The origin check records no delivery and does not touch the admission
  journal of the identity.

## Obligations covered by tests

All tests use public fixture keys and no external network. Grant, signature
and tip success/refusal cases use a fake verdict source in `internal/cg1` and a
fake checker in the producer tests. The separate production-composition test
uses the real factory and backend with a loopback-only fake JSON-RPC endpoint;
it reaches the backend's identity read, then returns typed `unavailable` with
no Result because that dependency is unavailable. Altered signed text instead
refuses as `inner_request_invalid` before the backend. No Live production
backend or warm-backend Validate success is claimed.

| Obligation from `docs/source-origin.md` | Test |
| --- | --- |
| Identity, connection, Matrix user, policy and registration only from the protected mapping; a missing mapping or fact refuses | `TestOpenRefusesMissingMapping`, `TestMappingDocumentIsClosed` (`internal/originproducer`) |
| Named public connection binds the expected Matrix user and store before construction and at recheck | `TestOpenBindsConnection`, `TestValidateRechecksConnection` |
| Non-event mailbox entries and content replacement refuse | `TestOpenRefusesNonEventEntry`, `TestRetainedContentReplacement` |
| Real signed event through producer and production checker/backend to the typed dependency refusal | `TestProductionCheckerComposition` |
| Mapping for another launcher UID or generation refuses | `TestOpenRefusesMappingForAnotherLauncher` |
| Mapping file protection (owner, mode, links, directory) | `TestMappingProtection`, `TestNewRequiresProtectedOwner` |
| The producer reads the retained event itself; an absent event refuses | `TestOpenRefusesAbsentRetainedEvent`, `TestPrepareAndValidateLive` |
| An owned checker with its own private scope per session | `TestConcurrentSessionsOwnDistinctCheckers`, `TestOpenOriginCheckerOwnsScope` (`internal/cg1`) |
| Exact signed inner request: author signature, signed text, co-signature, pinned signer | `TestOriginCheckInnerSignatureInvalid` (`internal/cg1`) |
| Inner request addressed to another agent refuses | `TestOriginCheckInnerRequestForAnotherAgent` (`internal/cg1`) |
| Grant states map to typed refusals; only Live yields facts | `TestOriginCheckGrantRefusals` (`internal/cg1`), `TestPrepareRefusalsCarryNoResult` |
| Current tip freshness, read from the node | `TestOriginCheckTipFreshness` (`internal/cg1`) |
| Origin shape; `event_id` is never a Matrix `$` ID | `TestOriginCheckLiveFacts` (`internal/cg1`), `TestPrepareRefusesMalformedFacts` |
| `Validate` freshly rechecks grants and pins (without ingest history) | `TestValidateRefusesChangedGrantState`, `TestOriginCheckLiveFacts` (second check reads the chain again) |
| `Validate` returns only the exact prepared origin; only a tip-only change is retryable | `TestValidateRefusesDifferentOrigin`, `TestValidateTipOnlyChange` |
| Prompt, idempotent `Close`; context cancellation | `TestCloseDuringPrepare`, `TestContextCancellationAndClosedSession`, `TestOriginCheckLifetime` (`internal/cg1`) |
| Cancellation during construction tears down ownership; failed cleanup is typed and scrubbed | `TestOpenCancellationDuringConstruction`, `TestCloseReportsScopeRemovalFailure`, `TestErrorsCarryNoProtectedValue` |
| Protected policy change during a check | `TestOriginCheckPolicyChange` (`internal/cg1`) |
| Pay profile only, validator not weakened | `TestOnlyPayProfileIsImplemented`, `TestPayProfileValidator`, `TestOriginTerms` (`internal/cg1`) |
| No protected value in any error; no log route | `TestErrorsCarryNoProtectedValue`, `TestPackageHasNoLogRoute` |
| Refusing default and one service per process | `TestServiceRefusingDefault`, `TestServiceSingleConstruction` (Linux) |

Gate-removal plants run only under `A2A_ORIGIN_PRODUCER_PLANTS=1` and are not
part of default CI. Run `A2A_ORIGIN_PRODUCER_PLANTS=1 go test ./internal/originproducer -run '^TestOriginProducerPlants$' -count=1 -v`.
Each plant requires an unchanged control before and after, its own diff and an
exit-1 named assertion failure, not a compile error or panic. The signature
acceptance plant removes both envelope verifications and must fail because
facts were produced; the first-gate-only plant separately checks early ordering.

| Plant | Named test that must fail |
| --- | --- |
| Grant check skipped | `TestOriginCheckGrantRefusals/no-grant` |
| `Validate` returns the cached verdict | `TestValidateRefusesChangedGrantState/seal-spent` |
| Mapping lookup falls back to the launcher-supplied principal | `TestOpenRefusesMissingMapping/unmapped-input-principal` |
| Both envelope verifications removed (acceptance) | `TestOriginCheckInnerSignatureInvalid/forged-author-signature` |
| First envelope gate removed (early ordering only) | `TestOriginCheckInnerSignatureInvalid/forged-author-signature` |
| Live consistency weakened | `TestOriginCheckGrantRefusals/retryable-live` |
| Tip-only retry removed | `TestValidateTipOnlyChange` |
| Connection binding removed | `TestOpenBindsConnection/another-account` |
| Production checker construction disconnected | `TestProductionCheckerComposition` |
| Post-construction cancellation ignored | `TestOpenCancellationDuringConstruction` |
| Scope cleanup failure ignored | `TestCloseReportsScopeRemovalFailure` |
| Mailbox entry-kind gate removed | `TestOpenRefusesNonEventEntry` |
| Retained content equality removed | `TestRetainedContentReplacement/before-prepare` |
| Journal or tip residual disclosure removed (document mutation) | `TestQualificationLimits/journal`, `TestQualificationLimits/tip` |
| Shared checker reused | `TestConcurrentSessionsOwnDistinctCheckers` |

## Obligations NOT covered (open)

These are not claimed. Each needs its own qualification before the endpoint
may be enabled.

1. **Real distinct-UID deployment.** No test runs the service, the launcher and
   an agent under three different accounts. The mailbox store requires the
   service account to be able to read the mapped identity's mailbox file under
   that file's existing 0600 check; whether a deployment satisfies this is not
   established.
2. **Protected pins.** The tests create the mapping as the test account and
   inject that account as the trusted owner. Root ownership of the real file,
   the operator-qualified ancestors of the mapping, policy and scope
   directories, and the launcher UID and generation pins of a real host are
   not exercised.
3. **FD theft exclusion.** Nothing here tests that another process cannot
   obtain or reuse the endpoint's descriptors, the mapping descriptor or a
   scope directory.
4. **Production startup.** The construction point is not called by any
   command. Start order, the one-service-per-process rule across a real
   service manager, restart behaviour and removal of scopes left by a crashed
   process are not exercised.
5. **Grant verification against a chain.** Grant states in these tests come
   from a fake verdict source placed behind the existing grant-source seam of
   the Matrix checker. Only the tip facts come from a fake node. The mapping
   from real chain facts (seal spent, landlord changed, expiry) to a verdict is
   the pinned grant backend's own behaviour and is covered only by the existing
   laboratory tests of the Matrix admission path, which need a real regtest
   node and are not part of this unit. **Live through the real backend** and
   **Validate recheck against a warm backend** remain untested compositions by
   name; the loopback production-composition control reaches only a dependency
   refusal, not Live or a provisioned cache.
6. **Trust profile.** Only the pay profile is implemented. The trust contract
   profile and its actions are not decoded or checked here.
7. **Wire-level behaviour with this producer linked.** Response release,
   client replay comparison and the hello with a linked producer are covered by
   upstream fixtures with a stand-in producer only.
8. **Monotonic time floor and ingest history (owner acceptance required).**
   The origin path has no monotonic time floor across checks. It relies on the
   retained event having been admission-gated at ingest under the same policy
   and pins. It does not read prior envelope bytes or the durable delivery
   binding/uniqueness journal and therefore does not repeat those gates.
   The existing `readMatrixJournal` loader requires a `*durable.Store`;
   `durable.Open` opens or creates a writable lock file and takes the writer's
   exclusive lock. There is no read-only constructor, so the origin path does
   not use it and no replacement reader is improvised. The initial policy
   watermark and within-check backward-clock check are not a durable floor.
   Rolling the host clock back into an expired envelope's window on a frozen
   or locally mined chain can make that envelope and tip look fresh again.
   On a continuously advancing chain, future-tip skew bounds that window but
   does not restore the missing floor. Qualification assumes a trustworthy
   non-rollback clock, suitable chain progress/freshness, and admission-gated
   retention; none is established by these unit fixtures. Explicit owner
   acceptance or a separately qualified read-only journal interface is needed.
9. **Backend-attested tip.** The backend does not attest the tip it used.
   A backend-attested tip, rather than bracket inference, remains an open
   obligation; the A to B to A residual is not eliminated in this interface.
