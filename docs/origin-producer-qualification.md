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

## Behaviour that follows from the design

* A session's checker starts from an empty private scope, so it holds no
  provisioned grant. The grant must be presented inside the signed inner
  request; a request without a presentation refuses as `grant_absent`.
* The origin `event_id` is the content ID of the verified inner request, the
  `grant_id` is the ID of the presented grant that was checked Live, and the
  `tip_hash` is the best block the checker read itself before and after the
  grant check. If the two reads differ the check refuses as `tip_moved`.
* `Validate` repeats the whole admission. A new block between `Prepare` and
  `Validate` changes the tip and therefore refuses; the launcher starts again.
* The retained event is verified again at preparation time. An inner request
  that has expired since it was admitted refuses.
* The origin check records no delivery and does not touch the admission
  journal of the identity.

## Obligations covered by tests

All tests use public fixture keys, a fake tip node and no network.

| Obligation from `docs/source-origin.md` | Test |
| --- | --- |
| Identity, connection, Matrix user, policy and registration only from the protected mapping; a missing mapping or fact refuses | `TestOpenRefusesMissingMapping`, `TestMappingDocumentIsClosed` (`internal/originproducer`) |
| Mapping for another launcher UID or generation refuses | `TestOpenRefusesMappingForAnotherLauncher` |
| Mapping file protection (owner, mode, links, directory) | `TestMappingProtection`, `TestNewRequiresProtectedOwner` |
| The producer reads the retained event itself; an absent event refuses | `TestOpenRefusesAbsentRetainedEvent`, `TestPrepareAndValidateLive` |
| An owned checker with its own private scope per session | `TestConcurrentSessionsOwnDistinctCheckers`, `TestOpenOriginCheckerOwnsScope` (`internal/cg1`) |
| Exact signed inner request: author signature, signed text, co-signature, pinned signer | `TestOriginCheckInnerSignatureInvalid` (`internal/cg1`) |
| Inner request addressed to another agent refuses | `TestOriginCheckInnerRequestForAnotherAgent` (`internal/cg1`) |
| Grant states map to typed refusals; only Live yields facts | `TestOriginCheckGrantRefusals` (`internal/cg1`), `TestPrepareRefusalsCarryNoResult` |
| Current tip freshness, read from the node | `TestOriginCheckTipFreshness` (`internal/cg1`) |
| Origin shape; `event_id` is never a Matrix `$` ID | `TestOriginCheckLiveFacts` (`internal/cg1`), `TestPrepareRefusesMalformedFacts` |
| `Validate` is a fresh admission and pin check | `TestValidateRefusesChangedGrantState`, `TestOriginCheckLiveFacts` (second check reads the chain again) |
| `Validate` returns only the exact prepared origin | `TestValidateRefusesDifferentOrigin` |
| Prompt, idempotent `Close`; context cancellation | `TestCloseDuringPrepare`, `TestContextCancellationAndClosedSession`, `TestOriginCheckLifetime` (`internal/cg1`) |
| Protected policy change during a check | `TestOriginCheckPolicyChange` (`internal/cg1`) |
| Pay profile only, validator not weakened | `TestOnlyPayProfileIsImplemented`, `TestPayProfileValidator`, `TestOriginTerms` (`internal/cg1`) |
| No protected value in any error; no log route | `TestErrorsCarryNoProtectedValue`, `TestPackageHasNoLogRoute` |
| Refusing default and one service per process | `TestServiceRefusingDefault`, `TestServiceSingleConstruction` (Linux) |

Gate-removal plants: `A2A_ORIGIN_PRODUCER_PLANTS=1 go test ./internal/originproducer -run '^TestOriginProducerPlants$' -count=1 -v`.

| Plant | Named test that must fail |
| --- | --- |
| Grant check skipped | `TestOriginCheckGrantRefusals/no-grant` |
| `Validate` returns the cached verdict | `TestValidateRefusesChangedGrantState/seal-spent` |
| Mapping lookup falls back to the launcher-supplied principal | `TestOpenRefusesMissingMapping/unmapped-input-principal` |
| Inner-signature check removed | `TestOriginCheckInnerSignatureInvalid/forged-author-signature` |
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
   node and are not part of this unit.
6. **Trust profile.** Only the pay profile is implemented. The trust contract
   profile and its actions are not decoded or checked here.
7. **Wire-level behaviour with this producer linked.** Response release,
   client replay comparison and the hello with a linked producer are covered by
   upstream fixtures with a stand-in producer only.
