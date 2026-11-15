# Shared distribution preparation (PLAN r3, slices 1 and 2)

The two production implementation slices prepare Linux packages, deterministic
archives, private Darwin input assembly, the signed platform manifest, cask
custody controls and publisher recovery. Integration is **partial**.
There is no combined release workflow, public upload, real release, tag creation,
tap write or installation on a coordinating host in this change.

The existing six-file Darwin publisher refuses with
`combined-release-controller-not-integrated` under the new shared policy,
before native/signing effects. Its native producer and original controls remain.
Do not use that legacy publisher for a combined release. The reserved keyless
identity for Linux checksums and the aggregate is
`.github/workflows/shared-release.yml@refs/tags/vX.Y.Z`; that workflow is
deliberately not supplied until the combined controller is integrated and reviewed.

The proposed combined successor is v0.1.2. The unused ref was checked during
implementation, but that check expires: custody must check it again. `release/VERSION`
now proposes 0.1.2; that source edit creates no tag. Published v0.1.1 and historical v0.1.0 remain immutable.

## Linux preparation

`release/linux.goreleaser.yml` uses OSS GoReleaser v2.20.2, not Pro interfaces,
prebuilt imports or a fork. It builds only `./cmd/a2a`, CGO off, for Linux
amd64/v1 and arm64. It explicitly retains trimpath, buildvcs=false, buildmode=exe,
compiler=gc, pgo=off, internal linking and libgcc=none. There is no stripping,
version injection, Swift/Darwin build, Homebrew generator or publication.

Resolve the pinned module inputs before disabling dependency network access.
Unlike the portable descriptor's managed vendor staging, this path uses
`-mod=readonly`, a read-only resolved module cache, `GOPROXY=off`, `GOSUMDB=off`,
`GOWORK=off`, `GOENV=off` and the pinned local Go 1.25.12 toolchain. The compilation
cache remains writable; it is separate from sealed module inputs. Build tasks
use `-p 1`, tests `-parallel 2`, and GoReleaser `--parallelism 2`.

Each tar.gz contains exactly `a2a`, `LICENSE`, `NOTICE`, `INSTALL.md`. Every file
has root/root ownership (numeric zero), the source commit timestamp, and an
explicit mode (0755 for the CLI, 0644 for documents). Gzip has no wall-clock
timestamp. The verifier checks these properties, including the observed
LICENSE/NOTICE drift class. Hosted CI builds twice after changing all document
filesystem mtimes and requires equality of **both complete archive byte streams**.
It does not claim deterministic SBOM timestamps, keyless signatures or all
package formats across arbitrary environments.

The six Linux primary assets are:

- `a2a_VERSION_linux_amd64.tar.gz`, `a2a_VERSION_linux_arm64.tar.gz`;
- `a2a_VERSION_amd64.deb`, `a2a_VERSION_arm64.deb`;
- `a2a-VERSION-1.x86_64.rpm`, `a2a-VERSION-1.aarch64.rpm`.

Each has a pinned-Syft `.sbom.json` sidecar. The final Linux bundle adds
`linux-release-evidence.json` and `linux-checksums.txt`; production sealing adds
`linux-checksums.txt.sig` and `.pem` (16 members total). The evidence records
source commit/annotated tag, full source archive SHA256, Go version/flags, ELF
architecture, binary/package/SBOM digests and tool pins. buildvcs=false is not
claimed to embed a source revision. The CLI independently compares the supplied
source archive with `git archive --format=tar COMMIT`, current checkout and epoch.

`a2a-distribution linux` verifies static ELF identity and Go build information,
archive metadata/documents, actual deb/rpm architecture/version and one-file
payload equality, and SBOM scanner/subject/module binding. Package inspection
uses Go readers for ar/tar and RPM/gzip/newc, not the builder's artifact metadata.
Maintainer scripts, links, configuration, services and extra payload files are
refused. Installation delivers only `/usr/bin/a2a` and has no startup effects.

RPM installation metadata is authoritative: the single FILEMODES row must be
regular-file 0100755, FILEUSERNAME/FILEGROUPNAME must both be root, and the
filename/directory/index arrays must identify exactly `/usr/bin/a2a`. Missing,
malformed, alternate or disagreeing file tables refuse. The CPIO mode must agree;
neither header nor payload may add setuid, setgid or sticky bits. Deb data.tar
executable and directory modes/ownership are also checked exactly. Hosted tests
regenerate the reviewer's header-only setuid and non-executable plants from each
real RPM, retaining CPIO bytes and recomputing the existing RPM integrity fields.
They exercise public `PrepareLinux` beside valid real-package positives and a
real-deb setuid negative, and require the named refusal with no output bundle.

SBOM coverage is explicit: tar archive SBOMs inventory the CLI's Go modules;
Syft's [deb archive cataloger](https://github.com/anchore/syft/blob/a033ae525f6c7ef937c6f49513e3403f07a1d6c0/syft/pkg/cataloger/debian/parse_deb_archive.go)
and RPM cataloger describe the package identity/version/architecture and subject
digest, rather than recursively cataloging the payload's Go modules. Independently
verified package-to-archive binary equality links those inventories, and signed
evidence must retain the same binary digest for every package of an architecture.
An archive SBOM alone is refused as a package SBOM.

Hosted package checks install/remove amd64 deb/rpm in disposable, offline,
digest-pinned Debian/Fedora containers. They verify payload equality, unchanged
throwaway HOME and `/etc`, and no scripts. A known-bad package/reference pair
must reach the digest gate specifically. Arm64 metadata/payload validation does
**not** qualify native arm64 installation.

## Closed production aggregate

The new production schema is `a2a-release-assets/2`. Q0's
`a2a-release-assets/1` remains qualification-only. Production requires exactly:

- `schema`, `binding` (`tag`, `commit`, `tag_object`), `version`,
  `architectures`, `assets`;
- architectures in the canonical order: `darwin/arm64`, `linux/amd64`,
  `linux/arm64`;
- all six unchanged Darwin members and all sixteen Linux members;
- each asset's exact `name`, fixed-repository/tag download `url` and lowercase
  SHA256. There are no optional production members.

Unknown, differently cased, duplicate or missing keys at every typed level,
unknown/duplicate/missing members, prereleases and association mismatches refuse.
The aggregate excludes itself, its signature/certificate and derived `a2a.rb`.
There is no circular cask/manifest dependency.

Creation verifies both platform checksum signatures and exact checksum subjects,
every member's bytes and evidence source/tag-object agreement. Manifest signing
uses keyless cosign 2.6.1; readback verifies the result before exposing a new
three-file manifest directory by one rename. Failed preparation leaves no output
bundle; an existing caller-owned output is preserved.

The real renderer route requires an independently verified tag/commit/tag-object
binding and the complete `/2` aggregate. It pins the exact certificate identity,
GitHub OIDC issuer, workflow SHA, ref, repository and push event. It authenticates
captured manifest bytes before parsing, binds **every** platform file and both
checksum signatures, projects the three archive rows to the existing renderer,
and writes the cask atomically. Arbitrary identity/issuer flags cannot expand
trust. `-fixture-key` refuses `/2`; qualification trust cannot seal a production
manifest. The pure `/1` renderer, golden and existing Q0 controls remain.

## Review and outstanding integration

The mandatory main-push checks now also include `distribution-controls` and
`linux-production-packages`, bound to `distribution-controls.yml`. Retained
mandatory checks are bound to their own reviewed workflow paths. Existing exact
job/run/check/repository/current-main, signature, history, protection/rules and
fail-closed API gates still apply. An accepted review must carry
`Release-Scope: a2a-shared-distribution-r3`; a COMMENTED transport also retains
`Release-Review: ACCEPT FULL_COMMIT_SHA`. The producer must not emit an acceptance
marker as a self-review.

These preparation controls do not complete whole-release acceptance. Remaining
work is:

1. Split Darwin preparation from publication, preserving admission, five-field
   refusal, one-call scoped search-list mutation/restoration, native full
   requirements, notary tickets, exact private membership and cleanup.
2. Bind both private bundles by immutable artifact ID/digest, commit and
   annotated tag object; independently cross-build both Linux architectures on
   the approved macOS assemble runner and require byte equality.
3. Integrate the existing publisher/client: re-admission before upload and
   public transition, exact uploaded membership/digest readback and read-only
   reconciliation of ambiguous outcomes, under the explicit main lease.
4. Verify actual public Linux downloads and the signed aggregate; derive the
   cask, record manifest SHA256, renderer tag/source and cask SHA256, and require
   tap-review re-render equality. Only the a2a cask paths may change. Stable
   channel only; no Curator cask or tap-wide policy change.
5. Review the VERSION successor and the **whole** combined release, qualify
   remaining native/install gates, then obtain the separate release/custody window.

The existing-bot manual tap route needs no `TAP_GITHUB_TOKEN`, additional Apple
fields, exported machine signing key or owner provisioning. No owner decision
is requested by this slice.

## Tools and reproducible entry points

Run build/test commands only on an authorized isolated runner. All caches,
outputs, homes and logs in the hosted workflow are under `RUNNER_TEMP`;
GoReleaser's ignored `dist/` is staging only. No installed alias is involved.

| Tool | Exact entry point | Output |
| --- | --- | --- |
| Go 1.25.12 | `go test -p 1 -parallel 2 -race -count=1 ./internal/sharedrelease ./internal/cask ./cmd/a2a-cask ./cmd/a2a-distribution` | Hosted control log |
| Go build/vet | `go build -p 1 ./cmd/a2a-cask ./cmd/a2a-distribution`; `go vet -p 1 ./internal/sharedrelease ./internal/cask ./cmd/a2a-cask ./cmd/a2a-distribution` | Hosted build/validation |
| GoReleaser OSS 2.20.2 | `RELEASE_VERSION=0.1.2 goreleaser release --config release/linux.goreleaser.yml --snapshot --clean --parallelism 2 --skip=publish,announce,sign` | Private qualification `dist/` |
| Syft 1.38.0 | GoReleaser's `syft scan file:ARTIFACT --output syft-json=DOCUMENT` | Six SBOM sidecars |
| Distribution tool | `a2a-distribution tools` | Toolchain/executable-pin refusal or success |
| Linux qualification | `a2a-distribution linux -qualification -tag v0.1.2 -commit COMMIT -tag-object COMMIT -epoch EPOCH -source-archive SOURCE.tar -out NEW_DIR` | Atomic private bundle, explicit qualification trust; COMMIT in tag-object is a placeholder, never real tag authority |
| Real-package regression tests | `A2A_PACKAGE_CONTROL_BUNDLE=BUNDLE A2A_PACKAGE_CONTROL_SOURCE=SOURCE.tar go test -p 1 -parallel 2 -v -count=1 -run 'TestReviewer|TestRPMHeaderOnly|TestDebSetuidTarMode' ./internal/sharedrelease` | Hosted positive/negative parser controls; plants are never installed or executed |
| Production preparation | Same `linux` command without `-qualification`, with the real admitted annotated tag object | Admitted private Linux bundle plus keyless checksum signature/certificate |
| Aggregate sealing | `a2a-distribution manifest -tag TAG -commit COMMIT -tag-object OBJECT -dist PLATFORM_DIR -out NEW_DIR` | Admitted, signed, verified platform-only aggregate; no publish |
| Production renderer | `a2a-cask -manifest release-assets.json -signature release-assets.json.sig -certificate release-assets.json.pem -certificate-identity EXPECTED -certificate-oidc-issuer https://token.actions.githubusercontent.com -tag TAG -commit COMMIT -tag-object OBJECT -checksums checksums.txt -checksums linux-checksums.txt -assets-dir PLATFORM_DIR -out a2a.rb` | Atomic derived cask |
| cosign 2.6.1 | `sign-blob` / `verify-blob` inside the production tools, with fixed identity/source claims | Signature/certificate and verification verdict |
| Docker | Digest-pinned `docker run --rm --network none ... sh /check.sh deb\|rpm\|rpm-meta ...` in the workflow | Disposable install checks; no coordinating-host install |

`release/linux-tools.json` pins immutable release/source objects, download and
executable SHA256s, and the upstream checksum-list SHA256. Executable digests were
computed from archives matching the immutable upstream release digests and
checksum lists. Sources: [GoReleaser v2.20.2](https://github.com/goreleaser/goreleaser/releases/tag/v2.20.2),
[Syft v1.38.0](https://github.com/anchore/syft/releases/tag/v1.38.0).
The workflow reuses already pinned checkout/setup-go/cosign/artifact actions.
It has read-only contents access and no OIDC permission; its artifacts are
explicitly qualification inputs, never production signatures or publication.


## Slice 2 private boundaries (publication still held)

`a2a-release prepare TAG` uses the original native producer and returns its
private six-file bundle after keyless checksum signing, repeated admission and
signature readback. It does not call the publisher. The real `release` command
continues refusing with `combined-release-controller-not-integrated`.

`a2a-distribution collect` requires the independently admitted tag/source/object,
immutable artifact ID, run ID, ZIP SHA256 and platform. It checks API repository,
source, tag, workflow, successful producer job and expiry associations, the
upload digest and closed flat ZIP members, then the payload tag-object binding.
The output is atomic and private. The expected producer names are
`darwin-producer / prepare` and `linux-producer`; artifact names are
`a2a-PLATFORM-TAG_OBJECT` in the reserved shared release workflow. Collection
alone is not signature authentication; aggregate creation verifies both platform
checksum signatures and production evidence again.

`a2a-distribution crosscheck -root SOURCE -dist LINUX_BUNDLE -binary CROSS_BINARY
-arch ARCH -tag TAG -commit COMMIT -tag-object OBJECT -epoch EPOCH
-source-archive SOURCE.tar` checks the clean checkout/archive/epoch, complete
archive metadata and documentation, ELF architecture, producer evidence digest,
and exact independent executable bytes. Hosted macOS independently builds both
Linux architectures using Go 1.25.12, the approved flags and offline modules.
Its fixture comparison cannot promote qualification evidence to production.

The cask guard checks canonical renderer bytes and Homebrew 7.0.13's public
`info --cask --json=v2 --variations` output. URL, SHA256, version, source binary
and resolved target must agree for every supported projection. Unknown fields,
artifacts and variation fields refuse; macOS Intel is excluded. Actual brew
plants change URL, checksum, version, binary source/target and an extra artifact,
with a valid nearby cask. No Ruby is evaluated by the Go guard.

Remaining production integration: the shared tag workflow, Linux producer
consumption/order, the whole assembly-to-publisher controller and explicit main
lease through final publication readback. Native re-verification, mandatory
independent compiler checks, the closed publisher and read-only recovery now
exist as preparation boundaries, but are not one activated production route.
The hold stays until these form one reviewed route. No tag, release or tap
publication is enabled by these preparation commands.

## Prepared manual tap custody (no tap write)

After a future admitted public release, custody downloads the signed aggregate
and all platform assets, verifies their keyless workflow/source/ref identity and
actual bytes, and rebuilds the renderer from that exact clean release revision.
Render with the normal production `a2a-cask` entry point. Before evaluating Ruby,
require byte equality with that canonical output. Evaluate using the pinned
Homebrew source commit `bc63375ac3a4d6debb1ceb441ae6e22854f0909a` (7.0.13) in an
isolated prefix, then capture public `brew info` JSON. Never evaluate an untrusted
proposal before the canonical byte comparison.

Run the same production flags plus `-proposed a2a.rb -brew-info INFO.json
-brew-prefix PREFIX -brew-platform darwin/arm64 -tap-dir TAP_CHECKOUT
-tap-base TAP_MAIN_COMMIT -renderer-revision COMMIT`, without `-out`. The tap checkout is an existing signed feature branch, with fresh independently
fetched `origin/main` at `TAP_MAIN_COMMIT`. The verifier repeats
manifest authenticity, all asset bindings, canonical cask derivation, effective
installer fields and the complete committed tap diff against that base. It
requires a clean tap feature checkout, verified bot signatures for every
introduced commit and exactly `Casks/a2a.rb` equal to the canonical cask; it requires a
clean renderer checkout at the recorded release revision. It emits a receipt
with manifest SHA256, renderer revision, cask SHA256 and tag object. It writes no
cask or tap file. This is a prepared verification step, not public-download
reconciliation or delivery evidence.

Custody uses the existing configured bot key for the feature commits, then
independent tap PR review/checks, nonforced FF and readback. Independent review
repeats authenticated download and renderer equality. No TAP_GITHUB_TOKEN,
exported signing key, new secret or owner provisioning is required. Tap delivery
and native installation/adoption remain separate outcomes.


## Private assembly, publisher reuse and recovery

The Darwin workflow is now reusable private preparation only, with no tag
trigger or contents-write permission. The future shared controller calls it as
`darwin-producer`; its native job is `prepare`. Only the five existing Apple
fields enter its native step. The original native implementation, preflight,
cleanup, full requirements and tickets remain the producer. Its reusable-workflow
certificate identity stays the legacy Darwin identity. The future shared parent
has one tag concurrency group with `cancel-in-progress: false`; it is not supplied
by this partial slice, and no production trigger replaces the hold yet.

`a2a-distribution assemble -inputs INPUTS.json -root SOURCE -out NEW_PLATFORM_DIR
-tag TAG -commit COMMIT -tag-object OBJECT -epoch EPOCH -source-archive SOURCE.tar`
requires two closed `BundleInput` objects (`darwin`, `linux`), each containing
`zip` and `artifact` (`id`, `run_id`, `sha256`, `platform`). The producer run IDs
must match. It captures both bundles, independently verifies original Darwin
signatures and full compiled requirements/ticket CDHashes without signing fields,
validates Linux evidence, builds both Linux targets offline on macOS and compares
exact bytes. Only after both checksum signatures authenticate does it atomically
return the exact 22 platform files. It emits private association and binary-digest
evidence separately on stdout. It neither repacks Darwin nor signs an aggregate
or publishes. Resolve modules before entering this offline boundary.

`a2a-distribution crossbuild` is the same independently compiled macOS path used
by the hosted control, with the `crosscheck` binding flags and `-out NEW_BINARY`.
Source archive digest, clean source revision, epoch and portable build settings
are all bound. Qualification evidence can be compared but cannot authorize an
aggregate or production assembly.

The original publisher delegates to a shared captured-candidate boundary. A
future combined caller supplies the exact 26 members (22 platform, aggregate
triple, derived cask) and the trusted production gate. Re-admission precedes the
first draft mutation and the public transition. Complete server-side membership
and each uploaded digest/size/state are read back before publication. There is
one PATCH only. An ambiguous result triggers read-only observation and returns
an explicit unknown-outcome error with observed draft/public state; it never
retries, deletes, overwrites or retags. Actual API mutation tests run against an
isolated HTTP fixture, not a real release.

`a2a-distribution reconcile -release-id ID -dist FINAL_26_FILES -tag TAG
-commit COMMIT -tag-object OBJECT` authenticates the original candidate and
observes the recorded release ID read-only. A private draft is reported as such.
For a public release it downloads every exact public member, compares actual
bytes with the authenticated candidate, re-authenticates, and repeats release
metadata readback. Redirects are restricted to HTTPS GitHub release hosts and no
credential is sent. Missing or changed bytes refuse. This command never resumes
publication. Custody runs it before preparing the tap PR.

## Slice 2 evidence limits and acceptance map

The brief has no formal attack-surface table. This map follows its acceptance
bullets; none is silently treated as out of contract.

| Contract | Named controls | Limit |
| --- | --- | --- |
| Artifact identity, run/job/source/tag object and closed ZIP | `TestArtifactAPIAssociation`, `TestPrivateArtifactCaptureBindings`, `TestArtifactZIPClosedEntries` | API fixture association controls; no production artifact is minted here |
| Original native Darwin bytes, installer modes and complete requirements/tickets | `TestPreparedDarwinBundleNative`, `TestDarwinInputTarEntries`, retained native requirement/ticket tests | Immutable public v0.1.1 fixture; no new Apple signing or Keychain execution |
| Independent Linux build and full source/archive binding | hosted macOS `crossbuild`, `TestIndependentLinuxByteControl`, `TestCrossBuildSourceBinding` | Both targets compared; no native arm64 Linux installation claim |
| Premature publication, changed digest/membership, changed admission and unknown outcome | `TestPublisherClosedTransition`, `TestReadOnlyReconciliation`, `TestFinalCandidateDerivation` | Isolated HTTP fixture; combined production caller remains held |
| Effective brew URL/hash/version/source/resolved target and closed stanzas | `TestBrewInstallerFields`, `TestBrewLinuxEvaluatedProjection`, real `TestRealBrewEvaluation` on Linux/macOS | Exact pinned Homebrew; evaluation does not install |
| Manifest/renderer/cask/tap mismatch | retained production cask authenticity tests, `TestFinalCandidateDerivation`, `TestCustodyTapDiff`, `TestCustodyRepositoryReadGate` | Manual custody command is prepared, no tap mutation |
| Public download integrity | `TestPublicAssetDownloadBinding`, `TestRealPublicDownloadDigest` | Real immutable Darwin download; a real published Linux download cannot run before the first separately authorized combined release |

The cask resolved-target narrowing mutant removes only target equality. The
named `TestBrewInstallerFields/binary-target` must fail for the intended reason;
an unrelated error does not count. The valid original, field plants and complete
Go build/vet controls remain required. Existing real RPM/deb reviewer plants and
the FILEMODES narrowing mutant remain unchanged.

Hosted pins: Go 1.25.12, cosign 2.6.1 and the existing packaging/SBOM digest lock;
Homebrew 7.0.13 at `bc63375ac3a4d6debb1ceb441ae6e22854f0909a`. That source locks
portable Ruby 4.0.9: ARM64 Darwin archive SHA256
`43ff285a82f48c84a06d0676a3800815a19d290d32e44182ddd7a6e95478e18e`,
x86_64 Linux archive SHA256
`20d7b22eba004e0518932ce7f8a271c16b1a9da91b81f696c735d14d817a2c07`.
New workflows reuse the existing full-commit action pins. Fixture asset digests
are recorded in `release/darwin-fixture.json`. Native Xcode 16.4/Swift 6.1.2
pins and their qualified path remain unchanged.
