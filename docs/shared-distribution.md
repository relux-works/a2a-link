# Shared distribution preparation (PLAN r3, first slice)

This is the first production implementation slice: Linux preparation, explicit
archive metadata, and a closed production platform manifest. It is **partial**.
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
implementation, but that check expires: custody must check it again. `VERSION`
stays at 0.1.1 in this partial slice. Its reviewed successor update belongs with
the combined controller. Published v0.1.1 and historical v0.1.0 remain immutable.

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
