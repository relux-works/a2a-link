# Linux installation

The archive contains the static `a2a` CLI, LICENSE, NOTICE and this file.
There is no Darwin Keychain companion on Linux. Extract into a directory you
own, verify the signed release manifest and platform checksums first, and run
`./a2a help`. Copy the executable to your chosen user-managed binary directory
only during an authorized installation window.

The deb/rpm packages place only `/usr/bin/a2a`. They contain no maintainer
scripts, services, identity registration, hooks, trust changes or daemon
startup. Package installation and removal require your package manager's normal
authority. Configuration and credentials are separate from the package.

`linux-checksums.txt` covers Linux archives, packages, their SBOMs and Linux
evidence. `checksums.txt` covers the unchanged Darwin bundle. The signed
`release-assets.json` binds both sets to one source commit and annotated tag.
Verify its expected workflow identity and issuer, not just a digest's format.
