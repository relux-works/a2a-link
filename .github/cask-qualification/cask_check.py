"""Structural checks on the generated cask and Homebrew's view of it.

  cask_check.py companion CASK             the companion is only in the macOS block
  cask_check.py linux CASK CHECKSUMS       Linux urls and digests match linux-checksums.txt
  cask_check.py intel INFO_JSON            Intel macOS is refused (depends_on arch arm64)

Each mode prints what it found and exits non-zero on a violation.
"""
import json
import re
import sys


def block(text, opener):
    """The body of the first `opener do ... end` block, matched by indentation."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.strip() == opener + " do":
            indent = len(line) - len(line.lstrip())
            body = []
            for inner in lines[i + 1:]:
                if inner.strip() == "end" and len(inner) - len(inner.lstrip()) == indent:
                    return "\n".join(body)
                body.append(inner)
    return None


def companion(path):
    text = open(path).read()
    mac = block(text, "on_macos")
    if mac is None:
        sys.exit("no on_macos block")
    print(mac)
    if 'binary "a2a-keychain-status"' not in mac:
        sys.exit("companion missing from the macOS block")
    if text.count('binary "a2a-keychain-status"') != 1:
        sys.exit("companion declared outside the macOS block")
    if "depends_on arch: :arm64" not in mac:
        sys.exit("macOS block does not require arm64")


def linux(path, checksums):
    text = open(path).read()
    lin = block(text, "on_linux")
    if lin is None:
        sys.exit("no on_linux block")
    print(lin)
    want = {}
    for line in open(checksums):
        digest, name = line.split()
        want[name] = digest
    found = {}
    for arch in ("on_intel", "on_arm"):
        body = block(lin, arch)
        if body is None:
            sys.exit(f"no {arch} block in on_linux")
        sha = re.search(r'sha256 "([0-9a-f]{64})"', body)
        url = re.search(r'url "([^"]+)"', body)
        if not sha or not url:
            sys.exit(f"{arch}: missing sha256 or url")
        name = url.group(1).rsplit("/", 1)[-1].replace("#{version}", "0.1.1")
        found[name] = sha.group(1)
    expected = {"a2a_0.1.1_linux_amd64.tar.gz", "a2a_0.1.1_linux_arm64.tar.gz"}
    if set(found) != expected:
        sys.exit(f"linux archives in cask {sorted(found)}, want {sorted(expected)}")
    for name, digest in found.items():
        if want.get(name) != digest:
            sys.exit(f"{name}: cask {digest} != linux-checksums {want.get(name)}")
    print("linux digests match:", found)


def intel(path):
    info = json.load(open(path))
    cask = info["casks"][0]
    base = cask.get("depends_on") or {}
    variations = cask.get("variations") or {}
    print("base depends_on:", base)
    print("variation keys:", sorted(variations))
    intel_mac = [k for k in variations if not k.startswith("arm64_") and not k.endswith("_linux")]

    def arm_only(dep):
        arch = (dep or {}).get("arch") or []
        return bool(arch) and all(a.get("type") == "arm" for a in arch)

    if not arm_only(base):
        sys.exit("macOS base does not depend on arch arm64")
    for key in intel_mac:
        dep = variations[key].get("depends_on", base)
        if not arm_only(dep):
            sys.exit(f"{key}: not refused, depends_on {dep}")
    print("Intel macOS refused; intel variations checked:", intel_mac or "none listed, base applies")


if __name__ == "__main__":
    mode, args = sys.argv[1], sys.argv[2:]
    {"companion": companion, "linux": linux, "intel": intel}[mode](*args)
