"""Write a QUALIFICATION FIXTURE release-assets.json.

v0.1.1 has no combined platform manifest and no Linux release assets, so the
qualification assembles one with the real archive digests and the real source
binding (tag and commit). It is signed in the job with an ephemeral fixture key.
That is fixture trust only: never production authority, and never presented as
a cosign keyless signature by the release workflow.

  fixture_manifest.py OUT --tag v0.1.1 --commit SHA --checksums FILE... \
      [--drop NAME] [--set-digest NAME=HEX] [--add NAME=HEX] [--version V]

Mutations exist only to build the negative controls; each one is named in the
assertion that uses it.
"""
import argparse
import json

BASE = "https://github.com/relux-works/a2a-swarm/releases/download/"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("out")
    p.add_argument("--tag", required=True)
    p.add_argument("--commit", required=True)
    p.add_argument("--checksums", nargs="+", required=True)
    p.add_argument("--only", nargs="+", required=True, help="asset names to include")
    p.add_argument("--drop", action="append", default=[])
    p.add_argument("--set-digest", action="append", default=[])
    p.add_argument("--add", action="append", default=[])
    p.add_argument("--version")
    a = p.parse_args()
    sums = {}
    for path in a.checksums:
        for line in open(path):
            if line.strip():
                digest, name = line.split()
                sums[name.lstrip("*")] = digest
    version = a.version or a.tag[1:]
    tag = "v" + version
    assets = []
    for name in a.only:
        if name in a.drop:
            continue
        assets.append({"name": name, "url": BASE + tag + "/" + name, "sha256": sums[name]})
    for kv in a.set_digest:
        name, digest = kv.split("=", 1)
        for x in assets:
            if x["name"] == name:
                x["sha256"] = digest
    for kv in a.add:
        name, digest = kv.split("=", 1)
        assets.append({"name": name, "url": BASE + tag + "/" + name, "sha256": digest})
    manifest = {"schema": "a2a-release-assets/1", "tag": tag, "commit": a.commit, "version": version, "assets": assets}
    with open(a.out, "w") as f:
        json.dump(manifest, f, indent=1, sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    main()
