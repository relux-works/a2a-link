#!/bin/sh
# Runs inside a disposable container with no network. Installs one package,
# proves it delivers exactly the reference binary, adds no maintainer scripts,
# service or /etc change, runs `a2a help` under a throwaway HOME, removes it.
#
#   pkg_check.sh deb PACKAGE REFERENCE
#   pkg_check.sh rpm PACKAGE REFERENCE
#   pkg_check.sh rpm-meta PACKAGE REFERENCE ARCH   (no install: foreign architecture)
set -eu
mode=$1 pkg=$2 ref=$3

allowed_files() { # stdin: the package file list; fail on anything but the binary path
	grep -vxE '/\.|/usr|/usr/bin|/usr/bin/a2a' | grep -v '^$' && { echo "unexpected packaged paths above" >&2; exit 1; } || true
}

run_help() {
	mkdir -p /tmp/h
	before=$(find /tmp/h | sort)
	HOME=/tmp/h /usr/bin/a2a help >/dev/null
	after=$(find /tmp/h | sort)
	[ "$before" = "$after" ] || { echo "a2a help wrote under HOME" >&2; exit 1; }
}

etc_before=$(find /etc -xdev 2>/dev/null | sort)
case "$mode" in
deb)
	dpkg -i "$pkg"
	dpkg -L a2a | allowed_files
	scripts=$(ls /var/lib/dpkg/info/a2a.* | grep -vE '\.(list|md5sums)$' || true)
	[ -z "$scripts" ] || { echo "maintainer scripts: $scripts" >&2; exit 1; }
	cmp /usr/bin/a2a "$ref"
	run_help
	dpkg -r a2a
	;;
rpm)
	rpm -i "$pkg"
	rpm -ql a2a | allowed_files
	scripts=$(rpm -q --scripts a2a)
	[ -z "$scripts" ] || { echo "rpm scriptlets: $scripts" >&2; exit 1; }
	cmp /usr/bin/a2a "$ref"
	run_help
	rpm -e a2a
	;;
rpm-meta)
	arch=$(rpm -qp --qf '%{ARCH}' "$pkg")
	[ "$arch" = "$4" ] || { echo "rpm arch $arch, want $4" >&2; exit 1; }
	digest=$(rpm -qp --qf '[%{FILENAMES} %{FILEDIGESTS}\n]' "$pkg" | awk '$1=="/usr/bin/a2a"{print $2}')
	want=$(sha256sum "$ref" | cut -d' ' -f1)
	[ "$digest" = "$want" ] || { echo "packaged a2a digest $digest, reference $want" >&2; exit 1; }
	exit 0
	;;
*)
	echo "usage: pkg_check.sh deb|rpm|rpm-meta PACKAGE REFERENCE [ARCH]" >&2
	exit 2
	;;
esac
[ ! -e /usr/bin/a2a ] || { echo "binary left after removal" >&2; exit 1; }
etc_after=$(find /etc -xdev 2>/dev/null | sort)
[ "$etc_before" = "$etc_after" ] || { echo "/etc changed across install and removal" >&2; exit 1; }
echo "OK $mode $pkg"
