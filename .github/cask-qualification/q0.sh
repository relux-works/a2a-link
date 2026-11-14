#!/usr/bin/env bash
# Assertion recorder for the cask qualification. Each assertion writes exactly one result JSON under
# $Q0_RESULTS, so a refusal, a skip and a pass are all kept as evidence.
# `check` and `refuse` are for independent, safe assertions: a failure is
# recorded and collection continues, and `verdict` fails the job at the end.
# `gate` is for admission checks (a tool checksum, a pinned commit, a fixture
# digest): a failure is recorded and the step STOPS, before the gated input is
# extracted, executed or used.
#
#   q0.sh check NAME -- COMMAND [ARG...]   run COMMAND, record pass or fail, continue
#   q0.sh gate NAME -- COMMAND [ARG...]    an admission check: record it, and on
#                                          failure EXIT 1, so nothing after it runs
#   q0.sh refuse NAME -- COMMAND [ARG...]  pass only if COMMAND fails (a negative)
#   q0.sh skip NAME REASON                 record an explicit skip
#   q0.sh verdict                          print the summary, exit 1 on any fail
set -uo pipefail

: "${Q0_RESULTS:?Q0_RESULTS must be set}"
: "${Q0_JOB:?Q0_JOB must be set}"
mkdir -p "$Q0_RESULTS"

record() { # name status exit detail-file
	python3 -I - "$Q0_RESULTS" "$Q0_JOB" "$1" "$2" "$3" "$4" <<'PY'
import json, os, platform, sys
results, job, name, status, code, detail = sys.argv[1:7]
text = ""
if detail and os.path.exists(detail):
    with open(detail, "rb") as f:
        text = f.read()[-4000:].decode("utf-8", "replace")
out = {
    "job": job,
    "assertion": name,
    "status": status,
    "exit": int(code),
    "detail_tail": text,
    "runner": {"os": platform.system(), "machine": platform.machine(), "release": platform.release()},
}
with open(os.path.join(results, f"{job}--{name}.json"), "w") as f:
    json.dump(out, f, indent=1, sort_keys=True)
print(f"Q0 {status.upper():5} {job}/{name} (exit {code})")
PY
}

run_cmd() { # mode name -- cmd...
	local mode=$1 name=$2
	shift 2
	[ "${1:-}" = "--" ] || { echo "q0.sh: missing --" >&2; exit 2; }
	shift
	local log
	log=$(mktemp)
	"$@" >"$log" 2>&1
	local code=$?
	cat "$log"
	local status
	if [ "$mode" = check ] || [ "$mode" = gate ]; then
		[ $code -eq 0 ] && status=pass || status=fail
	else
		[ $code -ne 0 ] && status=pass || status=fail
	fi
	record "$name" "$status" "$code" "$log"
	rm -f "$log"
	if [ "$mode" = gate ] && [ "$status" != pass ]; then
		echo "Q0 GATE CLOSED: $Q0_JOB/$name; nothing after it runs" >&2
		exit 1
	fi
}

case "${1:-}" in
check | gate | refuse) run_cmd "$@" ;;
skip)
	log=$(mktemp)
	printf '%s\n' "${3:?skip needs a reason}" >"$log"
	record "${2:?skip needs a name}" skip 0 "$log"
	rm -f "$log"
	;;
verdict)
	python3 -I - "$Q0_RESULTS" "$Q0_JOB" <<'PY'
import glob, json, os, sys
results, job = sys.argv[1:3]
rows = [json.load(open(p)) for p in sorted(glob.glob(os.path.join(results, f"{job}--*.json")))]
counts = {}
for r in rows:
    counts[r["status"]] = counts.get(r["status"], 0) + 1
    print(f'{r["status"]:5} {r["assertion"]}')
print(f"Q0 {job}: {counts}")
sys.exit(1 if counts.get("fail") or not rows else 0)
PY
	;;
*)
	echo "usage: q0.sh check|gate|refuse|skip|verdict ..." >&2
	exit 2
	;;
esac
