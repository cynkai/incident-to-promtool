#!/usr/bin/env bash
set -euo pipefail

usage() {
    printf 'Usage: bash scripts/demo.sh [--timing]\n'
    printf 'Use --timing to compare two versions of the payment alert against a firing deadline.\n'
}

timing=0
if [[ $# -eq 1 && $1 == --timing ]]; then
    timing=1
elif [[ $# -eq 1 && ( $1 == -h || $1 == --help ) ]]; then
    usage
    exit 0
elif [[ $# -ne 0 ]]; then
    usage >&2
    exit 2
fi

repo=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
if ! python=$(type -P python3); then
    printf 'Python 3.10 or later is required to run the demo.\n' >&2
    exit 2
fi
if [[ $python != /* ]]; then
    python="$PWD/$python"
fi

temporary=$(mktemp -d "${TMPDIR:-/tmp}/incident-to-promtool-demo.XXXXXXXX")
trap 'rm -rf -- "$temporary"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ -n ${PROMTOOL:-} ]]; then
    promtool=$PROMTOOL
    if [[ $promtool != */* ]] && ! promtool=$(type -P -- "$PROMTOOL"); then
        printf 'promtool executable not found: %s\n' "$PROMTOOL" >&2
        exit 2
    fi
elif ! promtool=$(type -P promtool); then
    printf 'Installing verified promtool 3.11.0 for the demo.\n' >&2
    bash "$repo/scripts/install-promtool.sh" 3.11.0 "$temporary" >&2
    promtool="$temporary/promtool"
fi
if [[ $promtool != /* ]]; then
    promtool="$PWD/$promtool"
fi

(
    CDPATH= cd -- "$temporary"
    # Keep subprocess scratch paths valid after leaving the caller's directory.
    export TMPDIR="$PWD"
    incident="$repo/demo/demo.json"
    if [[ "$timing" -eq 1 ]]; then
        incident="$repo/demo/timing.incident.json"
    fi
    "$python" "$repo/incident_to_promtool.py" "$incident" \
        --matrix "$repo/demo/incident.matrix.json" --output payment.test.yml >&2

    compare=("$python" "$repo/incident_to_promtool.py" compare payment.test.yml
        --before "$repo/demo/before.rules.yml" --promtool "$promtool")
    if [[ "$timing" -eq 0 ]]; then
        "${compare[@]}" --after "$repo/demo/after.rules.yml"
        exit
    fi

    compare+=(--timeline-policy "$repo/demo/timing.policy.json")
    status=0
    "${compare[@]}" --after "$repo/demo/before.rules.yml" --json-report original.json >/dev/null || status=$?
    if [[ "$status" -gt 1 ]]; then
        exit "$status"
    fi
    if [[ "$status" -eq 0 ]]; then
        printf 'The original rule unexpectedly passed the timing demo.\n' >&2
        exit 1
    fi
    "${compare[@]}" --after "$repo/demo/after.rules.yml" --json-report revised.json >/dev/null

    "$python" -B - "$repo" <<'PY'
import json
from pathlib import Path
import sys

sys.path.insert(0, sys.argv[1])
from incident_to_promtool import as_duration, format_timeline_shift


def read_candidate(path, deadline_status):
    report = json.loads(Path(path).read_text(encoding="utf-8"))
    policy = report["timeline_policy"]
    timeline, = policy["checks"]
    delay = timeline["gate"]
    deadline = timeline["deadline_gate"]
    result, = deadline["groups"]
    shift, = delay["groups"]
    expected_pass = deadline_status == "passed"
    if (not report["gate"]["passed"] or not delay["passed"] or result["status"] != deadline_status
            or policy["passed"] != expected_pass):
        sys.exit(f"Unexpected checkpoint or timing outcome in {path}.")

    checkpoints = report["summary"]["after"]
    return deadline["fire_by_ms"], (
        f"{checkpoints['matched']}/{checkpoints['total']}",
        as_duration(result["after_first_firing_offset_ms"]),
        f"{format_timeline_shift(shift['first_firing_delta_ms'])} (pass)",
        "Passed" if deadline["passed"] else "Failed",
        "Passed" if policy["passed"] else "Failed",
    )


deadline, original = read_candidate("original.json", "late")
_, revised = read_candidate("revised.json", "passed")
print("## Payment alert timing demo\n")
print(f"| Candidate | Checkpoints | First firing from replay start | Delay vs baseline | Fire by {as_duration(deadline)} | Result |")
print("| --- | ---: | ---: | --- | --- | --- |")
print("| " + " | ".join(("Original rule", *original)) + " |")
print("| " + " | ".join(("Revised rule", *revised)) + " |")
PY
)
