#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 0 ]]; then
    printf 'Usage: bash scripts/demo.sh\n' >&2
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
    "$python" "$repo/incident_to_promtool.py" "$repo/demo/demo.json" \
        --matrix "$repo/demo/incident.matrix.json" --output payment.test.yml >&2
    "$python" "$repo/incident_to_promtool.py" compare payment.test.yml \
        --before "$repo/demo/before.rules.yml" --after "$repo/demo/after.rules.yml" --promtool "$promtool"
)
