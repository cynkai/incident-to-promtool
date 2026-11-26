#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
: "${GITHUB_STEP_SUMMARY:?GITHUB_STEP_SUMMARY is required}"
cd -- "${GITHUB_WORKSPACE:-.}"
cd -- "$INCIDENT_REPO_PATH"

fixture_paths=()
while IFS= read -r fixture_path; do
    fixture_path=${fixture_path%$'\r'}
    if [[ "$fixture_path" =~ [^[:space:]] ]]; then
        fixture_paths+=("$fixture_path")
    fi
done <<< "${INCIDENT_FIXTURES:-}"

if [[ -n "${INCIDENT_FIXTURE:-}" && -n "${fixture_paths[0]:-}" ]] ||
   [[ -z "${INCIDENT_FIXTURE:-}" && -z "${fixture_paths[0]:-}" ]]; then
    printf 'Provide exactly one of fixture or fixtures.\n' >&2
    exit 2
fi
if [[ -n "${INCIDENT_FIXTURE:-}" ]]; then
    fixture_paths+=("$INCIDENT_FIXTURE")
fi
for fixture_path in "${fixture_paths[@]}"; do
    if [[ ! -f "$fixture_path" ]]; then
        printf 'Incident fixture file not found: %q\n' "$fixture_path" >&2
        exit 2
    fi
done

rule_arguments=()
while IFS= read -r rule; do
    rule=${rule%$'\r'}
    if [[ "$rule" =~ [^[:space:]] ]]; then
        rule_arguments+=(--rule-file="$rule")
    fi
done <<< "$INCIDENT_RULE_FILES"
if [[ -z "${rule_arguments[0]:-}" ]]; then
    printf 'Provide at least one repository-relative path in rule-files.\n' >&2
    exit 2
fi

gate=${INCIDENT_GATE-strict}
case "$gate" in
    strict|regressions) ;;
    *)
        printf 'gate must be strict or regressions.\n' >&2
        exit 2
        ;;
esac

runner_temp=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
work_dir=$(mktemp -d "$runner_temp/incident-promtool.XXXXXXXX")
trap 'rm -rf -- "$work_dir"' EXIT

python=python3
case "$INCIDENT_RULE_FORMAT" in
    kubernetes)
        python3 -m venv "$work_dir/venv"
        python="$work_dir/venv/bin/python"
        "$python" -m pip install --disable-pip-version-check 'PyYAML==6.0.3'
        ;;
    prometheus) ;;
    *)
        printf 'rule-format must be prometheus or kubernetes.\n' >&2
        exit 2
        ;;
esac

promtool="$INCIDENT_PROMTOOL_PATH"
if [[ -z "$promtool" ]]; then
    bash "$INCIDENT_ACTION_PATH/scripts/install-promtool.sh" 3.11.0 "$work_dir"
    promtool="$work_dir/promtool"
fi

report_dir=$(mktemp -d "$runner_temp/incident-review.XXXXXXXX")
report="$report_dir/review.md"
status=0
command_token=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
# Prevent diagnostic text from repository content from being read as runner commands.
printf '::stop-commands::%s\n' "$command_token"
"$python" "$INCIDENT_ACTION_PATH/incident_to_promtool.py" compare \
    --before-ref="$INCIDENT_BEFORE_REF" --after-ref="$INCIDENT_AFTER_REF" \
    --promtool="$promtool" --rule-format="$INCIDENT_RULE_FORMAT" --gate "$gate" \
    "${rule_arguments[@]}" -- "${fixture_paths[@]}" > "$report" || status=$?
printf '::%s::\n' "$command_token"

if [[ -s "$report" ]]; then
    printf 'report-path=%s\n' "$report" >> "$GITHUB_OUTPUT"
    cat -- "$report" >> "$GITHUB_STEP_SUMMARY"
else
    rm -f -- "$report"
    rmdir -- "$report_dir"
fi
exit "$status"
