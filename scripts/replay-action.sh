#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
: "${GITHUB_STEP_SUMMARY:?GITHUB_STEP_SUMMARY is required}"
cd -- "${GITHUB_WORKSPACE:-.}"
cd -- "$INCIDENT_REPO_PATH"

nonempty_path_lines() {
    local path
    while IFS= read -r path; do
        path=${path%$'\r'}
        if [[ "$path" =~ [^[:space:]] ]]; then
            printf '%s\n' "$path"
        fi
    done <<< "$1"
}

bundle=${INCIDENT_BUNDLE:-}
fixture=${INCIDENT_FIXTURE:-}
fixture_ref=${INCIDENT_FIXTURE_REF:-}
capture_summaries=${INCIDENT_CAPTURE_SUMMARIES:-}
fixture_paths=()
while IFS= read -r fixture_path; do
    fixture_paths+=("$fixture_path")
done < <(nonempty_path_lines "${INCIDENT_FIXTURES:-}")
bundle_paths=()
while IFS= read -r bundle_path; do
    bundle_paths+=("$bundle_path")
done < <(nonempty_path_lines "${INCIDENT_BUNDLES:-}")

source_count=0
for source in "$fixture" "${fixture_paths[0]:-}" "$bundle" "${bundle_paths[0]:-}"; do
    if [[ -n "$source" ]]; then
        source_count=$((source_count + 1))
    fi
done
if [[ "$source_count" -ne 1 ]]; then
    printf 'Provide exactly one of fixture, fixtures, bundle, or bundles.\n' >&2
    exit 2
fi

timeline_alertname=${INCIDENT_TIMELINE_ALERTNAME:-}
timeline_end=${INCIDENT_TIMELINE_END:-}
timeline_max_delay=${INCIDENT_TIMELINE_MAX_DELAY:-}
timeline_fixture=${INCIDENT_TIMELINE_FIXTURE:-}
timeline_bundle=${INCIDENT_TIMELINE_BUNDLE:-}
timeline_policy=${INCIDENT_TIMELINE_POLICY:-}
bundle_mode=0
if [[ -n "$bundle" || -n "${bundle_paths[0]:-}" ]]; then
    bundle_mode=1
fi

timeline_mode=disabled
if [[ -n "$timeline_policy" ]]; then
    timeline_mode=policy
fi
if [[ -n "$timeline_alertname" || -n "$timeline_end" || -n "$timeline_max_delay" ||
      -n "$timeline_fixture" || -n "$timeline_bundle" ]]; then
    if [[ "$timeline_mode" == policy ]]; then
        printf 'Provide timeline-policy or individual timeline inputs.\n' >&2
        exit 2
    fi
    if [[ "$bundle_mode" -eq 1 && -n "$timeline_fixture" ]]; then
        printf 'timeline-fixture requires fixture or fixtures.\n' >&2
        exit 2
    fi
    if [[ "$bundle_mode" -eq 0 && -n "$timeline_bundle" ]]; then
        printf 'timeline-bundle requires bundle or bundles.\n' >&2
        exit 2
    fi
    if [[ ! "$timeline_alertname" =~ [^[:space:]] || ! "$timeline_end" =~ [^[:space:]] ||
          ! "$timeline_max_delay" =~ [^[:space:]] ]]; then
        printf 'Provide timeline-alertname, timeline-end, and timeline-max-delay together.\n' >&2
        exit 2
    fi
    timeline_mode=single
fi

if [[ "$bundle_mode" -eq 1 ]]; then
    if [[ -n "$fixture_ref" || -n "$capture_summaries" ]]; then
        printf 'fixture-ref and capture-summaries require fixture or fixtures.\n' >&2
        exit 2
    fi
    if [[ -n "$bundle" ]]; then
        bundle_paths+=("$bundle")
    fi
    comparison_arguments=(compare-bundle --bundle-ref="$INCIDENT_BEFORE_REF" --after-ref="$INCIDENT_AFTER_REF")
    input_paths=("${bundle_paths[@]}")
else
    if [[ -n "$fixture" ]]; then
        fixture_paths+=("$fixture")
    fi
    comparison_arguments=(compare --before-ref="$INCIDENT_BEFORE_REF" --after-ref="$INCIDENT_AFTER_REF")
    input_paths=("${fixture_paths[@]}")
    if [[ -n "$fixture_ref" ]]; then
        comparison_arguments+=(--fixture-ref="$fixture_ref")
    else
        for fixture_path in "${fixture_paths[@]}"; do
            if [[ ! -f "$fixture_path" ]]; then
                printf 'Incident fixture file not found: %q\n' "$fixture_path" >&2
                exit 2
            fi
        done
    fi

    summary_paths=()
    while IFS= read -r summary_path; do
        summary_paths+=("$summary_path")
    done < <(nonempty_path_lines "$capture_summaries")
    if [[ -n "${summary_paths[0]:-}" ]]; then
        if [[ "${#summary_paths[@]}" -ne "${#fixture_paths[@]}" ]]; then
            printf 'Provide one capture summary path per fixture.\n' >&2
            exit 2
        fi
        for summary_path in "${summary_paths[@]}"; do
            if [[ -z "$fixture_ref" && ! -f "$summary_path" ]]; then
                printf 'Capture summary file not found: %q\n' "$summary_path" >&2
                exit 2
            fi
            comparison_arguments+=(--capture-summary="$summary_path")
        done
    fi
fi

if [[ "$timeline_mode" == policy ]]; then
    comparison_arguments+=(--timeline-policy="$timeline_policy")
elif [[ "$timeline_mode" == single ]]; then
    comparison_arguments+=(--timeline-alertname="$timeline_alertname" --timeline-end="$timeline_end"
        --timeline-max-delay="$timeline_max_delay")
    if [[ -n "$timeline_fixture" ]]; then
        comparison_arguments+=(--timeline-fixture="$timeline_fixture")
    elif [[ -n "$timeline_bundle" ]]; then
        comparison_arguments+=(--timeline-bundle="$timeline_bundle")
    fi
fi

rule_arguments=()
while IFS= read -r rule; do
    rule_arguments+=(--rule-file="$rule")
done < <(nonempty_path_lines "${INCIDENT_RULE_FILES:-}")
before_rule_arguments=()
while IFS= read -r rule; do
    before_rule_arguments+=(--before-rule-file="$rule")
done < <(nonempty_path_lines "${INCIDENT_BEFORE_RULE_FILES:-}")
after_rule_arguments=()
while IFS= read -r rule; do
    after_rule_arguments+=(--after-rule-file="$rule")
done < <(nonempty_path_lines "${INCIDENT_AFTER_RULE_FILES:-}")

if [[ -n "${before_rule_arguments[0]:-}" || -n "${after_rule_arguments[0]:-}" ]]; then
    if [[ -n "${rule_arguments[0]:-}" ]]; then
        printf 'Provide either rule-files or both before-rule-files and after-rule-files.\n' >&2
        exit 2
    fi
    if [[ -z "${before_rule_arguments[0]:-}" || -z "${after_rule_arguments[0]:-}" ]]; then
        printf 'Provide at least one path in both before-rule-files and after-rule-files.\n' >&2
        exit 2
    fi
    rule_arguments=("${before_rule_arguments[@]}" "${after_rule_arguments[@]}")
elif [[ -z "${rule_arguments[0]:-}" ]]; then
    printf 'Provide either rule-files or both before-rule-files and after-rule-files.\n' >&2
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
json_report="$report_dir/review.json"
junit_report="$report_dir/review.xml"
status=0
command_token=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
# Prevent diagnostic text from repository content from being read as runner commands.
printf '::stop-commands::%s\n' "$command_token"
"$python" "$INCIDENT_ACTION_PATH/incident_to_promtool.py" \
    "${comparison_arguments[@]}" \
    --promtool="$promtool" --rule-format="$INCIDENT_RULE_FORMAT" --gate "$gate" \
    --json-report "$json_report" --junit-report "$junit_report" \
    "${rule_arguments[@]}" -- "${input_paths[@]}" > "$report" || status=$?
printf '::%s::\n' "$command_token"

if [[ "$status" -le 1 ]]; then
    if [[ -s "$report" && -s "$json_report" && -s "$junit_report" ]] &&
        report_values=$("$python" - "$json_report" "$timeline_mode" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as source:
        report = json.load(source)
    count = report["summary"]["newly_failed"]
    timeline_mode = sys.argv[2]
    timeline_passed = None
    if timeline_mode == "policy":
        timeline_passed = report["timeline_policy"]["passed"]
    elif timeline_mode == "single":
        timeline_passed = report["timeline"]["gate"]["passed"]
except (OSError, ValueError, KeyError, TypeError):
    sys.exit(1)
if type(count) is not int or count < 0 or (timeline_mode != "disabled" and type(timeline_passed) is not bool):
    sys.exit(1)
print(count, str(timeline_passed).lower() if timeline_passed is not None else "")
PY
    ); then
        read -r newly_failed timeline_passed <<< "$report_values"
        cat -- "$report" >> "$GITHUB_STEP_SUMMARY"
        {
            printf 'report-path=%s\njson-report-path=%s\njunit-report-path=%s\nnewly-failed=%s\n' \
                "$report" "$json_report" "$junit_report" "$newly_failed"
            if [[ -n "$timeline_passed" ]]; then
                printf 'timeline-passed=%s\n' "$timeline_passed"
            fi
        } >> "$GITHUB_OUTPUT"
        exit "$status"
    fi
    printf 'Could not read complete Markdown, JSON, and JUnit XML comparison reports.\n' >&2
    status=2
fi

rm -f -- "$report" "$json_report" "$junit_report"
rmdir -- "$report_dir"
exit "$status"
