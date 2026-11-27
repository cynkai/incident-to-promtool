# Incident to Promtool

Turn a past Prometheus incident into a pull request check.

## Quickstart

Clone the repository and run the demo.

```sh
git clone https://github.com/cynkai/incident-to-promtool.git
cd incident-to-promtool
bash scripts/demo.sh
```

The demo replays synthetic payment metrics without a Prometheus server. It checks that the alert stays quiet before the outage and is firing five minutes after it starts. The original rule matches **1/2** checkpoints. The revised rule matches **2/2** and passes the check.

Run `bash scripts/demo.sh --timing` for the same offline payment replay with a seven-minute firing deadline. [Payment timing demo](#발화-기한-예제)

Use `timeline` to compare an alert's first firing across Git revisions. The GitHub Action can enforce delay limits and firing deadlines from a committed timing policy alongside checkpoint checks. [GitHub Action timing policy](#발화-지연-정책)

Use Python 3.10+ and `promtool` 3.9+. With no local `promtool`, the demo downloads and verifies a pinned binary on Linux x64. Set `PROMTOOL=/path/to/promtool` to use a specific executable.

Commit a fixture for your own incident, compare rule changes between Git refs, and add the same check to CI. Detailed examples are available in Korean. [Capture an incident](#내-prometheus로-실행) · [Plan capture selectors](#캡처할-시계열-계획) · [Raw metric snapshot](#원본-시계열-스냅샷) · [Bundle an incident](#장애-재현-번들) · [Inspect sample gaps](#시계열-표본-간격-확인) · [Alertmanager webhook](#alertmanager-웹훅으로-기대-동작-만들기) · [Native Prometheus rules](#룰-변경-전후-비교) · [Git ref comparison](#git-커밋으로-비교) · [Kubernetes PrometheusRule](#kubernetes-prometheusrule로-테스트) · [GitHub Action](#github-actions에서-pr-검사)

### Install the CLI from GitHub

Install the command in a Python virtual environment.

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install 'git+https://github.com/cynkai/incident-to-promtool.git'
```

For Kubernetes manifests, install the `kubernetes` extra with `python3 -m pip install 'incident-to-promtool[kubernetes] @ git+https://github.com/cynkai/incident-to-promtool.git'`. Install `promtool` 3.9+ separately for rule comparisons. From the cloned repository, try the installed command on the demo files.

```sh
mkdir -p demo/generated
incident-to-promtool demo/demo.json --matrix demo/incident.matrix.json \
  --output demo/generated/installed.test.yml
incident-to-promtool compare demo/generated/installed.test.yml \
  --before demo/before.rules.yml --after demo/after.rules.yml
```

장애 구간의 시계열과 팀이 정한 알람 기대 동작으로 `promtool` 테스트 파일을 만듭니다. 같은 데이터에서 기존 룰과 수정 룰을 비교해 PR에 붙일 Markdown 리포트를 만들고, 테스트 파일을 커밋해 이후 변경에도 같은 검사를 실행할 수 있습니다.

## 결제 장애 예제 실행

저장소 루트에서 `bash scripts/demo.sh`로 데모를 바로 실행하거나 아래 단계를 차례로 실행할 수 있습니다. 수동 실행에는 Python 3.10 이상과 `promtool` 3.9 이상이 필요합니다. 예제는 `alarm-study`의 결제 장애에서 착안한 합성 데이터입니다. [alarm-study](https://github.com/cynkai/alarm-study)

```sh
mkdir -p demo/generated
python3 incident_to_promtool.py demo/demo.json \
  --matrix demo/incident.matrix.json --rule-file demo/before.rules.yml \
  --output demo/generated/before.test.yml
promtool test rules demo/generated/before.test.yml
# FAIL — 장애 시작 5분 시점에 PaymentErrorsHigh가 아직 발화하지 않음

python3 incident_to_promtool.py demo/demo.json \
  --matrix demo/incident.matrix.json --output demo/generated/after.test.yml
promtool test rules demo/generated/after.test.yml
# SUCCESS — 장애 이전에는 조용하고, 시작 5분 시점에는 발화 중
```

`for`를 6분에서 2분으로 바꾸면 이 데이터에서 최초 발화가 장애 시작 후 7분 30초에서 3분 30초로 앞당겨집니다. 다시 생성할 때는 새 출력 경로를 사용하세요.

### 발화 기한 예제

```sh
bash scripts/demo.sh --timing
```

저장소에 있는 `demo/timing.incident.json`과 `demo/timing.policy.json`을 사용해, 같은 합성 결제 시계열에서 두 후보를 원래 룰과 각각 비교합니다. 두 후보 모두 체크포인트 `2/2`를 충족하고 기준 대비 지연 허용치 `0s`를 통과합니다. 원래 룰은 테스트 시작 `9m30s`에 발화해 `7m` 기한을 넘깁니다. 수정 룰은 `5m30s`에 발화해 기한을 충족합니다.

스크립트는 두 결과를 재현하면 `0`으로 종료하며 표준 출력에 두 비교를 담은 Markdown 요약을 남깁니다. 같은 파일로 수정 룰의 전체 Markdown과 JSON을 보려면 아래 명령을 실행합니다. [발화 지연 정책](#발화-지연-정책)

```sh
mkdir -p demo/generated
python3 incident_to_promtool.py demo/timing.incident.json \
  --matrix demo/incident.matrix.json --output demo/generated/payment-timing.test.yml
python3 incident_to_promtool.py compare demo/generated/payment-timing.test.yml \
  --before demo/before.rules.yml --after demo/after.rules.yml \
  --timeline-policy demo/timing.policy.json --json-report demo/generated/timing-review.json
```

## 룰 변경 전후 비교

앞에서 생성한 테스트의 시계열과 기대 동작을 그대로 사용해 두 룰을 오프라인으로 검증합니다. 리포트는 표준 출력으로 나오므로 파일에 저장해 PR에 붙일 수 있습니다.

```sh
python3 incident_to_promtool.py compare demo/generated/after.test.yml \
  --before demo/before.rules.yml --after demo/after.rules.yml > demo/generated/review.md
```

비교 입력은 이 CLI가 JSON 문법으로 생성한 `.test.yml` 파일입니다. 파일을 하나 지정하거나 여러 장애 파일을 이어서 지정할 수 있습니다. 같은 파일은 한 번씩 지정합니다. 리포트에는 전체 검사 건수와 장애별 검사 건수, 기대 동작과 달랐던 결과가 표시됩니다. 의존 룰 파일은 `--before`와 `--after`를 각각 반복해서 지정하세요. `--promtool /path/to/promtool`로 실행 파일을 지정할 수 있습니다.

기본 `--gate strict`에서는 수정 룰이 모든 검사를 통과해야 합니다. `--gate regressions`를 지정하면 기존 룰에서 통과하고 수정 룰에서 실패한 검사가 있을 때 게이트가 실패합니다. 같은 검사는 테스트 파일, 테스트 그룹, 알람 이름, 테스트 시작부터의 평가 시점으로 식별합니다.

리포트에는 게이트 결과와 새로 실패한 검사(`Newly failed`), 다시 통과한 검사(`Fixed`), 여전히 실패하는 검사(`Still failing`)가 표시됩니다. `regressions`에서 게이트를 통과해도 기존 실패는 리포트에 남습니다. 종료 코드는 게이트 통과 `0`, 게이트 실패 `1`, 입력 또는 `promtool` 실행 오류 `2`입니다. 실행 오류는 두 모드 모두 로그에 표시됩니다.

캡처 요약을 보관했다면 `--capture-summary PATH`로 비교에 사용할 테스트 파일이 생성 당시와 같은지 검증할 수 있습니다. 이 옵션을 쓸 때는 위치 인자로 지정한 테스트 파일마다 하나씩, 같은 순서로 요약을 지정합니다. v1 요약의 `fixture_sha256`을 테스트 파일 바이트의 SHA-256과 대조합니다. 요약이 유효하지 않거나 해시가 다르면 `promtool` 실행 전에 종료 코드 `2`를 반환합니다. [캡처 요약 JSON](#캡처-요약-json)

### 알람 발화 타임라인

`timeline`은 생성한 `.test.yml`에 `--alertname`의 기대 동작이 들어 있는 테스트 그룹을 찾아, 같은 시계열에서 기존 룰과 수정 룰의 발화 시점을 비교합니다.

```sh
python3 incident_to_promtool.py timeline demo/generated/after.test.yml \
  --before demo/before.rules.yml --after demo/after.rules.yml \
  --alertname PaymentErrorsHigh --end 10m
```

`--start`(기본 `0s`)와 `--end`는 각 테스트 그룹 시작 기준의 오프셋이며, 양끝 모두 평가 간격에 맞춰 지정합니다. 보고 범위에는 시작과 끝이 모두 들어갑니다. 평가는 항상 `0s`에서 시작해 보고 범위 앞의 상태도 재현합니다. 룰 버전별로 워밍업과 선택한 모든 테스트 그룹을 합해 최대 10,000개의 평가 시점을 사용할 수 있습니다.

지정한 이름의 알람이 라벨 조합 하나에서라도 발화하면 해당 평가 시점을 발화로 기록합니다. 리포트에는 범위 안에서 처음 관측한 발화, 연속된 평가 시점에서 발화한 구간, 양쪽에서 모두 발화가 관측됐을 때의 첫 발화 차이(수정 − 기준)가 들어갑니다. 구간 끝은 마지막으로 발화가 관측된 시점입니다. `--end`까지 이어지는 구간의 해제 시각은 이후 관측이 있어야 판단할 수 있습니다.

결제 예제에서는 테스트 시작부터 기준 룰 `570s`, 수정 룰 `330s`에 처음 발화가 관측돼 수정 룰이 `240s` 앞섭니다. 기본 출력은 Markdown이며 `--format json`으로 JSON을 받습니다. 의존 룰은 `--before`와 `--after`를 반복해 지정하고, Kubernetes `PrometheusRule`은 `--rule-format kubernetes`를 사용합니다. `--promtool`로 실행 파일을 지정할 수 있습니다. 체크포인트에 정의한 기대 동작은 `compare`에서 검증합니다.

#### CI에서 발화 지연 제한

`--max-delay`를 지정하면 `0s`부터 `--end`까지 관측한 최초 발화에 지연 게이트를 적용합니다. `--start`는 타임라인의 표시 범위를 정합니다. 기준 룰이 발화한 그룹마다 수정 룰도 `--end`까지 발화해야 하고, 최초 발화 차이(수정 − 기준)는 허용치 이하여야 합니다. 허용치와 같아도 통과합니다. `--max-delay 0s`는 기준과 같거나 더 이른 발화를 허용합니다.

기준 발화가 관측된 그룹만 지연을 검사합니다. 그런 그룹이 하나도 없으면 판정 근거가 부족해 게이트가 실패합니다.

```sh
python3 incident_to_promtool.py timeline demo/generated/after.test.yml \
  --before demo/after.rules.yml --after demo/before.rules.yml \
  --alertname PaymentErrorsHigh --start 9m --end 10m --max-delay 1m
```

`9m`부터 표시한 타임라인에서는 `30s` 차이가 보입니다. 게이트는 `0s`부터의 발화 지연 `240s`를 사용해 `1m` 한도를 초과한 것으로 판정합니다. Markdown에는 게이트 판정과 그 근거를 별도 표로 표시합니다.

`--max-delay`와 `--format json`을 같이 사용하면 JSON의 `gate`에 `mode`(`max-delay`), `max_delay_ms`, `passed`, `checked_groups`, `groups`가 들어갑니다. `groups`의 각 항목은 `group`, `status`, `before_first_firing_offset_ms`, `after_first_firing_offset_ms`, `first_firing_delta_ms`를 기록합니다. 이 시점과 차이는 `0s`부터 관측한 결과입니다. `status`는 `passed`, `delayed`, `missing_after`, `no_baseline` 중 하나입니다.

종료 코드는 게이트 없이 보고를 완료했거나 게이트를 통과했을 때 `0`, 게이트 실패 `1`, 입력 또는 실행 오류 `2`입니다.

`compare`와 `compare-bundle`에서 체크포인트와 최초 발화를 함께 검사하려면 `--timeline-alertname`, `--timeline-end`와 함께 `--timeline-max-delay`나 `--timeline-fire-by`를 지정합니다. 두 조건을 함께 적용할 수도 있습니다. 입력이 여러 개면 `compare`는 `--timeline-fixture`, `compare-bundle`은 `--timeline-bundle`로 대상을 지정합니다. 여러 발화 검사는 `--timeline-policy`로 구성할 수 있습니다. [발화 지연 정책](#발화-지연-정책)

#### 최초 발화 기한

`--fire-by`는 테스트 그룹 시작을 기준으로 수정 룰의 최초 발화 기한을 정합니다. 기한은 `--end` 이하여야 하며, 기한과 같은 시점에 발화해도 통과합니다. 게이트는 `0s`부터 `--end`까지 관측한 최초 발화를 사용합니다. `--start`는 표시 범위의 시작입니다.

선택한 알람에서 `exp_alerts`가 비어 있지 않은 체크포인트가 있는 그룹만 검사합니다. 발화를 기대하는 그룹이 하나도 없으면 입력 오류(`2`)입니다. 기준 룰의 발화 여부와 관계없이 수정 룰의 발화 시점으로 판정합니다.

```sh
python3 incident_to_promtool.py timeline demo/generated/after.test.yml \
  --before demo/before.rules.yml --after demo/before.rules.yml \
  --alertname PaymentErrorsHigh --end 10m --max-delay 0s --fire-by 7m
```

두 룰의 최초 발화 시점이 `570s`로 같으므로 상대 지연 검사는 통과합니다. 수정 룰은 `7m` 기한을 넘겨 기한 검사가 실패하며, 명령은 `1`로 종료합니다.

`--format json`에서 `gate`는 `--max-delay` 판정입니다. `--fire-by`를 지정하면 `deadline_gate`에 `mode`(`fire-by`), `fire_by_ms`, `passed`, `checked_groups`, `groups`를 추가합니다. 각 그룹에는 `after_first_firing_offset_ms`와 `passed`, `late`, `missing_after` 중 하나인 `status`가 들어갑니다. `--fire-by`를 지정한 리포트의 최상위 `passed`는 발화 조건 전체의 판정입니다.

#### Git 커밋의 룰로 타임라인 재생

`timeline`에서도 `--before-ref`와 `--after-ref`를 지정해 각 커밋의 룰을 읽을 수 있습니다. 두 커밋의 공통 경로를 `--rule-file`로 제공하거나, `--before-rule-file`과 `--after-rule-file`로 양쪽 목록을 각각 제공합니다. 룰 경로는 저장소 루트 기준이며 각 옵션을 반복할 수 있습니다. `--repo DIR`을 생략하면 현재 디렉터리의 Git 저장소를 사용합니다.

`--fixture-ref`를 지정하면 그 커밋에서 테스트 파일과 선택한 `--capture-summary` 파일 한 개를 읽습니다. 두 경로는 저장소 루트 기준입니다. `--fixture-ref`를 생략하면 현재 디렉터리 기준의 로컬 경로나 절대 경로를 사용합니다. 캡처 요약을 제공하면 테스트 파일의 SHA-256을 검증합니다.

```sh
python3 incident_to_promtool.py timeline tests/fixtures/payment.test.yml \
  --before-ref 'HEAD^1' --after-ref HEAD --rule-file prometheus/payment.rules.yml \
  --fixture-ref 'HEAD^1' --capture-summary tests/fixtures/payment.capture.json \
  --alertname PaymentErrorsHigh --end 10m --max-delay 1m --format json
```

룰을 읽는 두 Git ref와 선택한 테스트 ref를 로컬에 가져와야 합니다. GitHub Actions에서는 `fetch-depth: 0`으로 필요한 이력을 가져올 수 있습니다. PR의 두 커밋을 직접 비교하려면 `github.event.pull_request.base.sha`와 `github.event.pull_request.head.sha`를 기준 및 수정 ref로 사용합니다.

Git 리포트는 확정된 커밋 ID와 사용한 룰 경로를 기록합니다. JSON에서는 `commits`와 `rule_files`로 확인할 수 있습니다. `--fixture-ref`는 `fixture_commit`을, `--capture-summary`는 검증한 요약의 경로 `capture_summary`를 추가합니다. 둘 중 하나를 지정하면 테스트의 해시 `fixture_sha256`도 포함합니다.

### JSON 리포트

자동화에서 비교 결과를 읽으려면 `--json-report`를 추가합니다. JSON 출력은 새 경로를 지정합니다. 종료 코드 `0`과 `1`에서 JSON이 기록되고, 입력이나 실행 오류(`2`)가 발생하면 JSON 파일은 생성되지 않습니다.

```sh
python3 incident_to_promtool.py compare demo/generated/after.test.yml \
  --before demo/before.rules.yml --after demo/after.rules.yml \
  --json-report demo/generated/review.json > demo/generated/review.md
```

- `schema_version`은 `1`입니다. `gate`에는 모드 `mode`와 통과 여부 `passed`가 들어갑니다.
- `commits`는 Git 비교의 `{before, after}` 커밋 ID이며 파일 경로로 비교할 때는 `null`입니다.
- `summary`에는 `before`와 `after`의 `{matched, total}` 및 `newly_failed`, `fixed`, `still_failing` 건수가 들어갑니다.
- `fixtures`는 `path`, `before`, `after`, `changes`를 담은 배열입니다. 각 `changes` 항목은 `group`(1부터 시작), `alertname`, `offset_ms`(테스트 시작 기준), `change`, `before_diagnostic`, `after_diagnostic`를 포함합니다. `change`는 `newly_failed`, `fixed`, `still_failing` 중 하나이며, 해당 버전에서 조건을 충족한 경우 진단값은 `null`입니다.
- `--fixture-ref`를 지정하면 최상위 `fixture_commit`에 테스트 파일을 읽은 커밋 ID를 기록합니다. 각 `fixtures` 항목은 커밋에서 읽었거나 캡처 요약으로 검증했을 때 `sha256`을 포함합니다. 캡처 요약으로 검증한 경우 `capture_summary`에 요약 경로를 기록합니다.
- `--before-rule-file`과 `--after-rule-file`을 사용하면 최상위 `rule_files`의 `before`와 `after` 배열에 기준 커밋과 수정 커밋의 룰 경로 목록을 기록합니다.

### JUnit XML 리포트

`compare`와 `compare-bundle`에서 `--junit-report PATH`로 JUnit XML을 저장합니다. 출력에는 새 경로를 지정합니다. `--json-report`를 함께 사용할 때는 두 리포트에 서로 다른 경로를 사용합니다. 리포트는 비교가 완료되는 종료 코드 `0`과 `1`에서만 생성됩니다.

```sh
python3 incident_to_promtool.py compare demo/generated/after.test.yml \
  --before demo/before.rules.yml --after demo/after.rules.yml \
  --json-report demo/generated/payment-review.json \
  --junit-report demo/generated/payment-review.xml
```

테스트 파일마다 스위트 하나, 검사 시점마다 테스트 케이스 하나를 기록합니다. `strict`에서는 수정 룰의 모든 불일치가 실패이고, `regressions`에서는 새로 발생한 불일치가 실패입니다. 다시 통과한 검사와 `regressions`에서 허용한 기존 실패의 진단은 `system-out`에 기록합니다.

### Git 커밋으로 비교

두 Git ref를 지정하면 현재 체크아웃을 유지한 채 각 커밋에서 룰을 읽습니다. Markdown 리포트에는 확정된 두 커밋 ID가 들어가며 종료 코드는 파일 경로로 비교할 때와 같습니다.

```sh
python3 incident_to_promtool.py compare \
  tests/fixtures/payment.test.yml tests/fixtures/checkout.test.yml \
  --before-ref "$BASE_SHA" --after-ref "$HEAD_SHA" \
  --rule-file prometheus/payment.rules.yml \
  --rule-file prometheus/checkout.rules.yml > review.md
```

`--repo`를 생략하면 현재 디렉터리의 Git 저장소를 사용합니다. `--rule-file`에는 두 커밋에 모두 있는 일반 파일의 경로를 저장소 루트 기준으로 지정합니다. 경로 구분자는 `/`입니다. 의존 룰 파일은 `--rule-file`을 반복해서 추가하세요. `--promtool`로 실행 파일을 지정할 수 있습니다.

PR의 기준 커밋에 있는 기대 동작으로 비교하려면 `--fixture-ref 'HEAD^1'`을 추가할 수 있습니다. 이 경우 작업 트리에서 파일을 수정했거나 그 경로에 파일이 없어도 지정한 커밋에서 테스트 파일과 선택한 캡처 요약을 읽습니다. 두 파일의 경로는 모두 저장소 루트 기준입니다.

```sh
python3 incident_to_promtool.py compare tests/fixtures/payment.test.yml \
  --before-ref 'HEAD^1' --after-ref HEAD --rule-file prometheus/payment.rules.yml \
  --fixture-ref 'HEAD^1' --capture-summary tests/fixtures/payment.capture.json
```

룰 파일의 이름을 바꾸거나 여러 파일을 분할·병합하는 경우에는 `--before-rule-file`과 `--after-rule-file`로 각 커밋의 경로를 지정합니다. `--before-ref`와 `--after-ref` 및 양쪽 경로 목록을 모두 제공하며, 경로는 저장소 루트 기준입니다. 공통 경로(`--rule-file`), 커밋별 경로, 로컬 파일(`--before`, `--after`) 중 한 방식을 선택합니다. `--rule-format kubernetes`는 두 커밋의 룰에 적용합니다.

```sh
python3 incident_to_promtool.py compare tests/fixtures/payment.test.yml \
  --before-ref 'HEAD^1' --after-ref HEAD --fixture-ref 'HEAD^1' \
  --before-rule-file prometheus/payment.rules.yml \
  --after-rule-file prometheus/payment/alerts.yml \
  --after-rule-file prometheus/payment/recording.yml \
  --json-report review-split.json
```

### GitHub Actions에서 PR 검사

테스트 파일과 룰을 커밋한 뒤 PR 워크플로에 액션을 추가합니다. 기본 PR 체크아웃에서 읽은 동일한 테스트 파일을 적용해 GitHub가 만든 머지 후보(`HEAD`)와 그 첫 부모(`HEAD^1`)를 비교합니다. 두 커밋이 로컬 Git 이력에 있도록 전체 이력을 가져옵니다.

```yaml
name: Alert rule review
on:
  pull_request:
permissions:
  contents: read
jobs:
  compare:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0
          persist-credentials: false
      - name: Compare alert rules
        id: compare
        uses: cynkai/incident-to-promtool@main
        with:
          fixtures: |
            tests/fixtures/payment.test.yml
            tests/fixtures/checkout.test.yml
          rule-files: |
            prometheus/payment.rules.yml
            prometheus/checkout.rules.yml
```

테스트 파일을 하나 검사하면 `fixture`, 여러 개 검사하면 `fixtures`를 사용합니다. 테스트 파일은 `repo-path` 기준 경로이며 `fixtures`에서는 한 줄에 하나씩 적습니다. 두 커밋의 룰 경로가 같으면 `rule-files`에 저장소 루트 기준으로 한 줄에 하나씩 적습니다.

파일 이동이나 분할·병합을 비교할 때는 `fixture` 또는 `fixtures`와 함께 `before-rule-files`와 `after-rule-files`를 모두 지정합니다. 공통 `rule-files`와 커밋별 목록 중 한 방식을 선택합니다. 각 목록에는 저장소 루트 기준 경로를 한 줄에 하나씩 적습니다. 위 비교 단계의 `with`를 아래와 같이 바꿀 수 있습니다.

```yaml
with:
  fixture: tests/fixtures/payment.test.yml
  fixture-ref: 'HEAD^1'
  before-rule-files: |
    prometheus/payment.rules.yml
  after-rule-files: |
    prometheus/payment/alerts.yml
    prometheus/payment/recording.yml
```

| 선택 입력 | 기본값과 용도 |
| --- | --- |
| `repo-path` | `.`. 체크아웃한 Git 저장소 경로 |
| `rule-format` | `prometheus`. 렌더링된 `PrometheusRule`은 `kubernetes`. 번들에 담긴 기준 룰을 사용할 때는 수정 룰에만 적용합니다. |
| `before-ref`, `after-ref` | `HEAD^1`, `HEAD`. 다른 Git ref를 쓰려면 두 커밋을 미리 가져옵니다. |
| `fixture-ref` | `fixture` 또는 `fixtures`에서 사용합니다. 기본은 작업 트리이며, PR 기준 커밋의 테스트를 쓰려면 `with`에 `fixture-ref: 'HEAD^1'`을 지정합니다. |
| `capture-summaries` | `fixture` 또는 `fixtures`에서 사용합니다. v1 캡처 요약 경로를 테스트 파일과 같은 순서로 한 줄에 하나씩 지정합니다. `fixture-ref`를 쓰면 같은 커밋의 저장소 루트 기준 경로를 사용합니다. |
| `gate` | `strict`. 새로 실패한 검사만 단계 실패로 처리하려면 `with`에 `gate: regressions`를 지정합니다. |
| `promtool-path` | 생략하면 Linux x64에서 고정된 Promtool 3.11.0을 설치합니다. 기존 실행 파일은 작업 디렉터리 기준 경로나 `PATH`에 있는 명령으로 지정합니다. |

`kubernetes` 모드는 PyYAML 6.0.3을 격리된 가상 환경에 설치합니다. 완료된 비교는 실행 요약을 남기며 `steps.compare.outputs.report-path`로 Markdown 경로, `steps.compare.outputs.json-report-path`로 JSON 경로, `steps.compare.outputs.junit-report-path`로 JUnit XML 경로, `steps.compare.outputs.newly-failed`로 새로 실패한 검사 건수(문자열)를 제공합니다. 게이트를 통과하지 못해도 이 출력들은 제공됩니다. 입력이나 실행 오류는 단계 로그에만 표시됩니다.

게이트가 실패한 경우에도 후속 단계에서 JSON을 읽으려면 해당 단계에 `if: ${{ always() && steps.compare.outputs.json-report-path != '' }}`를 지정합니다. JUnit XML에는 같은 조건에서 `junit-report-path`를 사용합니다.

#### PR에서 최초 발화 지연 검사

`timeline-alertname`, `timeline-end`와 함께 `timeline-max-delay` 또는 `timeline-fire-by`를 설정합니다. 두 조건을 함께 지정할 수도 있습니다. `fixture` 또는 `fixtures`에서는 `timeline-fixture`, `bundle` 또는 `bundles`에서는 `timeline-bundle`로 대상을 선택합니다. 입력이 하나면 그 파일을 기본으로 선택합니다. 여러 개면 해당 선택 옵션이 필요합니다. 선택할 때는 입력에 적은 경로를 그대로 사용합니다.

체크포인트 검사에서 읽은 테스트와 룰을 사용해 `0s`부터 `timeline-end`까지의 최초 발화를 봅니다. `timeline-end`는 선택한 테스트의 평가 간격에 맞춥니다. 선택한 체크포인트 게이트(`strict` 또는 `regressions`)와 지정한 발화 조건을 모두 통과하면 단계가 성공합니다.

```yaml
with:
  fixture: tests/fixtures/payment.test.yml
  fixture-ref: 'HEAD^1'
  capture-summaries: |
    tests/fixtures/payment.capture.json
  rule-files: |
    prometheus/payment.rules.yml
  timeline-alertname: PaymentErrorsHigh
  timeline-end: '10m'
  timeline-max-delay: '0s'
  timeline-fire-by: '7m'
```

Markdown은 체크포인트 결과와 발화 타임라인을 함께 보여줍니다. JSON의 `timeline`에는 발화 타임라인과 지정한 발화 조건의 판정을 담고, 최상위 `gate`는 체크포인트 판정을 담습니다. JUnit XML에는 `Alert firing delay` 스위트가 추가되며 타임라인 검사 하나당 테스트 케이스 하나가 전체 검사 수에 반영됩니다.

발화 검사를 켜면 `steps.compare.outputs.timeline-passed`에 발화 조건 전체의 통과 여부를 문자열 `true` 또는 `false`로 제공합니다. 게이트가 실패해도 이 값을 읽을 수 있습니다. `newly-failed`는 새로 실패한 체크포인트 수입니다.

#### 발화 지연 정책

여러 알람이나 장애를 함께 검사할 때는 CLI의 `compare` 또는 `compare-bundle`에 `--timeline-policy PATH`를 지정합니다. GitHub Action 입력은 `timeline-policy`입니다. 정책 방식과 위의 단일 지연 검사 옵션 중 하나를 선택합니다.

아래 `tests/fixtures/payment-timing.json`은 두 결제 장애의 테스트 파일에서 같은 `PaymentErrorsHigh` 알람을 검사합니다.

```json
{
  "schema_version": 1,
  "checks": [
    {"source": "tests/fixtures/payment-timeout.test.yml", "alertname": "PaymentErrorsHigh", "end": "10m", "max_delay": "0s", "fire_by": "7m"},
    {"source": "tests/fixtures/payment-peak.test.yml", "alertname": "PaymentErrorsHigh", "end": "10m", "fire_by": "7m"}
  ]
}
```

입력이 하나면 `source`를 생략할 수 있습니다. 여러 개면 각 검사에 명령이나 액션에 지정한 테스트 또는 ZIP 경로를 그대로 적습니다. 같은 `source`와 `alertname` 조합은 한 번만 지정합니다. 각 검사에는 `max_delay`와 `fire_by` 중 하나 이상을 지정합니다. `end`는 해당 테스트의 평가 시점에 맞추고 `fire_by`는 `end` 이하로 지정합니다. `max_delay`에는 `0s`도 사용할 수 있습니다. 전체 정책은 룰 버전마다 최대 10,000개의 평가 시점을 사용할 수 있습니다.

`compare`에서 `--fixture-ref`를 사용하면 그 커밋에서 정책을 읽습니다. Git의 `compare-bundle`은 `--bundle-ref`에서, Action의 번들 비교는 `before-ref`에서 정책을 읽습니다. 이때 정책과 `source` 경로는 저장소 루트 기준입니다. 나머지 경우에는 로컬 파일 경로를 사용합니다.

두 테스트 파일과 정책을 기준 커밋에 보관한 뒤 실행합니다.

```sh
python3 incident_to_promtool.py compare \
  tests/fixtures/payment-timeout.test.yml tests/fixtures/payment-peak.test.yml \
  --before-ref 'HEAD^1' --after-ref HEAD --rule-file prometheus/payment.rules.yml \
  --fixture-ref 'HEAD^1' --timeline-policy tests/fixtures/payment-timing.json \
  --json-report review-policy.json
```

위 PR 워크플로의 비교 단계에도 같은 경로를 지정할 수 있습니다.

```yaml
- name: Compare alert rules and timing policy
  id: compare
  uses: cynkai/incident-to-promtool@main
  with:
    fixtures: |
      tests/fixtures/payment-timeout.test.yml
      tests/fixtures/payment-peak.test.yml
    fixture-ref: 'HEAD^1'
    rule-files: |
      prometheus/payment.rules.yml
    timeline-policy: tests/fixtures/payment-timing.json
```

JSON의 `timeline_policy`에는 정책 경로 `path`, 읽은 파일 바이트의 `sha256`, 커밋에서 읽었을 때의 `commit`, 정책 전체 판정 `passed`, 검사별 타임라인 `checks`가 들어갑니다. 각 검사 결과는 단일 `timeline`과 같은 구조를 사용합니다. `timeline-passed`는 모든 정책 검사의 통과 여부입니다. JUnit의 `Alert firing delay` 스위트에는 정책 검사마다 테스트 케이스 하나가 들어갑니다. 단계가 성공하려면 체크포인트 검사와 정책 검사가 모두 통과해야 합니다.

#### 기준 번들로 PR 검사

기준 커밋에 장애 번들 ZIP이 있으면 각 ZIP의 테스트와 기준 룰을 적용할 수 있습니다. 위 워크플로의 `fetch-depth: 0` 체크아웃을 유지하고 비교 단계를 다음과 같이 설정합니다. 아래 예제는 결제 번들에 최초 발화 지연 검사도 적용합니다.

```yaml
- name: Compare alert rules from bundles
  id: compare
  uses: cynkai/incident-to-promtool@main
  with:
    bundles: |
      tests/fixtures/payment-baseline.zip
      tests/fixtures/checkout-baseline.zip
    rule-files: |
      prometheus/payment.rules.yml
      prometheus/checkout.rules.yml
    timeline-alertname: PaymentErrorsHigh
    timeline-end: '10m'
    timeline-max-delay: '0s'
    timeline-bundle: tests/fixtures/payment-baseline.zip
```

ZIP 하나를 비교할 때는 `bundle`, 여러 개면 `bundles`에 한 줄에 하나씩 경로를 적습니다. 비교에는 `bundle`, `bundles`, `fixture`, `fixtures` 중 하나를 선택합니다. 번들 비교에서는 ZIP을 `before-ref`(기본 `HEAD^1`)에서 읽고, `rule-files`에 지정한 공통 수정 룰을 `after-ref`(기본 `HEAD`)에서 읽습니다. 두 경로는 저장소 루트 기준이며, 룰 파일은 수정 커밋에 있으면 됩니다. [장애 재현 번들](#장애-재현-번들)

현재 PR의 기준 룰을 사용하려면 `bundle` 또는 `bundles`와 함께 `before-rule-files`와 `after-rule-files`를 모두 지정합니다. ZIP과 기준 룰은 `before-ref`, 수정 룰은 `after-ref`에서 읽습니다. 두 룰 목록은 저장소 루트 기준으로 한 줄에 하나씩 적습니다. 두 목록을 제공하는 방식과 ZIP에 담긴 기준 룰을 쓰는 `rule-files` 방식 중 하나를 선택합니다.

```yaml
with:
  bundle: tests/fixtures/payment-baseline.zip
  before-rule-files: |
    prometheus/payment.rules.yml
  after-rule-files: |
    prometheus/payment/alerts.yml
    prometheus/payment/recording.yml
  gate: regressions
```

## Kubernetes PrometheusRule로 테스트

Kubernetes 모드에는 PyYAML이 필요합니다. 아래 명령은 Python 가상 환경에서 실행할 수 있습니다. Helm 차트는 먼저 `helm template`으로 렌더링합니다.

```sh
python3 -m pip install 'PyYAML>=6,<7'
mkdir -p demo/generated
python3 incident_to_promtool.py export-rules demo/kubernetes/after.yml \
  --output-dir demo/generated/native
python3 incident_to_promtool.py demo/demo.json --matrix demo/incident.matrix.json \
  --rule-file demo/generated/native/rules-1.yml --output demo/generated/kubernetes.test.yml
python3 incident_to_promtool.py compare demo/generated/kubernetes.test.yml \
  --rule-format kubernetes --before demo/kubernetes/before.yml \
  --after demo/kubernetes/after.yml > demo/generated/kubernetes-review.md
```

`export-rules`의 출력 디렉터리는 새 경로여야 하며 상위 디렉터리는 미리 만듭니다. 입력에 등장하는 순서대로 리소스 하나당 `rules-1.yml`, `rules-2.yml` 형식의 `promtool` 룰 파일이 생성됩니다. 의존하는 기록 룰이 있으면 해당 매니페스트도 입력으로 제공하고, 테스트를 생성할 때 필요한 출력 파일을 `--rule-file`로 하나씩 지정하세요.

렌더링된 다중 문서 YAML, Kubernetes `v1/List`, `monitoring.coreos.com/v1`의 `PrometheusRuleList`를 읽을 수 있습니다. 같은 입력에 들어 있는 다른 종류의 리소스는 건너뜁니다. Git 커밋 간 비교에도 `--rule-format kubernetes`를 추가하고 `--rule-file`에 매니페스트 경로를 지정합니다.

평가는 매니페스트에 선언된 Prometheus 룰을 기준으로 합니다. Operator가 Prometheus에서 무시하는 Thanos Ruler 전용 `partial_response_strategy`는 내보낼 때 제외합니다. Operator admission 단계의 변경과 `enforcedNamespaceLabel` 적용은 범위 밖입니다. [Prometheus Operator API 문서](https://prometheus-operator.dev/docs/api-reference/api/)

## 내 Prometheus로 실행

`demo/demo.json`을 복사해 장애 시간과 메트릭, 룰 파일, 기대 동작을 바꿉니다. 아래는 설정을 저장소 루트의 `incident.json`에 저장한 경우입니다.

```sh
python3 incident_to_promtool.py incident.json \
  --prometheus-url http://localhost:9090 --output incident.test.yml
promtool test rules incident.test.yml
```

저장된 API 응답이 있을 때는 `--matrix`로 로컬에서 변환할 수 있습니다. Prometheus의 `/api/v1/query`에 범위 선택자를 보냈을 때 반환되는 원본 `matrix` 응답을 사용합니다. 인증이 필요한 서버에 연결할 때는 토큰 파일이나 환경 변수를 지정할 수 있습니다. [Prometheus 인증](#prometheus-인증)

Prometheus의 요청당 조회 한도에 걸리는 긴 캡처는 여러 요청으로 나눌 수 있습니다. [긴 캡처 구간 나눠 조회하기](#긴-캡처-구간-나눠-조회하기)

- `start`와 `end`는 시간대가 포함된 캡처 구간입니다. `start`를 테스트의 시각 기준으로 고정합니다. `start`는 장애보다 앞에 두고, 룰의 `rate(...[5m])` 같은 조회 범위와 `for` 상태를 평가할 수 있게 충분한 사전 구간을 포함하세요.
- `selectors`에는 룰 평가에 필요한 원본 시계열 선택자를 넣습니다. `sample_interval`은 시계열 격자 간격, `evaluation_interval`은 테스트의 단일 평가 간격입니다. 발화 시점을 대조하려면 평가 간격을 운영과 맞추고 `start`도 운영 룰 그룹의 평가 시점에 맞추세요. 평가 시점이 다른 그룹은 테스트를 따로 생성하세요.
- `expectations[].at`는 `start`부터 센 시간이며 평가 간격에 맞춰야 합니다. `alerts: []`이면 해당 시점에 발화가 없어야 합니다. 발화를 기대할 때는 해당 알람의 모든 최종 라벨과 펼쳐진 주석을 지정합니다. `alertname`은 별도 필드에 둡니다.
- `rule_files`는 설정 파일이 있는 디렉터리를 기준으로 적습니다. `--rule-file`로 바꿀 때는 현재 작업 디렉터리가 기준입니다. 출력 파일에는 출력 디렉터리 기준 상대 경로가 기록됩니다.

`"sample_interval": "auto"`는 `evaluation_interval`과 캡처 구간에 있는 모든 표본의 `start` 기준 시간 차이를 나누어떨어지게 하는 가장 큰 간격을 밀리초 단위로 계산합니다. 빈 슬롯까지 펼쳐 모든 시계열의 합이 200만 칸 이내라면 이 간격을 사용해 표본 시각을 그대로 보존합니다. `--round-up`만 함께 지정해도 같은 방식으로 계산합니다.

`auto` 전용 옵션인 `--max-shift`에 양수를 지정하면, 정확한 간격으로 200만 칸을 넘길 때 아래 조건을 만족하는 더 큰 간격 중 가장 촘촘한 간격을 선택합니다.

- 평가 간격이 선택한 간격의 배수이며, 전체 슬롯은 200만 칸 이내입니다.
- 표본을 앞으로 미루는 시간은 허용치 이내입니다. 모든 표본은 캡처 구간 안에 남고 같은 시계열의 서로 다른 표본은 각기 다른 칸에 들어갑니다.

`incident.json`에서 `"sample_interval": "auto"`를 설정한 뒤 실행합니다.

```sh
python3 incident_to_promtool.py incident.json --prometheus-url http://localhost:9090 \
  --max-shift 2ms --output incident.auto.test.yml
```

선택한 간격과 실제 최대 이동 시간이 출력되며 간격은 테스트 파일에도 기록됩니다. 표본 이동은 알람 판정 시각에 영향을 줄 수 있습니다. 조건에 맞는 간격이 없으면 캡처 구간을 줄이거나 `selectors`를 좁히세요.

`"30s"`처럼 간격을 직접 지정하면 평가 간격은 그 배수여야 하며, 기본 변환은 표본 시각이 격자에 맞아야 합니다. 명시적으로 `--round-up`을 쓰면 표본을 다음 격자로 미루고 최대 이동 시간을 표시합니다. 이때 `end`도 격자에 맞춰야 하고, 같은 시계열의 두 타임스탬프가 한 칸에 들어가면 더 촘촘한 간격이 필요합니다.

입력은 유한한 스칼라 표본입니다. Prometheus 원본 조회 API는 stale 표식을 제외하므로, `absent()`처럼 시계열이 stale 상태가 된 시각에 의존하는 룰은 이 방식으로 정확히 재현하기 어렵습니다.

### 긴 캡처 구간 나눠 조회하기

라이브 테스트 생성 명령과 `snapshot`, `inspect`, `bundle`은 기본적으로 선택자마다 전체 캡처 구간을 한 번에 조회합니다. `--chunk-window DURATION`을 지정하면 각 Prometheus 요청의 조회 범위가 지정한 길이 이내가 되도록 캡처를 나눕니다. 양수 기간과 `--prometheus-url`이 필요하며, 인증과 TLS 옵션도 함께 쓸 수 있습니다. [Prometheus 인증](#prometheus-인증)

같은 라이브 명령에 `--split-on-limit`을 지정하면 Prometheus 표본 수 한도 초과 오류(HTTP 422, `errorType: execution`)가 발생한 범위만 밀리초 단위로 이등분해 시간순으로 다시 조회합니다. `--chunk-window`를 함께 지정하면 처음부터 그 길이가 요청당 상한이며, `--split-on-limit`만 지정하면 전체 구간부터 요청합니다. 1ms 구간에서도 표본 수 한도를 넘거나 다른 HTTP 오류나 데이터 오류가 발생하면 캡처를 중단합니다.

```sh
python3 incident_to_promtool.py snapshot incident.json \
  --prometheus-url http://localhost:9090 --chunk-window 15m --split-on-limit \
  --output incident.matrix.json
```

첫 요청의 조회 범위는 `start`보다 1ms 앞에서 시작해 `start` 시각의 표본을 포함합니다. 이후 각 요청은 바로 이전 구간의 끝 다음부터 현재 구간의 끝까지 조회합니다. 모든 요청이 성공해야 결과를 만들며, 실패하면 출력 파일을 생성하지 않습니다. 합친 표본의 원본 시각은 스냅샷과 ZIP 안의 `matrix` 응답에 보존됩니다. 표준 형식으로 저장한 스냅샷, 테스트, 번들은 오프라인에서도 쓸 수 있습니다.

### Prometheus 인증

`--bearer-token-file PATH`는 Prometheus에 연결하는 테스트 생성 명령과 `bundle`, `snapshot`, `inspect`, `plan-capture`에서 사용할 수 있습니다. `--prometheus-url`을 함께 지정합니다. `--matrix`는 저장된 응답을 읽는 오프라인 모드라 인증 정보를 생략합니다.

파일에는 RFC 6750 형식의 Bearer 토큰 하나를 넣습니다. 끝에 줄바꿈(LF 또는 CRLF) 하나를 둘 수 있습니다. 명령 실행당 한 번 읽으며, 마운트된 Kubernetes Secret의 심볼릭 링크 경로도 사용할 수 있습니다. 파일 옵션을 지정하면 파일이 우선합니다. 파일 옵션을 생략하면 `PROMETHEUS_BEARER_TOKEN` 환경 변수의 토큰을 사용합니다.

사설 CA나 자체 서명 인증서를 쓰는 Prometheus에는 같은 명령에서 `--ca-file PATH`로 PEM CA 파일을 지정할 수 있습니다. `--prometheus-url`에는 HTTPS 주소를 쓰고, Bearer 인증이 필요하면 `--bearer-token-file`도 함께 지정합니다. 지정한 CA는 시스템 기본 신뢰 목록에 추가되고, 서버 이름과 인증서 유효 기간도 계속 검증합니다.

```sh
python3 incident_to_promtool.py snapshot incident.json \
  --prometheus-url https://prometheus.example.com \
  --ca-file /etc/prometheus/tls/ca.crt \
  --bearer-token-file /var/run/secrets/prometheus/token \
  --output incident.matrix.json
```

`--ca-file`을 쓰면 HTTPS 리디렉션 대상의 인증서도 검증하며, HTTP로 향하는 리디렉션은 오류로 처리합니다. `urllib`은 원래 요청에만 인증 헤더를 붙이므로 `--prometheus-url`에는 최종 Prometheus HTTPS 기본 URL을 지정하세요.

#### 클라이언트 인증서로 연결 (mTLS)

클라이언트 인증을 요구하는 Prometheus에는 HTTPS `--prometheus-url`과 함께 `--client-cert-file PATH` 및 `--client-key-file PATH`를 지정합니다. 두 옵션은 함께 사용해야 합니다. 앞의 다섯 라이브 명령에서 지원하며, 파일에는 각각 PEM 인증서 체인과 암호화되지 않은 PEM 개인 키를 넣습니다. 서버 인증서와 호스트 이름도 검증합니다. 필요에 따라 `--ca-file`이나 `--bearer-token-file`을 추가할 수 있습니다.

아래는 클라이언트 인증서와 키를 읽기 전용 Kubernetes Secret으로 마운트한 예입니다.

```sh
python3 incident_to_promtool.py snapshot incident.json \
  --prometheus-url https://prometheus.example.com \
  --ca-file /etc/prometheus/tls/ca.crt \
  --client-cert-file /var/run/secrets/prometheus-client/tls.crt \
  --client-key-file /var/run/secrets/prometheus-client/tls.key \
  --output incident.matrix.json
```

mTLS를 쓰면 리디렉션은 원래 URL과 HTTPS 스킴, 호스트, 포트가 같을 때만 따릅니다. Bearer 토큰도 사용하는 경우 `--prometheus-url`에 최종 HTTPS 기본 URL을 지정하세요.

### 캡처할 시계열 계획

`plan-capture`는 알람 룰에 필요한 원본 시계열 선택자를 찾아줍니다. 저장소 루트의 Python 가상 환경에서 실행합니다.

```sh
python3 -m pip install '.[planner]'
python3 incident_to_promtool.py plan-capture demo/after.rules.yml \
  --alertname PaymentErrorsHigh --prometheus-url http://localhost:9090
```

Prometheus 룰 YAML은 위치 인자로 여러 개 지정할 수 있습니다. Prometheus와 같이 각 파일의 첫 문서를 읽습니다. 알람이 여러 개면 `--alertname`을 반복합니다. Kubernetes `PrometheusRule`은 [`export-rules`](#kubernetes-prometheusrule로-테스트)로 변환한 YAML을 입력으로 사용합니다.

이 명령은 PromQL 식을 Prometheus 3.x의 실험적 `/api/v1/parse_query`에 보내 구문을 분석합니다. Prometheus 3.9와 3.11에서 확인했습니다. 시계열 표본 조회는 이후 캡처 단계에서 실행합니다. [Prometheus 구문 분석 API](https://prometheus.io/docs/prometheus/latest/querying/api/#parsing-a-promql-expressions-into-a-abstract-syntax-tree-ast) · [Prometheus 인증](#prometheus-인증)

출력은 `schema_version`이 `1`인 JSON으로, 요청한 `alertnames`, 따라간 `recording_rules`, 캡처할 `selectors`를 담습니다. `selectors` 배열을 장애 설정에 복사하세요. 상수식처럼 원본 시계열이 필요 없는 룰의 `selectors`는 빈 배열입니다. 룰 변경 전후에 참조하는 시계열이 달라지면 두 버전에서 얻은 선택자를 합쳐서 캡처하세요.

기록 룰을 참조하면 입력 파일에서 같은 이름의 메트릭을 생성하는 룰을 모두 따라갑니다. 예를 들어 `foo{service="pay"}`가 `bar{job="api"}`를 읽는 기록 룰 `foo`를 참조하면 `bar{job="api"}`를 제안합니다. 입력에서 빠진 기록 룰의 출력은 캡처 대상 메트릭으로 남습니다.

메트릭 이름이 없거나 하나로 확정되지 않는 선택자, `info()`, 순환 의존성, 내부 알람 상태 시계열은 오류로 처리합니다. 캡처의 `start`와 `end`는 범위 벡터와 하위 쿼리에 필요한 사전 구간, `offset`, `@`, 그룹의 `query_offset`, 알람의 `for`를 고려해 직접 정하세요.

### 원본 시계열 스냅샷

`snapshot`으로 장애 구간의 시계열을 저장해 두면, 이후 Prometheus 서버 연결 없이 테스트를 생성할 수 있습니다.

```sh
python3 incident_to_promtool.py snapshot incident.json \
  --prometheus-url http://localhost:9090 --output incident.matrix.json
python3 incident_to_promtool.py incident.json \
  --matrix incident.matrix.json --output incident.offline.test.yml
```

스냅샷 설정에는 시간대가 포함된 `start`와 `end`가 필요합니다. 서버에서 가져올 때는 `selectors`도 지정합니다. `sample_interval`, `evaluation_interval`, `rule_files`, `expectations`는 두 번째 명령에서 테스트를 생성할 때 채웁니다. 같은 구간을 재현할 수 있도록 `incident.json`도 스냅샷과 함께 보관합니다.

저장 파일은 Prometheus `matrix` 응답 형식이며, 지정 구간의 표본 시각을 밀리초 정밀도로 보존하고 라벨과 값을 그대로 담습니다. 저장된 응답을 합치려면 `snapshot`에 `--matrix part-a.matrix.json --matrix part-b.matrix.json`과 같이 입력을 반복 지정합니다. 같은 시계열에서 시각과 값이 일치하는 표본은 하나로 합칩니다. 구간 안에 표본이 없거나 같은 시각의 값이 충돌하거나, 응답에 경고 또는 네이티브 히스토그램이 있으면 오류로 처리합니다.

### 장애 재현 번들

`bundle`은 한 번 캡처한 시계열로 스냅샷과 테스트를 만들고, 오프라인에서 다시 실행할 파일을 ZIP 하나에 담습니다. `--output`에는 새 ZIP 경로를 지정합니다.

```sh
mkdir -p demo/generated
python3 incident_to_promtool.py bundle demo/alertmanager.incident.json \
  --matrix demo/incident.matrix.json --output demo/generated/payment.zip
unzip -q demo/generated/payment.zip -d demo/generated/payment
(cd demo/generated/payment && promtool test rules incident.test.yml)
```

시계열은 `--matrix`를 반복해 지정하거나 `--prometheus-url`로 가져옵니다. `--rule-file`을 반복해 설정의 룰 파일을 바꿀 수 있습니다. `--round-up`과 `--max-shift`는 테스트를 생성할 때와 같은 의미입니다.

| 파일 | 내용 |
| --- | --- |
| `incident.json` | 룰을 번들 내부의 상대 경로로 지정하고 기대 동작을 `alerts`에 담은 오프라인 설정 |
| `incident.matrix.json` | 시각을 그대로 보존한 원본 시계열 스냅샷 |
| `incident.test.yml` | `promtool`에서 바로 실행할 테스트 |
| `capture.json` | 상대 테스트 경로, SHA-256, `generation_options` 배열을 담은 캡처 요약 |
| `coverage.json` | 캡처 구간의 표본과 간격에 대한 관측 결과 |
| `rules/rules-N.yml` | 사용한 룰 파일의 원본 바이트 |
| `manifest.json` | 번들 데이터 파일 전체의 SHA-256을 기록한 버전 1 매니페스트 |

Alertmanager 웹훅을 사용했다면 기대 동작에 쓰는 라벨과 주석만 오프라인 설정에 남습니다. Prometheus 조회 주소, 인증 토큰, 실시간 조회 선택자는 캡처 단계에서만 사용합니다.

압축을 푼 디렉터리에서 같은 버전의 CLI로 `incident.json`과 `incident.matrix.json`을 읽으면 테스트를 바이트 단위로 다시 생성할 수 있습니다. 출력은 같은 디렉터리 안에 새 파일로 지정하고, 생성에 사용한 옵션은 `capture.json`의 `generation_options`에 기록된 그대로 전달합니다.

#### 번들 전체 검증

새 번들의 `manifest.json`은 `schema_version`이 `1`이며, `files`는 번들 데이터 파일 경로를 각각의 SHA-256에 대응시킵니다. `capture.json`의 `bundle_manifest_version`은 해당 ZIP에 `manifest.json`이 필요하다는 표시입니다.

위 예제로 만든 ZIP을 Python CLI만으로 바로 검사할 수 있습니다. 기본 출력은 Markdown입니다. `--format json`의 `schema_version`은 `1`이며, `bundle_path`와 `verified_files`에 ZIP 경로와 검증한 파일 목록을 기록합니다.

```sh
python3 incident_to_promtool.py verify-bundle demo/generated/payment.zip --format json
```

전체 검증에는 `manifest.json`이 필요합니다. 종료 코드는 검증을 통과하면 `0`, 형식이 잘못됐거나 파일과 해시가 일치하지 않으면 `2`입니다. 이 검사는 ZIP 내부 파일과 동봉된 해시의 일치 여부를 확인합니다. 작성자와 배포 출처를 확인하려면 신뢰할 수 있는 서명이나 별도의 출처 기록이 필요합니다.

#### 번들에서 룰 변경 비교

`compare-bundle`은 ZIP에서 테스트를 바로 읽습니다. 기본 비교에는 ZIP에 담긴 기준 Prometheus 룰을 사용합니다. 번들 내부 `capture.json`에 기록된 테스트의 SHA-256을 확인하고, 같은 테스트로 기준 룰과 수정 룰을 비교합니다. 매니페스트가 있는 번들에서는 `incident.test.yml`과 `capture.json`을 매니페스트와 대조합니다. ZIP에 담긴 기준 룰을 사용하면 해당 룰도 대조합니다. 기존 ZIP도 `capture.json`의 테스트 해시로 검증해 비교할 수 있습니다. [번들 전체 검증](#번들-전체-검증)

```sh
mkdir -p demo/generated
python3 incident_to_promtool.py bundle demo/alertmanager.incident.json \
  --matrix demo/incident.matrix.json --rule-file demo/before.rules.yml \
  --output demo/generated/payment-baseline.zip
python3 incident_to_promtool.py compare-bundle demo/generated/payment-baseline.zip \
  --after demo/after.rules.yml --json-report demo/generated/payment-comparison.json
```

결제 예제에서 기준 룰은 검사 2개 중 1개를 충족하고, 수정 룰은 2개 모두 충족합니다. 수정 룰 파일이 여러 개면 `--after`를 반복합니다. 수정 룰이 Kubernetes `PrometheusRule`이면 `--rule-format kubernetes`를 추가합니다. ZIP의 기준 룰은 Prometheus 룰 형식으로 읽습니다.

파일 비교와 Git 비교 모두 ZIP 경로를 위치 인자로 여러 개 지정할 수 있습니다. 각 ZIP의 테스트를 입력 순서대로 실행합니다. 기본 비교에서는 ZIP마다 자기 기준 룰을 사용하고, 모든 ZIP에 동일한 수정 룰을 적용합니다. 같은 ZIP 경로를 반복하거나 배치에 잘못된 입력이 있으면 종료 코드 `2`로 처리합니다. 리포트는 비교를 완료한 배치에 대해 생성됩니다.

전체 집계와 번들별 결과를 Markdown으로 표준 출력에 보냅니다. JSON은 `--json-report`, JUnit XML은 `--junit-report`로 저장합니다. 게이트는 `compare`와 같은 `strict`와 `regressions`를 지원합니다. 종료 코드는 게이트 통과 `0`, 게이트 실패 `1`, 입력 또는 실행 오류 `2`입니다. [룰 변경 전후 비교](#룰-변경-전후-비교) · [JUnit XML 리포트](#junit-xml-리포트)

JSON에는 ZIP 하나를 비교할 때 기존 `bundle` 객체를, 여러 개면 `bundles` 배열을 기록합니다. `bundles`와 `fixtures`는 입력 순서대로 대응합니다. 각 번들 항목에는 ZIP 경로 `path`와 ZIP 내부의 기준 룰 경로 목록 `rule_files`가 있습니다. `fixtures` 항목의 `path`와 `capture_summary`는 각각 `ZIP!incident.test.yml`, `ZIP!capture.json` 형식입니다.

ZIP에 담긴 기준 룰로 Git 비교를 하려면 `--bundle-ref`, `--after-ref`, `--rule-file`을 함께 지정합니다. ZIP과 룰 경로는 저장소 루트 기준입니다. 수정 룰이 여러 개면 `--rule-file`을 반복하고, 다른 저장소에서 읽으려면 `--repo DIR`을 지정합니다.

```sh
python3 incident_to_promtool.py compare-bundle \
  tests/fixtures/payment-baseline.zip tests/fixtures/checkout-baseline.zip \
  --bundle-ref 'HEAD^1' --after-ref HEAD \
  --rule-file prometheus/payment.rules.yml --rule-file prometheus/checkout.rules.yml \
  --json-report review.json
```

이때 JSON의 `commits.before`는 ZIP을 읽은 커밋, `commits.after`는 수정 룰을 읽은 커밋입니다.

##### 현재 기준 룰로 비교

번들을 만들 때 실패했던 검사를 이후 수정했고, 새 변경이 그 문제를 재현한다고 가정합니다. 캡처 당시 룰을 기준으로 삼으면 `regressions` 게이트는 이를 기존 실패로 집계합니다. 현재 PR의 기준 룰을 적용하면 새로 실패한 검사로 잡을 수 있습니다.

로컬 파일로 비교할 때는 `--before`와 `--after`에 각 룰을 지정합니다. 둘 다 반복할 수 있습니다. 결제 예제에서 문제를 고친 룰을 현재 기준으로 사용하면, 예전 룰을 다시 적용하는 변경이 회귀로 판정됩니다.

```sh
python3 incident_to_promtool.py compare-bundle demo/generated/payment-baseline.zip \
  --before demo/after.rules.yml --after demo/before.rules.yml --gate regressions
```

Git 비교에서는 `--bundle-ref`와 `--after-ref`를 지정하고, `--before-rule-file`과 `--after-rule-file`로 양쪽 룰 경로를 제공합니다. 두 룰 옵션은 반복할 수 있습니다. ZIP과 기준 룰은 `--bundle-ref`에서 읽고, 수정 룰은 `--after-ref`에서 읽습니다. 각 경로는 저장소 루트 기준입니다. 양쪽 경로를 제공하는 방식과 ZIP에 담긴 기준 룰을 쓰는 `--rule-file` 방식 중 하나를 선택합니다.

```sh
python3 incident_to_promtool.py compare-bundle tests/fixtures/payment-baseline.zip \
  --bundle-ref 'HEAD^1' --after-ref HEAD \
  --before-rule-file prometheus/payment.rules.yml \
  --after-rule-file prometheus/payment/alerts.yml \
  --after-rule-file prometheus/payment/recording.yml --gate regressions
```

외부 룰 목록은 모든 ZIP에 공통으로 적용합니다. `--rule-format kubernetes`는 외부 기준 룰과 수정 룰 모두에 적용합니다. JSON 최상위 `rule_files.before`와 `rule_files.after`에는 실제 비교에 사용한 외부 룰 경로가 기록됩니다. `bundle.rule_files`와 `bundles`의 각 `rule_files`는 ZIP에 담긴 룰 멤버 경로입니다.

##### 번들의 최초 발화 지연 검사

`compare-bundle`에서 `--timeline-alertname`, `--timeline-end`와 함께 `--timeline-max-delay` 또는 `--timeline-fire-by`를 지정하면, 체크포인트 검사를 위해 읽고 검증한 테스트와 룰로 최초 발화도 검사합니다. ZIP에 보관한 기준 룰과 외부 기준 룰 모두 사용할 수 있습니다.

```sh
python3 incident_to_promtool.py compare-bundle demo/generated/payment-baseline.zip \
  --after demo/after.rules.yml --timeline-alertname PaymentErrorsHigh \
  --timeline-end 10m --timeline-max-delay 0s --timeline-fire-by 7m \
  --json-report demo/generated/payment-timing.json
```

여러 ZIP을 비교할 때는 `--timeline-bundle`에 입력 목록의 ZIP 경로 하나를 그대로 적습니다. ZIP 하나를 비교할 때는 그 파일을 기본으로 선택합니다.

JSON의 `timeline`에는 선택한 `bundle`, 기준 룰의 출처 `baseline_source`(`bundle` 또는 `rules`), 실제 비교한 `rule_files.before`와 `rule_files.after`를 기록합니다. ZIP의 기준 룰을 사용하면 `before` 목록은 번들 내부의 룰 멤버 경로입니다. Git 비교에서는 `timeline.fixture_commit`에 ZIP에서 테스트를 읽은 커밋을 기록합니다. [PR에서 최초 발화 지연 검사](#pr에서-최초-발화-지연-검사)

### 시계열 표본 간격 확인

`inspect`는 캡처 구간에서 관측된 시계열별로 표본 수, 첫 표본과 마지막 표본의 UTC 시각, 구간 양끝의 공백, 연속된 두 표본 사이의 최장 간격을 보고합니다. 간격은 실제 표본 시각으로 계산합니다. 기본 출력은 Markdown이고, `--format json`은 간격의 시작과 끝도 기록합니다.

```sh
python3 incident_to_promtool.py inspect demo/demo.json \
  --matrix demo/incident.matrix.json --max-gap 30s
```

저장 응답은 `--matrix`를 반복해 지정할 수 있습니다. 서버에서 조회할 때는 시간대가 있는 `start`와 `end`, `selectors`를 설정하고 `--prometheus-url`을 사용합니다.

`--max-gap`을 지정하면 첫 표본 전, 표본 사이, 마지막 표본 후의 공백 중 하나라도 제한을 초과할 때 실패합니다. 구간에 표본이 하나도 없을 때도 이 검사는 실패합니다. 옵션을 생략하면 빈 구간을 포함한 관측 결과를 그대로 보고합니다. 종료 코드는 검사 통과 또는 제한 없이 보고할 때 `0`, 간격 검사 실패 `1`, 잘못된 입력 `2`입니다.

### Alertmanager 웹훅으로 기대 동작 만들기

저장해 둔 Alertmanager v4 일반 웹훅 JSON에서 발화 알람의 라벨과 주석을 읽어 기대 동작을 만들 수 있습니다. `expectations`의 해당 항목에 `alertmanager_webhook`을 지정합니다. 상대 경로는 설정 파일 기준입니다. 같은 설정을 로컬 `--matrix`와 `--prometheus-url` 캡처에 모두 사용할 수 있습니다. [Alertmanager 웹훅 문서](https://prometheus.io/docs/alerting/latest/configuration/#webhook_config)

```json
{
  "at": "7m",
  "alertname": "PaymentErrorsHigh",
  "alertmanager_webhook": "alertmanager.webhook.json",
  "drop_labels": ["cluster"]
}
```

- `at`는 `startsAt`, `endsAt`과 별도로 지정합니다. 캡처 시작부터의 시간이며 캡처 구간 안의 평가 시점이어야 합니다.
- 상태가 `firing`이고 `alertname`이 일치하는 항목의 라벨과 주석을 기대 동작에 사용합니다. `alertname` 라벨은 항상 제거합니다. `drop_labels`는 웹훅에서만 붙은 외부 라벨이나 라우팅용 라벨을 제외하는 선택 항목입니다.
- 라벨을 제외한 뒤 라벨과 주석이 같은 알람은 하나로 합칩니다. 라벨이 같고 주석이 다르면 오류로 처리합니다.
- `resolved` 항목은 건너뜁니다. 일치하는 발화 알람이 없거나 `truncatedAlerts`가 0보다 큰 웹훅은 오류로 처리합니다. 조용해야 하는 시점은 `alerts: []`로 지정하세요.

라우팅, 사일런스, 억제 설정은 웹훅에 포함된 알람 집합에 영향을 줍니다. 선택한 평가 시점에 해당 알람에서 기대하는 발화 인스턴스 전체를 담은 웹훅을 사용하세요.

결제 예제는 조용한 시점을 수동으로 지정하고, 장애 시작 5분 시점의 발화 기대값은 합성 웹훅에서 읽습니다.

```sh
mkdir -p demo/generated
python3 incident_to_promtool.py demo/alertmanager.incident.json \
  --matrix demo/incident.matrix.json --output demo/generated/alertmanager.test.yml \
  --summary-format json > demo/generated/alertmanager.capture.json
python3 incident_to_promtool.py compare demo/generated/alertmanager.test.yml \
  --before demo/before.rules.yml --after demo/after.rules.yml \
  --capture-summary demo/generated/alertmanager.capture.json
```

### 캡처 요약 JSON

`--summary-format json`을 지정하면 기본 텍스트 요약 대신 JSON을 표준 출력으로 보냅니다. `--output`은 생성할 테스트 파일 경로입니다.

```sh
python3 incident_to_promtool.py incident.json --prometheus-url http://localhost:9090 \
  --output incident.capture.test.yml --summary-format json > capture.json
```

- `schema_version`은 `1`입니다. `fixture_path`와 `fixture_sha256`은 출력 파일의 경로와 SHA-256 해시입니다. `start`와 `end`는 UTC입니다.
- `evaluation_interval_ms`, `sample_interval_ms`, `max_shift_ms`, `max_shift_limit_ms`는 평가 간격, 선택한 표본 간격, 실제 최대 이동, 이동 허용치를 밀리초로 기록합니다. 허용치는 `--max-shift`에 지정한 값, 수치 간격에 `--round-up`을 쓴 경우에는 간격에서 1ms를 뺀 값, 그 외에는 `null`입니다. `sampling_mode`는 `fixed_exact`, `fixed_round_up`, `auto_exact`, `auto_bounded` 중 하나입니다.
- `series_count`, `sample_count`, `shifted_sample_count`, `checkpoint_count`, `expanded_slots`는 시계열, 표본, 이동한 표본, 기대 동작 검사, 빈 칸을 펼친 전체 슬롯 수입니다. 선택자가 겹쳐 같은 표본을 여러 번 받아도 `sample_count`에는 한 번만 셉니다.

## 실제 변경에 적용하기

최근에 고친 알람 하나로 시작하세요. 기존 룰에서는 기대 동작 검사가 실패하고 수정한 룰에서는 통과하는지 확인한 뒤, 생성된 테스트를 룰 변경 PR에 넣어보세요. CI에서는 `promtool test rules incident.test.yml`을 실행하면 됩니다. 테스트와 번들에는 캡처한 메트릭 값과 라벨, 알람 주석이 들어 있으므로 커밋 전에 저장소 접근 범위에 맞는 데이터인지 확인하세요. [Prometheus 룰 테스트 문서](https://prometheus.io/docs/prometheus/latest/configuration/unit_testing_rules/)
