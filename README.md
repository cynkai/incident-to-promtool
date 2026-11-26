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

Use Python 3.10+ and `promtool` 3.9+. With no local `promtool`, the demo downloads and verifies a pinned binary on Linux x64. Set `PROMTOOL=/path/to/promtool` to use a specific executable.

Commit a fixture for your own incident, compare rule changes between Git refs, and add the same check to CI. Detailed examples are available in Korean. [Capture an incident](#내-prometheus로-실행) · [Native Prometheus rules](#룰-변경-전후-비교) · [Git ref comparison](#git-커밋으로-비교) · [Kubernetes PrometheusRule](#kubernetes-prometheusrule로-테스트) · [GitHub Action](#github-actions에서-pr-검사)

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

### Git 커밋으로 비교

두 Git ref를 지정하면 현재 체크아웃을 유지한 채 각 커밋에서 룰을 읽습니다. Markdown 리포트에는 확정된 두 커밋 ID가 들어가며 종료 코드는 파일 경로로 비교할 때와 같습니다.

```sh
python3 incident_to_promtool.py compare \
  tests/fixtures/payment.test.yml tests/fixtures/checkout.test.yml \
  --before-ref "$BASE_SHA" --after-ref "$HEAD_SHA" \
  --rule-file prometheus/payment.rules.yml \
  --rule-file prometheus/checkout.rules.yml > review.md
```

`--repo`를 생략하면 현재 디렉터리의 Git 저장소를 사용합니다. `--rule-file`에는 두 커밋에 모두 있는 일반 파일의 경로를 저장소 루트 기준으로 지정합니다. 경로 구분자는 `/`입니다. 의존 룰 파일은 `--rule-file`을 반복해서 추가하세요. 룰 파일이 이동해 경로가 달라졌다면 위의 `--before`와 `--after`로 각 파일 경로를 지정하세요. `--promtool`로 실행 파일을 지정할 수 있습니다.

PR의 기준 커밋에 있는 기대 동작으로 비교하려면 `--fixture-ref 'HEAD^1'`을 추가할 수 있습니다. 이 경우 작업 트리에서 파일을 수정했거나 그 경로에 파일이 없어도 지정한 커밋에서 테스트 파일과 선택한 캡처 요약을 읽습니다. 두 파일의 경로는 모두 저장소 루트 기준입니다.

```sh
python3 incident_to_promtool.py compare tests/fixtures/payment.test.yml \
  --before-ref 'HEAD^1' --after-ref HEAD --rule-file prometheus/payment.rules.yml \
  --fixture-ref 'HEAD^1' --capture-summary tests/fixtures/payment.capture.json
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

테스트 파일을 하나 검사하면 `fixture`, 여러 개 검사하면 `fixtures`를 사용합니다. 두 입력 중 하나를 선택하고 `rule-files`를 함께 지정하세요. 테스트 파일은 `repo-path` 기준 경로이며 `fixtures`에서는 한 줄에 하나씩 적습니다. `rule-files`에는 두 커밋에 모두 있는 룰 경로를 저장소 루트 기준으로 한 줄에 하나씩 적습니다.

| 선택 입력 | 기본값과 용도 |
| --- | --- |
| `repo-path` | `.`. 체크아웃한 Git 저장소 경로 |
| `rule-format` | `prometheus`. 렌더링된 `PrometheusRule`은 `kubernetes` |
| `before-ref`, `after-ref` | `HEAD^1`, `HEAD`. 다른 Git ref를 쓰려면 두 커밋을 미리 가져옵니다. |
| `fixture-ref` | 생략하면 작업 트리에서 읽습니다. PR 기준 커밋에 있는 테스트를 쓰려면 `with`에 `fixture-ref: 'HEAD^1'`을 지정합니다. |
| `capture-summaries` | 검증에 사용할 v1 캡처 요약 경로를 테스트 파일과 같은 순서로 한 줄에 하나씩 지정합니다. `fixture-ref`를 쓰면 같은 커밋의 저장소 루트 기준 경로를 사용합니다. |
| `gate` | `strict`. 새로 실패한 검사만 단계 실패로 처리하려면 `with`에 `gate: regressions`를 지정합니다. |
| `promtool-path` | 생략하면 Linux x64에서 고정된 Promtool 3.11.0을 설치합니다. 기존 실행 파일은 작업 디렉터리 기준 경로나 `PATH`에 있는 명령으로 지정합니다. |

`kubernetes` 모드는 PyYAML 6.0.3을 격리된 가상 환경에 설치합니다. 완료된 비교는 실행 요약을 남기며 `steps.compare.outputs.report-path`로 Markdown 경로, `steps.compare.outputs.json-report-path`로 JSON 경로, `steps.compare.outputs.newly-failed`로 새로 실패한 검사 건수(문자열)를 제공합니다. 게이트를 통과하지 못해도 이 출력들은 제공됩니다. 입력이나 실행 오류는 단계 로그에만 표시됩니다.

게이트가 실패한 경우에도 후속 단계에서 JSON을 읽으려면 해당 단계에 `if: ${{ always() && steps.compare.outputs.json-report-path != '' }}`를 지정합니다.

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

Bearer 인증이 필요한 서버에는 환경 변수 `PROMETHEUS_BEARER_TOKEN`을 사용할 수 있습니다. 저장된 API 응답이 있을 때는 `--matrix`로 로컬에서 변환할 수 있습니다. Prometheus의 `/api/v1/query`에 범위 선택자를 보냈을 때 반환되는 원본 `matrix` 응답을 사용합니다.

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

최근에 고친 알람 하나로 시작하세요. 기존 룰에서는 기대 동작 검사가 실패하고 수정한 룰에서는 통과하는지 확인한 뒤, 생성된 테스트를 룰 변경 PR에 넣어보세요. CI에서는 `promtool test rules incident.test.yml`을 실행하면 됩니다. 테스트 파일에는 캡처한 메트릭 값과 라벨이 들어 있으므로 커밋 전에 저장소 접근 범위에 맞는 데이터인지 확인하세요. [Prometheus 룰 테스트 문서](https://prometheus.io/docs/prometheus/latest/configuration/unit_testing_rules/)
