# Incident to Promtool

Turn past Prometheus incidents into offline alert-rule regression tests.

장애 구간의 시계열과 팀이 정한 알람 기대 동작으로 `promtool` 테스트 파일을 만듭니다. 같은 데이터에서 기존 룰과 수정 룰을 비교해 PR에 붙일 Markdown 리포트를 만들고, 테스트 파일을 커밋해 이후 변경에도 같은 검사를 실행할 수 있습니다.

## 결제 장애 예제 실행

저장소 루트에서 실행합니다. Python 3.10 이상과 `promtool` 3.9 이상이 필요합니다. 예제는 `alarm-study`의 결제 장애에서 착안한 합성 데이터입니다. [alarm-study](https://github.com/cynkai/alarm-study)

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

비교 입력은 이 CLI가 JSON 문법으로 생성한 `.test.yml` 파일입니다. 의존 룰 파일이 있으면 `--before`와 `--after`를 각각 반복해서 지정하세요. `--promtool /path/to/promtool`로 실행 파일을 지정할 수 있습니다.

종료 코드 `0`은 수정 룰 통과, `1`은 수정 룰에서 기대 동작 불일치, `2`는 입력 또는 `promtool` 실행 오류입니다. 기존 룰에서 발생한 기대 동작 불일치는 리포트에 표시하며 종료 코드는 수정 룰의 결과를 따릅니다.

GitHub Actions에서 같은 명령의 출력을 `>> "$GITHUB_STEP_SUMMARY"`로 보내면 실행 요약에 표와 불일치 내용이 표시됩니다. 수정 룰이 검사에 실패하면 그 단계도 실패합니다.

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

기본 모드는 유한한 스칼라 표본을 지정한 격자에 정확히 들어갈 때 변환합니다. 평가 간격은 표본 간격의 배수여야 합니다. `--round-up`은 표본을 다음 격자로 미루고 최대 이동 시간을 표시하며, `end`도 격자에 맞춰야 합니다. 같은 시계열의 서로 다른 두 타임스탬프가 한 칸에 들어가면 더 촘촘한 격자가 필요합니다. 올림은 판정 시각에 영향을 줄 수 있습니다. Prometheus 원본 조회 API는 stale 표식을 제외하므로, `absent()`처럼 시계열이 stale 상태가 된 시각에 의존하는 룰은 이 방식으로 정확히 재현하기 어렵습니다.

## 실제 변경에 적용하기

최근에 고친 알람 하나로 시작하세요. 기존 룰에서는 기대 동작 검사가 실패하고 수정한 룰에서는 통과하는지 확인한 뒤, 생성된 테스트를 룰 변경 PR에 넣어보세요. CI에서는 `promtool test rules incident.test.yml`을 실행하면 됩니다. 테스트 파일에는 캡처한 메트릭 값과 라벨이 들어 있으므로 커밋 전에 저장소 접근 범위에 맞는 데이터인지 확인하세요. [Prometheus 룰 테스트 문서](https://prometheus.io/docs/prometheus/latest/configuration/unit_testing_rules/)
