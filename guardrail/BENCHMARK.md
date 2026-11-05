# 2단계 — 공통 평가기 검증

`eval.jsonl` 24개는 사용자가 검토 완료한 작은 합성 평가 세트다. 이번 단계는 실제 모델을 설치·로드하지 않고 **평가기의 판정·오류 처리·지연 집계**를 검증한다.

## 기록할 명령

저장소 루트에서 Python 3.9 이상으로 실행한다. 추가 패키지는 없다.

```bash
python3 -B -m unittest -v guardrail.test_data guardrail.test_benchmark
python3 -B -m guardrail.validate_data --mode benchmark
python3 -B -m guardrail.benchmark --backend rules --repeats 3 --warmup 1 --output /tmp/r3-benchmark/rules.json
python3 -B -m guardrail.benchmark --backend mock --repeats 3 --warmup 1 --output /tmp/r3-benchmark/mock.json
```

테스트는 47개다. 평가기는 승인·해시를 확인하고 최종 평가 파일로만 실행한다.

출력에서 다음을 확인한다.

- `RUN_KIND=smoke_only MODEL_INFERENCE=false`
- `total_cases=24`, `completed_cases=24`, `coverage=1.0`, 오류·불안정 사례 0
- `MODEL_METRICS=null`, `eligible_for_model_comparison=false`
- `LATENCY.count=72`: 측정 3회 × 문장 24개. warmup 1 suite인 24회는 제외
- 각 JSON과 같은 이름의 CSV에 요청별 반복 번호·판정·시간·오류 유형 저장

테스트 통과와 measurement_valid는 측정 절차가 정상이라는 뜻이며 방어 성능이 높다는 뜻이 아니다. /tmp 결과는 임시 파일이므로 실습 증거로 남길 파일은 별도 보관한다.

## 지표와 오류

기존 `GuardRequest -> GuardResult`를 그대로 사용한다. allow는 0, block은 1이다. 튜플·미지원 판정·예외·backend 이름 불일치는 **오류**이며 block으로 변환하지 않는다. 원문과 예외 메시지는 공개 보고서에 저장하지 않는다.

Precision, Recall, 공격 양성 클래스 F1, Accuracy, FPR/FNR, TP/FP/TN/FN을 계산한다. Python 표준 라이브러리로 이진 지표의 정의식을 구현했으며 분모가 0이면 null로 기록한다. F1을 Accuracy라고 표기하지 않는다.

문장별 모든 반복이 성공하고 판정도 같을 때만 완료 사례로 센다. 지표 표본은 항상 문장당 1개이며 반복을 독립 데이터로 세지 않는다. 오류·판정 불안정·warmup 오류가 하나라도 있으면 모델 비교용 metrics를 null로 유지하고 완료율과 진단 지표를 따로 남긴다. 오류를 제외한 부분집합의 F1을 전체 성능으로 대체하지 않는다.

rules/mock 결과의 metrics도 항상 null이다. `diagnostics.completed_case_metrics`는 규칙 동작 또는 고정 응답 검증용이며 실제 모델 성능이 아니다. 기존 규칙을 이 평가 문장에 맞춰 수정하지 않는다.

## 지연 측정

모델은 사전 로드하고 추론 전용 모드를 설정해야 한다. runner는 고정 순서로 전체 세트를 반복한다. 요청 객체 구성·파일 읽기·warmup·지표 계산·보고서 저장은 지연 집계 밖이다. `guard.check()` 내부의 토큰화·추론·판정 파싱과 실행 후 장치 동기화는 포함한다. 성공 요청만 평균·중앙값 p50·nearest-rank p95에 넣고 오류 요청 수를 별도 표시한다.

실제 GPU/MPS 모델은 명시적 동기화 callback이 필요하다. 동기화 전에는 타이머를 시작하지 않고, 호출 후에도 동기화를 기다려 종료한다. 실제 CPU 모델의 스레드 수 설정과 추론 전용 모드 적용은 다음 단계의 loader가 담당한다. 현재 동기식 runner는 독자적인 강제 timeout을 제공하지 않으며 timeout 처리는 backend 책임이다.

모델 지연에는 모델 로딩이 포함되지 않는다. 현재 `model_loading_ms`는 미측정인 null이다. 원격 API와 로컬 추론을 동일 조건 지연으로 섞어 비교하지 않는다. backend의 결과 캐싱을 사용해 반복 측정 시간을 줄이지 않는다.

## 실제 모델 연결 계약

모델 loader가 준비되면 `evaluate_file(guard, data, manifest, execution=..., synchronize=...)`에 연결한다. 파일 승인·해시 검사를 통과하기 전에는 guard를 호출하지 않는다. `run_guard()`는 테스트용 저수준 함수이며 파일 검사를 대신하지 않는다.

model kind에는 model_id, 고정 model_revision, variant, device, dtype, threads, decision_policy가 필요하다. 장치가 CPU가 아니면 동기화 callback도 필요하다. 이 정보와 kind는 호출한 loader의 선언이며 runner가 가중치를 검사하거나 실제 학습 이력을 증명하지 않는다. CLI는 현재 rules/mock만 노출하므로 모델을 실행했다고 출력할 수 없다.

다음 단계는 GLiClass·Laya·Llama Guard 실제 loader 구현과 고정된 모델별 실행 조건을 기록하는 것이다. 기본 모델/공부용 학습 모델, 콘텐츠 안전 정책/인젝션 탐지 정책의 차이를 보존한다.
