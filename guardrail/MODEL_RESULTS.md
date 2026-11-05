# 3단계 — 실제 모델 추론과 고정 평가 자료 비교

2026-11-05 실행. 입력은 사용자가 검토한 `eval.jsonl`의 24개 문장(정상 12, 공격 12), 원본 그룹 12개다. 작은 합성 자료이며 운영 성능을 검증한 결과가 아니다.

## 실제 측정 결과

| 구분 | 공격 F1 | 정상 오차단 | 공격 누락 | 평균 ms/건 | p50 ms | p95 ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| GLiClass 원본 zero-shot · 추가 기준선 | 0.667 | 12/12 | 0/12 | 18.037 | 17.023 | 22.196 |
| ours-GLiClass · 기존 공부용 head 학습형 | 0.700 | 1/12 | 5/12 | 18.232 | 17.310 | 22.614 |
| Laya 다국어 322M | 0.815 | 4/12 | 1/12 | 89.709 | 84.760 | 115.062 |
| Llama Guard 4 12B | 미측정 | 미측정 | 미측정 | 미측정 | 미측정 | 미측정 |

GLiClass 원본은 전부 block이므로 F1 0.667만 보고 유효한 방어라고 해석하면 안 된다. 학습형은 정상 오차단을 줄였지만 공격 5개를 놓쳤다. Laya는 이 자료에서 공격을 더 많이 잡았지만 정상 오차단도 더 많고 느렸다. 임계값·질문·체크포인트를 이 평가 결과에 맞춰 수정하거나 가장 좋은 변형을 골라 바꾸지 않았다. 현재 모델을 운영용으로 활성화하지 않는다.

## 고정 조건과 확인한 증거

- 동일 Apple Silicon Mac, 물리 RAM 16GiB, CPU float32, intra-op 스레드 2, inter-op 1, batch size 1, 비양자화.
- 단독 프로세스로 순차 실행. 평가 문장 고정 순서, warmup 1 suite(24회), 측정 3 suites(72회). F1 표본은 반복을 더하지 않은 24개.
- 각 소형 모델에서 torch forward hook으로 실제 forward **96회**를 확인했다. 응답 캐시나 mock 결과로 대체하지 않았다.
- 모델 로딩·파일 읽기·warmup은 요청 지연에서 제외했다. 토큰화·추론·점수 파싱·어댑터 처리는 포함한다.
- raw checkpoint 체크섬을 확인했다. GLiClass는 로딩 오류 키 0개와 checkpoint 텐서 prefix 111개 일치를 검사했고, 최대 입력은 115 tokens로 잘림이 없다.
- Laya는 `multilingual` 체크포인트만 고정하여 사용하며 자동 언어 라우팅·compile·fast path를 쓰지 않는다. 모든 요청에서 `usage.truncated=false`를 확인한다. SDK의 tokenizer 정규화가 pinned 입력을 변경하지 않도록 임시 복사본을 사용했다.
- 패키지: Python 3.12 실행 환경, torch 2.15.0, transformers 5.21.0, gliclass 0.1.21, laya 0.4.22, numpy 2.5.4, safetensors 0.8.0, huggingface-hub 2.3.0. 세 측정 모두 같은 패키지 버전을 사용했다.
- 새 가상환경은 기존 ML 환경을 읽기 전용 경로로 재사용하고 Laya wheel만 별도로 설치했다. 다른 장비에서의 완전한 클린 설치 재현까지 검증한 것은 아니다.

Wi-Fi 중단 때 완료된 결과는 파일로 남아 있어 다시 추론하지 않았다. 모델별 벽시계 실행 시점은 다르고 온도·백그라운드 부하를 통제한 실험은 아니다. 지연의 작은 차이에 통계적 의미를 부여하지 않는다.

## 모델 정체성과 정책

- GLiClass 원본: `knowledgator/gliclass-small-v1.0@21edefaf7951f68c68c505f9139ba536d3b448f7`, 실제 143,592,193 parameters.
- 학습형: 위 원본에서 이전 실습 때 encoder를 동결하고 projector head를 40번 갱신한 체크포인트. 가중치 SHA-256 `89fd42fa2738739d7066fb58bfbb91d64fdfb7e12526f792f64c9c8d67974ad2`. 이번 단계에서 새로 학습하지 않았다.
- 이전 학습·validation·test 32개의 파일 해시는 배제 코퍼스 원본 해시와 대조했다. 새 평가 자료를 학습에 넣지 않았다.
- Laya: `convaiinnovations/laya@7b928d828b7b0e022f929d9bd2e44165aa270148`, `multilingual`, 실제 321,908,995 parameters. wheel SHA-256 `7e8cad8ca4cb76588ef608e70ad6753bae612885e015aeeeae7b43268ec5fd5a`.
- GLiClass는 고정 라벨의 악성 점수 하나라도 0.5 이상이면 block이다. Laya는 고정한 세 typed yes/no 질문 중 하나라도 P(true)가 0.5 이상이면 block이다. 질문·실행 조건은 첫 모델 측정 전에 `model_protocol.json`에 고정했다.
- Llama Guard 연결 코드는 공식 vanilla 콘텐츠 안전 taxonomy와 엄격한 safe/unsafe 파서를 사용한다. 인젝션 전문 모델과 목적이 다름을 보존한다.

참조: [GLiClass](https://huggingface.co/knowledgator/gliclass-small-v1.0), [Laya](https://huggingface.co/convaiinnovations/laya), [Laya SDK](https://github.com/NandhaKishorM/laya), [Llama Guard 4](https://huggingface.co/meta-llama/Llama-Guard-4-12B).

## 12B는 왜 미측정인가

동일 CPU float32 조건에서 가중치만 약 48GB이고, 사전 점검은 추가 메모리를 포함해 60GB를 추정한다. 현재 16GiB와 맞지 않아 **다운로드·로딩·추론을 실행하지 않았다**. BF16 가중치도 약 24GB라 현재 메모리보다 크다. 양자화 모델이나 원격 API로 자동 교체하지 않았다.

`llama-preflight.json`의 상태는 `not_run_memory_limit`, F1·지연은 null이다. gated 모델 접근 권한은 확인하지 않았으며 약관 동의·토큰 입력도 수행하지 않았다. 전체 세 모델 비교 완료 여부는 **false**다. 나중에 충분한 메모리의 장비와 사용자 Hugging Face 접근 권한을 준비해야 한다. GPU나 양자화를 선택하면 모든 비교 조건을 새로 정의한다.

## 보존 결과를 확인하는 명령

저장소 루트에서 추가 설치 없이 실행한다. 이 명령들은 완료된 모델 추론을 반복하지 않는다.

```bash
python3 -B -m unittest -v guardrail.test_data guardrail.test_benchmark guardrail.test_model_backends guardrail.test_comparison
python3 -B -m guardrail.compare_reports --reports-dir guardrail/reports/2026-11-05 --output /tmp/r3-benchmark/comparison.json
```

63 tests/OK와 `THREE_MODEL_COMPARISON_COMPLETE=false`를 확인한다. 비교기는 평가 데이터·프로토콜 해시, CPU/dtype/스레드, 패키지·반복·표본 수가 다른 보고서를 섞지 않는다. 실행 당시 기록한 소스 해시와 현재 파일도 대조한다.

추론은 작업 폴더의 staging 소스에서 실행했고 원본 JSON을 그대로 보존했다. 원본 보고서의 `source_commit`은 null이다. 소스 해시와 대조해 커밋할 코드가 실행 코드와 일치함을 검증했으며, 나중의 커밋에서 실행했다고 소급 기입하지 않았다. 원문·예외 메시지를 결과 파일에 넣지 않았다.

## 사용자가 실제 추론 로그를 직접 남기려면

같은 Mac에 준비한 환경·가중치로 실행한다. 결과는 /tmp에 저장하며 코드·학습 가중치는 바꾸지 않는다.

```bash
R3_MODEL_PY="/Users/user/Documents/ChatGPT/ihhh/reviewer3-benchmark/stage3-env/bin/python"
"$R3_MODEL_PY" -B -m guardrail.run_models --backend gliclass-trained --model-manifest /Users/user/Documents/ChatGPT/ihhh/reviewer3-model/model-manifest.json --trained-checkpoint /Users/user/Documents/ChatGPT/ihhh/reviewer3-remaining/trained-study --output /tmp/r3-benchmark/ours.json
"$R3_MODEL_PY" -B -m guardrail.run_models --backend laya --model-manifest guardrail/manifests/laya-multilingual.local.json --output /tmp/r3-benchmark/laya.json
```

이 두 명령은 실제 추론을 새로 한다. `MODEL_INFERENCE=true`, `FORWARD_PASSES=96`, 각 JSON·CSV를 보관한다. 기존 결과와 별도 실행이므로 시간·소수점이 달라질 수 있다. Laya local manifest는 이 Mac의 경로를 가리킨다. 다른 장비에서는 같은 revision·체크섬의 가중치 경로를 준비해야 한다.

12B의 미실행 사전 점검만 재현하려면 다음 명령을 쓴다. 현재 Mac에서는 **종료 코드 3이 예상값**이다.

```bash
"$R3_MODEL_PY" -B -m guardrail.run_models --backend llama-guard4 --output /tmp/r3-benchmark/llama-preflight.json
```
