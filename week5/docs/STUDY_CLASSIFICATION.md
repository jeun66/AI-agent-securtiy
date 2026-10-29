# 공부용 소규모 분류 헤드 학습

## 범위

W4의 auto-draft/needs_review를 사람 검토 완료 데이터로 간주하지 않고, 별도의 작성된 합성 예시를 사용한다. `study_classification.jsonl`은 train 16 / validation 8 / test 8이다. 텍스트·ID 중복 및 split 사이 family 중복을 검사하며 각 split에 네 label이 모두 존재한다. 이 작은 분리는 실전 일반화나 공격 강건성을 입증하지 않는다.

기존 GLiClass CPU 환경만 사용한다. PyTorch의 명시적 학습 루프로 loss/backward/optimizer.step을 확인한다. GLiClass 내장 Trainer 실행은 아니며, Trainer 추가 의존성 설치도 하지 않았다. encoder는 고정하고 text/classes projector 두 head의 2,362,368개 parameter만 학습한다. BCEWithLogitsLoss, seed=42, batch=2, lr=2e-5, 5 epochs이다. validation BCE로 checkpoint를 선택하고 test 결과로 hyperparameter를 바꾸지 않는다.

## 실제 실행 결과

- optimizer step 40회, head tensor 8개가 실제 변경됐다.
- train 평균 BCE: 1 epoch 3.863624 → 5 epoch 0.573436
- validation BCE: 1 epoch 1.890668 → 5 epoch 0.630266
- 선택된 epoch: 5
- 저장 모델을 새 프로세스에서 다시 로드해 test의 decision과 전체 label score가 학습 종료 시점과 일치하는 것을 확인했다.

동일한 별도 study test 8건에서:

| 조건 | TP | FP | TN | FN | 합성 binary F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 원본 zero-shot | 6 | 2 | 0 | 0 | 0.857143 |
| 분류 head 학습 후 | 2 | 0 | 2 | 4 | 0.500000 |

정상 과차단은 줄었지만 공격 누락이 늘어 F1은 악화됐다. loss가 줄거나 학습 코드가 실행됐다고 방어 성능 향상을 주장할 수 없다는 실습 결과다. 원본 F1은 무조건 차단 기준선과 같다. 두 수치 모두 실제 벤치마크 F1이 아니다.

동일 CPU/float32/2 threads에서 tokenization + forward + adapter의 40회 측정을 수행했다. mean/p50/p95와 실행 시각은 실제 JSON에 남긴다. warmup 8회 및 model load는 제외한다. 원본과 학습 후는 동일한 study test를 사용하며, 앞선 zero-shot 8예시 리포트와 표본을 섞지 않는다.

## 저장된 실제 모델로 재검증

```bash
R3_MODEL_PY="/Users/user/Documents/ChatGPT/ihhh/reviewer3-model/.venv/bin/python"
R3_STUDY_DIR="/Users/user/Documents/ChatGPT/ihhh/reviewer3-remaining"

HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 TOKENIZERS_PARALLELISM=false \
"$R3_MODEL_PY" -B -m week5.evaluate_study --variant base \
  --model-manifest /Users/user/Documents/ChatGPT/ihhh/reviewer3-model/model-manifest.json \
  --output /tmp/r3-study-base.json

HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 TOKENIZERS_PARALLELISM=false \
"$R3_MODEL_PY" -B -m week5.evaluate_study --variant trained \
  --trained-model "$R3_STUDY_DIR/trained-study" --output /tmp/r3-study-trained.json
echo "evaluation exit=$?"
```

노션에는 `SYNTHETIC_TEST`, `CPU_LATENCY`, `CHECKPOINT_RELOADED_AND_VERIFIED=true`, `PIPELINE` 및 종료 코드를 복사한다. 파이프라인의 HTTP 도구는 mock이며, 실제 추론은 로컬 모델로 수행한다.

## 학습 과정 자체를 다시 실행할 때

```bash
R3_STUDY_RUN="$(mktemp -d /tmp/r3-study.XXXXXX)"
HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 TOKENIZERS_PARALLELISM=false \
"$R3_MODEL_PY" -B -m week5.train_study \
  --model-manifest /Users/user/Documents/ChatGPT/ihhh/reviewer3-model/model-manifest.json \
  --output "$R3_STUDY_RUN/model"
echo "training exit=$?"
```

기존 폴더·원본 snapshot을 덮어쓰는 학습 출력은 거부한다. 새 checkpoint는 수백 MB이며 Git에 넣지 않는다. 실제 학습이다. mock 학습, 대형 모델 학습, GLiNER 학습, encoder 전체 fine-tuning으로 표기하지 않는다.
