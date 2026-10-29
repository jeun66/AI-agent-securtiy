# 같은 encoder를 공유하는 분류·span 검출 공부용 실습

## 구현과 실제 학습

`SharedStudyGuard`는 fine-tuning한 GLiClass 모델을 한 번만 로드한다. 입력 분류는 기존 projector head를 쓰고, 출력 span 검출은 그 모델의 **같은 encoder 객체**와 작은 BIO token head를 사용한다. `DefenseHook(guard, guard)`로 input/output을 연결한다.

추가 모델 다운로드 없이 동작하는 직접 구성한 교육용 구조다. GLiNER 패키지나 GLiNER 사전학습 가중치를 사용한 실습은 아니다. encoder·분류 head는 고정하고 BIO head만 별도로 학습했으므로 end-to-end joint training으로 표기하지 않는다.

person/resident_id/api_key/email의 BIO 9개 tag를 사용한다. 이름·번호·이메일·canary는 작성된 가상 데이터다. 원문 위치는 Python 문자열의 문자 offset이며, tokenizer offset과 BIO tag를 맞춘다. train/validation/test 각 10건이고 텍스트 중복, family 누출, span 범위·overlap을 검사한다.

실제 CPU 학습: frozen encoder feature를 계산한 뒤 linear token head를 20 epochs, optimizer 200 steps로 학습했다. weight/bias 2개 tensor가 변경됐으며, checkpoint 선택에는 validation loss만 썼다. 전체 입력 분류·출력 span 모델에는 encoder가 1개 존재하고, input/output hook이 같은 객체를 공유하는 것을 확인했다.

## 실제 관측 결과와 한계

- 합성 test exact-character-span TP=2 / FP=6 / FN=6
- exact span precision=0.25 / recall=0.25 / F1=0.25
- 저장된 span head·분류 checkpoint를 새 프로세스에서 다시 로드하여 테스트의 span 위치·label·score가 저장된 예측과 일치하는 것을 확인했다.
- 전체 3레이어에 연결한 HTTP mock 사례에서 정상 출력은 공개됐고, **가상 사람 이름 출력도 누락되어 공개됐다.** 해당 누락을 성공적인 PII 차단으로 보고하지 않는다.
- 로컬 모델 추론·학습은 실제이고, HTTP 도구와 예시는 mock/합성이다. 실제 MCP 서버, 실제 LLM 생성, 실제 사람 정보는 사용하지 않았다.
- F1=0.25는 작은 합성 데이터의 교육용 결과이며 실제 벤치마크 F1이 아니다. 배포 유효성은 검증하지 않았다.

## 실제 저장 모델의 입출력 hook 확인

```bash
R3_MODEL_PY="/Users/user/Documents/ChatGPT/ihhh/reviewer3-model/.venv/bin/python"
R3_STUDY_DIR="/Users/user/Documents/ChatGPT/ihhh/reviewer3-remaining"
HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 TOKENIZERS_PARALLELISM=false \
"$R3_MODEL_PY" -B -m week5.evaluate_span_study \
  --span-checkpoint "$R3_STUDY_DIR/trained-span-final" \
  --output /tmp/r3-shared-span.json
echo "span evaluation exit=$?"
```

`MODEL_INFERENCE=true`, `ENCODER_INSTANCES=1`, `SAVED_SPAN_PREDICTIONS_REPRODUCED=true`, `SYNTHETIC_SPAN_METRICS`, 두 `CASE`와 종료 코드를 노션 코드 블록에 붙인다. 여기서 `STATUS=ok`는 검사 로직을 거쳐 출력됐다는 뜻이며 정보가 안전하다는 외부 정답 판정이 아니다. PII 정답과 대조한 누락 여부를 함께 기록한다.

## span 학습을 다시 실행할 때

```bash
R3_SPAN_RUN="$(mktemp -d /tmp/r3-span.XXXXXX)"
HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 TOKENIZERS_PARALLELISM=false \
"$R3_MODEL_PY" -B -m week5.train_span_study \
  --classification-checkpoint "$R3_STUDY_DIR/trained-study" \
  --output "$R3_SPAN_RUN/span"
echo "span training exit=$?"
```

기존 출력 폴더를 덮어쓰지 않는다. classifier 전체 가중치를 복제하지 않고 작은 span head와, 연결할 classifier checkpoint 경로·SHA를 보관한다. 함께 사용할 classifier checkpoint를 삭제하면 재로드할 수 없다. 원본·학습 결과의 체크포인트는 Git 밖에 둔다.
