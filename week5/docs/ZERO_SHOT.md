# 리뷰어3 다음 단계 — GLiClass 실제 zero-shot 추론

## 수행한 작업

- 기존 W4 Python 3.9.6 가상환경은 그대로 두고 별도 Python 3.12.14 환경을 만들었다.
- 실제 설치: gliclass 0.1.21, torch 2.15.0, transformers 5.21.0. 전체 버전은 `week5/requirements-model.lock.txt`에 고정했다. 이 lock은 macOS arm64/Python 3.12 실행 환경 기준이다.
- `knowledgator/gliclass-small-v1.0` 공개 safetensors 가중치와 tokenizer 약 586MB를 다운로드했다. 학습이나 호스팅 추론 API를 호출하지 않았다.
- revision: `21edefaf7951f68c68c505f9139ba536d3b448f7`
- 가중치 SHA-256: `ed3d94af3541d078e91d9518a8bfb87b090f73da488184d3cd6a1feed4511278`
- 실제 파라미터 수: 143,592,193. CPU/float32/torch threads=2로 실행했다.
- 다운로드 후에는 offline/local_files_only로 로드한다. 누락·불일치·예상 밖 checkpoint key가 있으면 중단하며, 실제 로드된 111개 텐서의 일부 값도 저장된 값과 비교한다. 이 검사는 모든 텐서 전체 값 비교가 아니라 prefix 비교다. 파일 전체의 무결성은 manifest SHA-256으로 검사한다.
- 모델 추론 실패 시 mock으로 대체하지 않는다. 출력 가드는 여전히 기존 규칙 가드이며 GLiNER 실제 추론은 이번 범위에 없다.

## 실제 관측 결과

한국어 4건·영어 4건, 총 8개의 작성된 합성 예시를 사용했다. 각 언어는 정상 1건과 injection/jailbreak/system_prompt_extraction 각 1건이다. 별도의 실제 벤치마크나 사람 검토를 완료한 held-out 평가 데이터가 아니다.

- 설정: labels=`benign`, `prompt_injection`, `jailbreak`, `system_prompt_extraction`, multi-label, threshold=0.5.
- **8건을 모두 block했다. 정상 2건도 차단했다.** TP=6, FP=2, TN=0, FN=0.
- 합성 smoke의 binary precision=0.75, recall=1.0, F1≈0.857143이다. 같은 데이터에서 **무조건 차단하는 기준선과 동일한 수치**다. 판별력이나 운영 유효성을 입증한 결과로 쓰지 않는다.
- 실제 벤치마크 F1은 `null`, `DEPLOYMENT_VALIDATED=false`로 기록한다.
- warmup 1회 × 8건을 제외하고 5회 × 8건=40회 실제 forward pass의 latency를 측정한다. 고유 예시는 여전히 8건이며 반복으로 평가 표본 수를 늘리지 않는다.
- 지연은 CPU tokenization + 모델 forward + 어댑터 판정 범위다. import·가중치 로드·warmup·MCP·LLM 생성·HTTP는 포함하지 않는다. 로드 시간은 별도로 기록한다.
- 실제 모델을 3레이어 hook에 넣어 policy_denial / taint_denial / normal_request도 확인한다. 앞 두 사례는 모델 호출 0회이며, 정상 요청은 실제 모델이 1회 호출된 뒤 guardrail에서 차단된다. HTTP는 mock 도구이고 여기서는 실행되지 않았다.
- 실제 분류는 모델 가중치로 수행했지만 예시 텍스트와 도구 환경은 합성/mock이다. 이를 실제 공격 벤치마크 평가와 혼동하지 않는다.

현재 환경에서 일반 주제 분류 예시도 여러 라벨에 높은 점수를 냈다. checkpoint key와 sampled value는 일치하지만 라이브러리/체크포인트의 의미상 호환성·라벨 표현·확률 보정까지 검증된 것은 아니다. transformers 모델 타입·deprecated 경고도 원본 로그에 보존했다. 원인을 특정하거나 threshold를 이 8건에 맞춰 조정하지 않았다. 호환성과 독립 검증 데이터를 먼저 확인한 뒤 보정·파인튜닝 여부를 결정한다.

## VS Code Bash — 실행 결과를 노션 코드 블록에 복사

저장소 루트에서 실행한다. 아래 경로는 실제 준비한 모델 환경이다. 화면 캡처는 필요 없다.

```bash
R3_MODEL_DIR="/Users/user/Documents/ChatGPT/ihhh/reviewer3-model"
R3_MODEL_PY="$R3_MODEL_DIR/.venv/bin/python"
"$R3_MODEL_PY" --version

HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 TOKENIZERS_PARALLELISM=false \
"$R3_MODEL_PY" -B -m week5.run_zero_shot \
  --model-manifest "$R3_MODEL_DIR/model-manifest.json" \
  --summary-only --output /tmp/r3-gliclass-zero-shot.json
echo "zero-shot exit=$?"

# 기존 Python 3.9.6 환경에서 누적 회귀 검증
R3_CORE_PY="/Users/user/Documents/ChatGPT/ihhh/week4-repair/.venv/bin/python"
"$R3_CORE_PY" -B -m unittest -v \
  week5.test_guards week5.test_defense week5.test_demo \
  week5.test_zero_shot week4.test_integration
echo "tests exit=$?"

git log -1 --oneline
git status -sb
```

노션에는 `RUN_KIND`, 모델·revision·실제 버전, 8개 `CASE`, `CPU_LATENCY`, `SYNTHETIC_SMOKE_METRICS`, `DIAGNOSTICS`, 3개 `PIPELINE_PROBE`, 종료 코드를 붙인다. 테스트에서는 `Ran 34 tests`, `OK`를 붙인다. 경고가 있으면 결과에서 숨기지 말고 원본 로그에 함께 보관한다.

`--summary-only`는 콘솔의 예시별 문구만 줄인다. 실제 label별 score, confusion matrix, 언어별 수치, 가중치/소스 해시는 JSON 보고서에 남긴다.

## 새 환경에서 준비할 때만 실행

현재 컴퓨터에는 이미 준비됐으므로 재설치·재다운로드할 필요 없다. 새 환경에서는 호환되는 Python 3.12로 별도 venv를 만들고 lock을 설치한 다음, pinned snapshot을 받는다. 아래 명령은 네트워크와 수백 MB 다운로드를 사용한다.

```bash
# 호환되는 Python 3.12 가상환경을 만든 뒤 해당 python으로 실행
"$R3_MODEL_PY" -m pip install -r week5/requirements-model.lock.txt
"$R3_MODEL_PY" -B -m week5.download_zero_shot_model --destination "$R3_MODEL_DIR"
```

모델·venv·cache는 저장소 밖에 둔다. manifest는 로컬 경로를 포함하며, 모델 파일을 수정/이동했다면 재다운로드·manifest를 다시 생성한 후 무결성을 확인한다. 신뢰할 수 없는 manifest를 받으면 출처를 확인한다. manifest 해시는 전송 후 변경 검출을 위한 것으로 작성자 서명 검증은 아니다.

공식 참고: https://github.com/Knowledgator/GLiClass / https://huggingface.co/knowledgator/gliclass-small-v1.0
