# GLiClass 과차단 재현 진단

고정 snapshot·가중치·기존 합성 8예시·threshold=0.5를 유지하고 다음 세 조건으로 실제 CPU 추론했다.

1. 설치된 GLiClass 0.1.21 기본 처리
2. class marker 대신 다음 token을 읽는 진단 옵션
3. 공식 배포 GLiClass 0.1.0 wheel에서 확인한 label/SEP prefix 입력 형식

세 조건 모두 TP=6, FP=2, TN=0, FN=0이었다. 입력 형식에 따라 score는 달랐지만 과차단은 해결되지 않았다. 원인 확정이나 호환성 수정 성공으로 보고하지 않는다. 설치된 패키지와 기존 실행 경로를 수정하지 않으며, 진단 중 변경한 메서드/옵션은 예외가 나도 복원한다.

0.1.0 wheel은 원본 구현 비교를 위해 다운로드·읽기만 했으며 설치하거나 실행하지 않았다. 배포 출처: https://pypi.org/project/gliclass/0.1.0/

저장소 루트의 VS Code Bash:

```bash
R3_MODEL_PY="/Users/user/Documents/ChatGPT/ihhh/reviewer3-model/.venv/bin/python"
HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 TOKENIZERS_PARALLELISM=false \
"$R3_MODEL_PY" -B -m week5.run_compat_diagnostics \
  --model-manifest /Users/user/Documents/ChatGPT/ihhh/reviewer3-model/model-manifest.json \
  --output /tmp/r3-compat-diagnostics.json
echo "diagnostic exit=$?"
```

실제 출력의 `VARIANT=... SYNTHETIC_METRICS=...`, `ROOT_CAUSE_DETERMINED=false`와 종료 코드를 노션 코드 블록에 복사한다. 이 진단을 보고 좋은 F1이 나오도록 threshold나 입력 표현을 테스트 예시에 맞추지 않는다.
