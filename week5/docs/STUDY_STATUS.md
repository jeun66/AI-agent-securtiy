# 리뷰어3 공부용 실습 — 실행 상태

| 항목 | 상태 | 실제 실행 범위 |
| --- | --- | --- |
| 정책 → 오염 → 가드레일 | 완료 | W4 회귀, mock 도구, 실제 로컬 검사 코드 |
| 입력·출력 hook, 시스템 프롬프트 하드닝 | 구현·검증 | fake LLM 응답으로 경계 검사; 실제 LLM 효과는 미평가 |
| GLiClass zero-shot | 실행 | 실제 144M CPU 추론, 정상 예시 과차단 확인 |
| 과차단 진단 | 실행 | token 위치·0.1.0 입력 형식으로도 과차단 미해결; 원인 미확정 |
| 분류 fine-tuning | 공부용 실행 | 합성 16/8/8, frozen encoder, projector 40 updates, 저장·재로드 |
| 한 encoder 분류 + span | 공부용 실행 | 직접 구성한 BIO head 200 updates; GLiNER 모델 자체는 미사용 |
| 정확도·지연 리포트 | 실행 | 동일 합성 study test의 원본·학습 후 실제 CPU 결과 |
| 탈옥·시스템 프롬프트 추출 예시 | 분류 평가 실행 | 실제 모델에 텍스트 예시 입력; 실제 agent jailbreak ASR은 미측정 |
| laya 322M | 미실행 | 공식 대상 convaiinnovations/laya-multilingual 확인. 설치 승인이 거절되어 패키지·가중치 실행 안 함 |
| Llama Guard 4 12B | 미실행 | 사용자가 대형 모델은 제외하도록 선택. Mac 16GiB에서 원본 FP16 가중치만 약 24GB |
| 외부 AgentScan | 미실행 | 명세의 제품·대상 불명. 임의 서비스 가입·API 호출 안 함 |
| GLiNER 사전학습 모델·내장 Trainer | 미실행 | 추가 설치 없이 PyTorch 학습 루프와 자체 span head로 교육용 구조를 확인 |
| 실제 벤치마크·운영 배포 | 미실행 | 결과의 benchmark_f1=null, deployment_validated=false |

학습 loss 감소를 방어 성능 향상으로 해석하지 않는다. 합성 test에서 분류 F1은 0.857143 → 0.5로 악화됐다. 정상 과차단은 2 → 0, 공격 누락은 0 → 4였다. span exact F1은 0.25이며 가상 사람 이름 출력 누락 사례도 확인했다.

공부용으로 구조 연결, 실제 추론, 실제 parameter 갱신, 저장·재로드, 오류·실패 결과 기록까지 확인했다. 비교 모델·외부 서비스·실전 평가까지 모두 완료했다는 뜻은 아니다. 모델·원본 설정은 실험 결과가 좋게 보이도록 자동 교체하거나 활성화하지 않았다.

## 노션에 텍스트 결과 기록

화면 캡처 대신 각 문서의 명령 실행 결과를 코드 블록에 붙인다.

- [과차단 재현 진단](COMPAT_DIAGNOSTICS.md)
- [분류 head 학습·동일 test 비교](STUDY_CLASSIFICATION.md)
- [shared encoder span 학습·입출력 hook](SHARED_SPAN_STUDY.md)

전체 코드 회귀 검증:

```bash
R3_CORE_PY="/Users/user/Documents/ChatGPT/ihhh/week4-repair/.venv/bin/python"
"$R3_CORE_PY" -B -m unittest -v \
  week5.test_guards week5.test_defense week5.test_demo week5.test_zero_shot \
  week5.test_diagnostics week5.test_study week5.test_span_study week4.test_integration
echo "tests exit=$?"
git log -3 --oneline
git status -sb
```

코드 검증은 47 tests/OK를 확인한다. 이는 판별 모델의 정확도가 높다는 뜻이 아니다. ML 의존성이 없는 테스트에서는 fake 응답을 사용하며, 실제 모델·학습 증거는 별도의 실행 JSON·학습 로그로 구분한다.
