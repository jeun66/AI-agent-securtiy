# 리뷰어3 — 정책·오염·가드레일 연결

W4 기준 커밋: `882ea9d`. 핵심 실행·테스트는 Python 3.9.6과 기존 PyYAML 환경을 사용한다.

## 구현 범위

- `guards.py`: 공통 `GuardRequest -> GuardResult` 인터페이스. `input`/`output`, 탐지 라벨·점수·span, backend와 `kind`를 기록한다. `rule`, `mock`, `model`을 구별한다.
- `model_adapters.py`: 이미 로드한 GLiClass pipeline과 GLiNER model을 받는 선택적 어댑터. 테스트에서는 fake 응답으로 변환 형식만 확인했다. 실제 모델 추론을 실행했다는 뜻이 아니다.
- `defense.py`: 스키마 선검증 → **정책 → 오염 → 입력 가드레일** → 도구 실행 → 출력 가드. 앞 단계 차단/오류 시 후속 단계와 도구 실행을 생략한다. 잘못된 guard 응답·예외·가드 미설정은 차단한다.
- 기존 `week2/agent_tools.py`, `week2/agent_loop.py`의 에이전트 루프에 `defense_hook=`을 주면 사용자 입력을 LLM 호출 전에 검사하고, 하드닝된 시스템 프롬프트를 사용하며, 도구 결과와 최종 답변을 반환 전에 검사한다. `defense_hook`을 생략한 기존 루프와 W4 모드는 기존 동작을 유지한다.
- `policy+taint+guard` 모드는 hook을 생략하면 실행을 차단한다. 신규 모드의 공개 TRACE에는 원문 인자·PII를 남기지 않는다. 실행된 인자는 `[REDACTED]`로 기록한다.
- `tool_executed=false`는 실행 전 차단, `tool_executed=true/output_released=false`는 실행 후 출력 보류다. 출력 가드는 이미 일어난 도구 부작용을 되돌리지 못한다.
- 직접 호출하려면:

```python
from week2 import agent_tools
from week4.run_attacks import FakeToolCall
from week5.defense import DefenseHook
from week5.guards import RuleGuard

hook = DefenseHook(input_guard=RuleGuard(), output_guard=RuleGuard())
call = FakeToolCall("http_get", {"url": "https://study.example/info"})
result = agent_tools.execute_tool_with_mode(
    call, mode="policy+taint+guard", defense_hook=hook, input_text="요약해줘")
```

`FakeToolCall`은 호출 모양만 모사하며 LLM의 제안을 생성하지 않는다. 여기서 `http_get`은 기존 mock 응답 함수다.

## VS Code Bash 실행·캡처

저장소 루트에서 실행한다. 아래 PY는 W4 복구 때 만든 Python 3.9.6 가상환경이다.

```bash
PY="/Users/user/Documents/ChatGPT/ihhh/week4-repair/.venv/bin/python"
R3_LOG_DIR="/tmp/reviewer3-logs"
mkdir -p "$R3_LOG_DIR"
set -o pipefail
"$PY" --version

# 1단계: 인터페이스 (현재 누적 소스에서 재검증)
"$PY" -B -m unittest -v week5.test_guards 2>&1 | tee "$R3_LOG_DIR/01-interface.log"
echo "stage1 exit=$?"

# 2단계: 3레이어 + W4 회귀
"$PY" -B -m unittest -v week5.test_guards week5.test_defense week4.test_integration 2>&1 | tee "$R3_LOG_DIR/02-pipeline.log"
echo "stage2 exit=$?"

# 3단계: 보고서까지 누적 검증
"$PY" -B -m unittest -v week5.test_guards week5.test_defense week5.test_demo week4.test_integration 2>&1 | tee "$R3_LOG_DIR/03-all-tests.log"
echo "stage3 exit=$?"

# 실제 로컬 규칙 검사를 실행. HTTP 도구는 mock이고 파일 읽기는 로컬 fixture다.
"$PY" -B -m week5.run_demo --backend rules --repeats 20 --warmup 1 --output "$R3_LOG_DIR/rules.json" | tee "$R3_LOG_DIR/rules.log"
echo "rules exit=$?"

# 고정 allow mock으로 배선 동작만 확인. 탐지 성능으로 사용하지 않는다.
"$PY" -B -m week5.run_demo --backend mock --repeats 20 --warmup 1 --output "$R3_LOG_DIR/mock.json" | tee "$R3_LOG_DIR/mock.log"
echo "mock exit=$?"

git log -3 --oneline
git status -sb
```

각 단계에서 `OK`와 종료 코드 `0`을 확인한다. 1/2/3단계는 각각 7/23/26개 테스트다. W4 회귀 테스트가 출력하는 `[실행]`은 기존 mock 호출 로그다. 보고서는 이 명령으로 지정한 /tmp 폴더에 남으며 Git 작업 트리를 변경하지 않는다. 단계별 커밋은 별도로 생성되므로 위 캡처 명령에 commit/push를 넣지 않는다.

## 실제 결과와 mock의 구분

- `rules`: Python 규칙·정책·오염 코드와 시간 측정은 실제 실행한다. 합성 시나리오, mock HTTP, 로컬 `note.txt`만 사용한다. regex 규칙은 학습 모델이 아니며 한국어/영어의 일부 알려진 표현만 검사한다.
- `mock`: 가드가 고정 allow를 반환한다. 인젝션·PII 사례도 통과하도록 기대값을 명시했다. `MATCHED=160`은 이 배선 기대값의 일치 횟수이며 방어율·정확도가 아니다.
- `model`: 이 작업에서는 GLiClass/GLiNER 모델을 다운로드하거나 추론하지 않았다. Llama Guard와 laya도 미연결·미실행이다. 비교 표의 F1·지연은 `null`이다.
- latency는 warmup 1 suite를 제외한 20회 × 8개 시나리오의 실제 `perf_counter` 측정이다. total은 전체 로컬 파이프라인, policy/taint/guardrail은 실행된 단계만, guard_input/guard_output은 해당 가드 호출만 집계한다. count가 다른 이유는 조기 차단이다. p50은 중앙값, p95는 nearest-rank다. 모델 로딩·실제 네트워크·LLM 추론 latency는 포함하지 않는다.
- 합성 시나리오 기대값 일치는 구현의 회귀 검증이다. 사람 검토를 마친 held-out 데이터가 없어 모델 F1을 계산하지 않는다.
- 출력 가드가 차단한 원문은 공개 TRACE와 보고서에 저장하지 않는다. span offset의 기준은 해당 guard 입력 문자열이다. input 문자열은 사용자 입력 + context + JSON 인자를 포함할 수 있다.

## GLiClass / GLiNER 연결 준비

공식 API 확인 출처:

- https://github.com/Knowledgator/GLiClass
- https://huggingface.co/knowledgator/gliclass-small-v1.0
- https://github.com/urchade/GLiNER

`gliclass-small-v1.0` 모델 카드는 **144M, English**로 표기한다. 약 340M 모델·한국어 성능으로 간주하지 않는다. 모델 환경의 Python/torch/transformers 호환성은 별도로 확인해야 하며, 기존 W4 가상환경에 대형 패키지를 자동 설치하지 않는다.

아래는 **실행하지 않은 연결 예시**다. 선택한 모델 패키지·가중치를 별도 환경에 준비한 뒤 사용한다. 모델 다운로드, CPU 메모리, 라이선스 및 laya의 정확한 모델 ID는 실측 단계 전에 확인해야 한다.

```python
from gliclass import GLiClassModel, ZeroShotClassificationPipeline
from transformers import AutoTokenizer
from gliner import GLiNER
from week5.model_adapters import GLiClassGuard, GLiNERGuard
from week5.defense import DefenseHook

model_id = "knowledgator/gliclass-small-v1.0"
model = GLiClassModel.from_pretrained(model_id)
model.eval()
pipeline = ZeroShotClassificationPipeline(
    model, AutoTokenizer.from_pretrained(model_id),
    classification_type="multi-label", device="cpu")
ner_id = "urchade/gliner_multi-v2.1"
ner = GLiNER.from_pretrained(ner_id)
ner.eval()
hook = DefenseHook(
    GLiClassGuard(pipeline, threshold=0.5, model_id=model_id),
    GLiNERGuard(ner, threshold=0.5, model_id=ner_id))
```

이 연결은 분류와 span 검출에 **서로 다른 두 모델**을 사용한다. 단일 모델 공동 파인튜닝을 구현한 것은 아니다. GLiClass는 입력 검사만, GLiNER는 출력 span만 지원하며 다른 방향 요청에는 실패한다. 일반 GLiClass와 GLiNER 모델이 인젝션·PII에 검증된 방어 모델이라는 보장은 없다.

## 다음 실습과 한계

현재 작업은 MCP-Guard **방식의 애플리케이션 내부 hook**이며 외부 MCP-Guard 제품이나 MCP JSON-RPC 서버/프록시를 구현·실행한 것은 아니다. 참고 논문의 static/neural/LLM 3단계 재현과도 구별한다.

W4 Tainted 객체를 보존한 호출은 추적하지만, 실제 LLM이 문자열을 다시 생성한 경우 출처가 자동 복원되지는 않는다. 시스템 프롬프트 하드닝은 방어 지시이며 보안 보장이 아니다. 규칙 가드는 exact prompt와 일부 패턴을 검사하며 변형·다국어·난독화 공격에 대한 한계가 있다.

후속 범위: AgentScan 실제 연동, 공격 코퍼스 확대, 실제 모델별 동일 데이터·하드웨어 F1/지연 비교, 사람 라벨 검토, held-out 분리와 GLiClass/GLiNER 파인튜닝. 기존 W4 데이터에는 auto-draft 및 needs_review 항목이 있으므로 라벨링 완료로 간주하거나 자동 학습하지 않는다.
