Week4: Taint + Policy Integration Tests

결과 요약과 제한사항:

- 이 디렉토리의 테스트는 scripted mock 환경에서 동작합니다. `week2/agent_tools.py`의 `MOCK_PAGES` 및 `read_file` 함수로 외부 네트워크에 접근하지 않고 재현 가능한 문자열을 반환합니다.
- 테스트는 provenance(소스) 메타를 `TRACE`에 기록하고, `policy+taint` 모드에서 관측(observed) 유래 인자에 대해 taint 차단을 수행하도록 구현되어 있습니다.
- 실제 LLM의 경계(LLM이 어떤 인자를 생성·수정하는지, followup 관측을 어떻게 유도하는지)는 본 스크립트에서 검증하지 않습니다. scripted followup/observation은 LLM 동작을 모사하지만, 실제 LLM 검증을 대체하지 않습니다.

검증 항목:

- provenance `sources` 필드에 외부 출처(예: `web:external`, `file:config.json`)가 포함되는지 확인합니다. 해당 필드는 `week2/agent_tools.py`의 TRACE에 기록됩니다.
- `policy+taint`에서 taint에 의해 차단된 호출의 경우 `executed_args`이 `null`이며, `MOCK_CALL_COUNT`(도구별 호출 수)가 증가하지 않아야 합니다. 이 테스트는 `week4/test_integration.py`에서 단위 테스트로 자동 검증됩니다.

제한사항:

- scripted mock 한계: 테스트는 모의 응답/파일을 사용하므로 실제 네트워크/LLM 행동과 차이가 있을 수 있습니다. 실제 LLM 경계 검증은 별도 실험(실제 LLM 호출 또는 샌드박스된 모델 실행)이 필요합니다.

보고서 위치:

- 최종 JSON 보고서: `week4/results/w4_report_final.json`
- 추가 보고서: `week4/results/w4_report_aug_*.json`
