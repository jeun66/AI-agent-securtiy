# W7 로컬 위임·명령 무결성 비교

실행 환경 Darwin 27.0.1 arm64 · Python 3.12.14 · OPA 1.22.3
각 조건에서 공격 11종, 정상 2종, 장애 대조 1종을 각각 10회 실행했다.

| 방어 조건 | ASR | 비인가 부작용 | 정상 성공 | 정상 실패율 | 전체 p50 | 전체 p95 | 정상 읽기 p50 | 서명 로그 완전성 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Baseline | 10/11 (90.9%) | 10/11 | 2/2 | 0.0% | 0.035 ms | 0.235 ms | 0.036 ms | — |
| OPA만 적용 | 6/11 (54.5%) | 6/11 | 1/2 | 50.0% | 8.657 ms | 9.382 ms | 8.679 ms | — |
| 전체 방어 | 0/11 (0.0%) | 0/11 | 2/2 | 0.0% | 4.707 ms | 16.977 ms | 16.000 ms | 140/140 |

## 케이스별 결과

| 케이스 | Baseline | OPA만 적용 | 전체 방어 |
| --- | --- | --- | --- |
| 다른 에이전트의 DID 사칭 | ALLOW (`allowed`) | ALLOW (`allowed`) | DENY (`invalid_signature`) |
| 위임 토큰 서명 위조 | ALLOW (`allowed`) | ALLOW (`allowed`) | DENY (`invalid_token_signature`) |
| 정상 키로 서명한 하위 권한 확대 | ALLOW (`allowed`) | ALLOW (`allowed`) | DENY (`scope_expanded`) |
| 만료된 위임 토큰 사용 | ALLOW (`allowed`) | ALLOW (`allowed`) | DENY (`capability_inactive`) |
| 회수된 상위 토큰의 하위 위임 사용 | ALLOW (`allowed`) | ALLOW (`allowed`) | DENY (`capability_revoked`) |
| 중간 에이전트의 최초 명령 변경 | ALLOW (`allowed`) | ALLOW (`allowed`) | DENY (`command_changed`) |
| OPA 허용 목록 밖의 로컬 파일 읽기 | ALLOW (`allowed`) | DENY (`policy_denied`) | DENY (`policy_denied`) |
| 사용자 승인 없이 파일 변경 | ALLOW (`allowed`) | REQUIRE_APPROVAL (`approval_required`) | REQUIRE_APPROVAL (`approval_required`) |
| 승인 후 쓰기 내용 변경 | ALLOW (`allowed`) | REQUIRE_APPROVAL (`approval_required`) | DENY (`approval_request_mismatch`) |
| 소모된 승인 토큰 재사용 | ALLOW (`allowed`) | REQUIRE_APPROVAL (`approval_required`) | DENY (`approval_already_used`) |
| 공통 경로 검증을 우회하는 상위 경로 읽기 | DENY (`invalid_resource`) | DENY (`invalid_resource`) | DENY (`invalid_invocation`) |
| 정상 위임 파일 읽기 | ALLOW (`allowed`) | ALLOW (`allowed`) | ALLOW (`allowed`) |
| 정상 승인 파일 쓰기 | ALLOW (`allowed`) | REQUIRE_APPROVAL (`approval_required`) | ALLOW (`allowed`) |
| OPA 실행 파일 사용 불가 | ALLOW (`allowed`) | DENY (`policy_unavailable`) | DENY (`policy_unavailable`) |

전체 방어의 서명 로그는 원본을 검증했고, 한 줄 변조와 마지막 기록 삭제를 탐지했다.
승인은 자동 입력으로 재현했고, 공격과 도구는 로컬 합성 시나리오로 실행했다.
세 조건 모두 동일한 임시 샌드박스와 경로 검증을 사용했다.
ASR과 비인가 부작용은 실제 파일 읽기 결과·변경으로 판정했다. 반복으로 공격 시나리오 수를 늘리지 않았다.
OPA만 적용한 조건은 쓰기를 승인 대기로 둔다. 서명 승인 경로는 전체 방어에 연결되어 있다.
지연에는 호출별 OPA 프로세스와 전체 방어의 인증·서명 로그 저장 시간이 포함된다. 일부 공격은 OPA에 도달하기 전에 차단되므로 정상 읽기 지연을 따로 표시했다.
장애 대조와 로그 변조는 ASR·지연 집계에서 제외했다.
