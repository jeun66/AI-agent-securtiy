# W7 에이전트 신원과 권한 위임 실습

## 2단계 · Ed25519 `did:key`와 챌린지 검증

사용자와 에이전트는 각자 Ed25519 키쌍을 생성한다. DID에는 `ed01` Multicodec 접두어와 32바이트 공개키를 Base58BTC로 인코딩한 값이 들어간다. 검증기는 DID에서 키를 복원하고 libsodium으로 공개키의 유효성을 검사한다. [did:key 명세](https://w3c-ccg.github.io/did-key-spec/) · [libsodium 공개키 검사](https://doc.libsodium.org/advanced/point-arithmetic)

검증기는 요청한 DID와 Gateway 식별자에 임의 nonce를 묶어 챌린지를 발급한다. 사용자는 챌린지의 정해진 바이트 표현에 서명한다. 검증기는 발급 당시 보관한 챌린지로 서명을 확인하고, 성공 시 nonce를 소모하면서 인증된 DID를 반환한다. 챌린지 상태와 개인키는 이번 로컬 실습에서 프로세스 메모리에 보관한다. 인증 결과는 DID 키 소유를 증명하며, 실행 권한은 다음 단계의 자격증명·위임 정책으로 결정한다.

저장소 루트에서 1단계 가상환경을 활성화한 뒤 실행한다.

```bash
python -m pip install -r week7/requirements.txt
python -B -m pytest -q -p no:cacheprovider week7
python -B -m week7.run_identity_demo
```

사용자·에이전트의 정상 서명은 `ALLOW`로 표시된다. 다른 키로 서명한 사칭, 사용된 챌린지 재사용, 만료 후 정상 서명은 각각 `DENY`로 표시된다. 출력의 DID는 실행마다 달라진다.

## 3단계 · VC 검증과 위임 체인

허용 목록에 있는 VC 발급자가 사용자의 DID와 권한을 서명한다. 실습 VC는 VC Data Model 2.0의 기본 필드와 로컬 `AgentDelegationCredential` 프로필을 사용하며, Ed25519로 서명한 Compact JWS로 전달한다. 검증기는 이 프로필의 발급자, 대상 Gateway, 유효 기간과 서명을 확인한다. [VC Data Model 2.0](https://www.w3.org/TR/vc-data-model/) · [VC JOSE](https://www.w3.org/TR/vc-jose-cose/) · [Ed25519 JOSE 알고리즘](https://www.rfc-editor.org/rfc/rfc9864.html)

- 첫 토큰의 발급자는 VC에 기록된 사용자여야 한다. 다음 토큰의 발급자는 직전 토큰의 수신자여야 한다. 토큰은 서명된 VC와 직전 토큰의 SHA-256 해시를 포함한다.
- 권한은 행동과 리소스의 정확한 쌍이다. 하위 토큰은 부모의 권한과 유효 기간 안에서만 발급되며, 재위임 가능 깊이는 각 단계에서 줄어든다.
- 실행 요청의 최종 권한은 시스템 상한, 현재 사용자 정책, 하위 토큰 권한의 교집합이다. 검증기는 2단계에서 인증된 DID를 최종 토큰의 수신자와 대조한다.
- 사용자 정책은 축소만 할 수 있다. 상위 토큰을 회수하면 그 토큰을 포함하는 기존 하위 체인도 즉시 차단된다. 정책과 회수 상태는 로컬 검증기 프로세스 메모리에 저장한다.

저장소 루트에서 실행한다.

```bash
python -B -m pytest -q -p no:cacheprovider week7
python -B -m week7.run_delegation_demo
```

데모는 실제 Ed25519 키와 서명으로 정상 읽기, 토큰 서명 위조, 서명이 유효한 권한 확대, 정책 축소 전후, 부모 회수 후의 요청을 검증한다. 출력은 로컬 권한 판정이며 파일 접근은 4단계 Gateway와 Runtime 연결에서 확인한다.

## 4단계 · OPA, Gateway, 최초 명령 무결성

사용자가 최초 명령의 텍스트·도구·대상을 함께 서명한다. 전달자는 원본 명령 해시, 직전 링크의 해시, 송신자와 수신자를 묶어 서명한다. Gateway는 모든 서명과 전달 순서를 검증된 위임 경로와 대조하고, 최종 요청이 최초 명령과 같은지 확인한다. 에이전트의 챌린지 서명도 이 도구 요청에 묶이므로 다른 요청으로 옮기거나 재사용할 수 없다.

Gateway는 확인된 신원과 위임·명령 검증 결과만 로컬 OPA CLI에 전달한다. Rego는 기본 거부 정책으로 `note.txt` 읽기를 허용하고 쓰기는 `REQUIRE_APPROVAL`로 돌려준다. CLI 오류와 잘못된 판정은 실행 전에 차단한다. Runtime은 승인된 읽기에만 샌드박스 파일을 열고, 심볼릭 링크와 하드 링크를 거부한다. 사용자 정책 축소와 회수 변경은 진행 중인 호출의 권한 검사와 파일 실행 사이에 끼어들지 않는다. [OPA CLI](https://www.openpolicyagent.org/docs/cli)

저장소 루트에서 1단계 가상환경을 사용한다. `OPA_BIN`은 OPA 실행 파일 경로로 설정하거나, `opa`가 `PATH`에 있으면 생략한다.

```bash
"${OPA_BIN:-opa}" test -v week7/authz.rego week7/authz_test.rego
python -B -m pytest -q -p no:cacheprovider week7
python -B -m week7.run_gateway_demo
```

데모는 임시 샌드박스에서 `note.txt`를 실제로 읽고 내용 일치를 확인한다. 명령 변조, 위임 초과, Rego 정책 거부, 미승인 쓰기와 OPA 실행 실패는 `tool_invoked=false`로 출력된다. 이번 Gateway는 로컬 프로세스에서 동작한다.

## 5단계 · 고위험 작업 승인

샌드박스의 `note.txt` 덮어쓰기는 사용자 승인이 필요하다. Gateway는 작업, 대상, 실행자, 위험, 변경 내용을 검토할 수 있는 승인 요청을 반환한다. 사용자 키는 전체 도구 요청과 명령의 해시, 실행자, 대상, Gateway 인스턴스에 묶인 Ed25519 토큰을 발급한다. 승인 토큰의 유효 시간은 최대 120초다.

실행할 때는 새 챌린지로 에이전트를 인증하고 위임, 최초 명령, OPA 정책을 다시 확인한다. 승인 토큰은 쓰기 호출 직전에 소모하며, 실패한 쓰기를 다시 시도할 때도 새 승인이 필요하다. Runtime은 승인한 UTF-8 바이트를 같은 디렉터리의 임시 파일에 쓴 뒤 대상 파일을 원자적으로 교체한다. 승인과 사용 기록은 로컬 Gateway 인스턴스에 한정된다.

저장소 루트에서 1단계 가상환경으로 실행하고, 터미널의 대상과 변경 내용을 확인한 뒤 `APPROVE`를 입력한다.

```bash
python -B -m week7.run_approval_demo
```

데모는 미승인·변경된 요청·재사용을 차단하고, 승인한 원래 요청에서만 임시 파일을 실제로 바꾼다.

## 6단계 · 서명 감사 로그와 위임 경로

`SignedAuditLog`를 연결한 Gateway는 호출별 판정과 도구 실행 결과를 JSONL에 기록한다. 기록에는 인증된 DID, 요청 해시, 도구와 대상, Rego가 반환한 정책 버전, 검증한 위임 경로가 들어간다. 명령 본문, 파일 내용, VC·capability·승인 토큰 원문은 기록하지 않는다.

각 기록은 직전 SHA-256 해시를 포함하고 Ed25519로 서명된다. 실행 전 판정 기록을 저장하지 못하면 도구를 호출하지 않는다. 도구 실행 뒤 기록에 실패하면 결과 반환을 중단하고, 검증기가 실행 기록 누락을 표시한다.

서명된 체크포인트는 로그 식별자, 기록 수, 마지막 해시, 순서가 있는 머클 루트를 고정한다. 신뢰할 서명자 DID와 최신 체크포인트를 로그와 별도로 보관해야 올바른 서명이 있는 로그 뒷부분의 삭제도 탐지할 수 있다. 머클 루트는 RFC 9162의 트리 해시를 사용한다. [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1.1)

저장소 루트에서 1단계 가상환경과 `OPA_BIN`을 사용한다. 데모는 고유 폴더에 `audit.jsonl`, `checkpoint.json`, 공개 `audit-signer.did`, Mermaid 위임 경로 `delegation.md`와 변조 실험용 복사본을 남긴다.

```bash
W7_EVIDENCE=$(mktemp -d)
python -B -m week7.run_audit_demo --output-dir "$W7_EVIDENCE"
python -B -m week7.audit --audit "$W7_EVIDENCE/audit.jsonl" \
  --signer "$(cat "$W7_EVIDENCE/audit-signer.did")" \
  --checkpoint "$W7_EVIDENCE/checkpoint.json"
```

검증기는 성공 시 `0`, 해시·서명·체크포인트 불일치 시 `1`, 서명은 유효하지만 실행 결과가 빠졌을 때 `2`를 반환한다. 데모는 로컬 파일을 읽고 자동 승인된 쓰기를 실행한 뒤 원본, 한 줄 변조, 마지막 기록 삭제를 각각 검증한다.
