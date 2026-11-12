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
