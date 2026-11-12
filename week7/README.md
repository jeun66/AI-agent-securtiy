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
