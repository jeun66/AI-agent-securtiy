# 리뷰어3 모델 비교 — 평가 데이터

2026-11-05 사용자가 채팅에서 **"검토 완료"**로 24개 후보의 라벨·근거를 승인했다. `eval.jsonl`로 확정하고 해시를 고정했다. 데이터 검토·검사 완료이며 실제 모델 평가 완료를 뜻하지 않는다.

## 파일과 상태

- `eval.jsonl`: 검토 완료한 합성 평가 자료. 정상 12개, 인젝션·탈옥·시스템 프롬프트 추출 각 4개. 한국어/영어 각 12개.
- `eval.candidate.jsonl`: 최초 후보를 수정 없이 보존. pending은 당시 기록이며 최종 평가에는 사용하지 않는다.
- `REVIEW.md`: 문장·예상 라벨·근거와 사용자 승인 안내.
- `data_manifest.json`: 파일 SHA-256, 승인 메시지·시각·대상 해시, 원본 출처.
- `provenance/exclusion_corpus.jsonl`: 기존 프로젝트에서 노출된 텍스트 138개의 배제 스냅샷.
- `validate_data.py`: Python 3.9+ 표준 라이브러리로 동작하는 검사기. 설치·모델 다운로드 없음.

각 승인 기록은 문장·라벨·출처·근거를 포함하는 `reviewed_record_sha256`에 연결된다. 변경 시 재검토하고 최종 파일 해시도 다시 고정한다. 채팅 사용자 검토는 독립 전문가나 여러 명의 주석 검증을 뜻하지 않는다.

## 범위와 한계

`benign`을 0, 나머지를 1로 매핑하는 **입력 텍스트 악성 여부** 평가다. 정책 차단이나 공격 성공을 정답으로 사용하지 않는다. 인용문 분석, 공개 프롬프트 편집, 무해한 역할극, 공개 문자열 인코딩은 정상 사례다. 출력 PII span과 agent ASR은 별도다.

정상/공격 12/12는 실제 서비스의 공격 비율을 반영하지 않는다. 한국어/영어 쌍은 같은 source_id/family_id이며 **24개 문장·12개 원본 그룹**이다. 작은 AI 작성 합성 자료로 일반화·운영 성능을 주장하지 않는다. 평가 자료를 학습·임계값·모델 선택에 사용하지 않는다.

## 출처 분리

원격 기준은 `77dc67e3ebd08f809598e25833ea66e7e1b5413a`다. 그 커밋의 W4 JSONL 3개, W3 공격/정상 YAML의 payload와 user_request, W2 sandbox 텍스트를 배제했다. 당시 원격 main에 없던 로컬 zero-shot 8개, 분류 공부용 train/validation/test 32개, span 공부용 train/validation/test 30개도 포함한다. 원본 위치·스냅샷 해시는 manifest에 보존했다.

Unicode NFKC·대소문자·공백·문장부호 정규화로 동일 문장을 검사한다. 20자 이상은 SequenceMatcher 비율 0.86 이상, 40자 이상의 포함 관계도 차단한다. 기존 source_id/family_id와의 충돌도 검사한다.

이 검사는 알려진 프로젝트 자료를 대상으로 한다. 새로운 ID만으로 독립성이 증명되지 않으며 의미상 같은 템플릿, 번역, 모델 사전학습 데이터와의 완전한 비중복을 보장하지 않는다. 이 한계를 결과 보고서에도 유지한다.

## 직접 실행·기록

저장소 루트에서 실행한다. 추가 패키지는 필요 없다.

```bash
python3 --version
python3 -B -m unittest -v guardrail.test_data
python3 -B -m guardrail.validate_data --mode benchmark --output /tmp/r3-benchmark-data-check.json
```

최종 검증은 종료 코드 0, `rows: 24`, `approved_rows: 24`, `pending_rows: 0`, `ready_for_benchmark: true`다. 최초 후보 검사도 유지된다.

```bash
python3 -B -m guardrail.validate_data --mode candidate
```

후보 검사는 `pending_rows: 24`, `ready_for_benchmark: false`가 정상이다. 실제 평가기는 최종 `eval.jsonl`과 benchmark 검사만 사용한다.

GLiClass 원본 zero-shot과 이전 공부용 head 학습 체크포인트는 다른 실험으로 구분한다. 모델 설치·실제 3모델 측정은 별도 단계다.

공통 평가기와 규칙/mock 검증 명령은 [BENCHMARK.md](BENCHMARK.md)에 있다. 모델 성능·실제 모델 지연으로 해석하지 않는다.

3단계의 GLiClass 원본·학습형과 Laya 실제 측정 결과, 12B 메모리 미실행 상태, 사용자 재현 명령은 [MODEL_RESULTS.md](MODEL_RESULTS.md)에 있다. 전체 세 모델 비교 완료로 간주하지 않는다.
