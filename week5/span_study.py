"""Synthetic output-span study helpers; offsets are Python string character offsets."""
import math

TYPES = ('person', 'resident_id', 'api_key', 'email')
TAGS = ('O',) + tuple(prefix + name for name in TYPES for prefix in ('B-', 'I-'))


def build_span_rows():
    values = {
        'train': [('김가상', '이예시'), ('000101-1000000', '000202-2000000'),
                  ('R3_CANARY_SECRET=TRAIN_A', 'R3_CANARY_SECRET=TRAIN_B'), ('train.a@example.invalid', 'train.b@example.invalid')],
        'validation': [('박연습', '최가상'), ('000303-3000000', '000404-4000000'),
                       ('R3_CANARY_SECRET=VALID_A', 'R3_CANARY_SECRET=VALID_B'), ('valid.a@example.invalid', 'valid.b@example.invalid')],
        'test': [('정연습', '윤예시'), ('000505-1000000', '000606-2000000'),
                 ('R3_CANARY_SECRET=TEST_A', 'R3_CANARY_SECRET=TEST_B'), ('test.a@example.invalid', 'test.b@example.invalid')],
    }
    templates = {'train': '합성 연습 데이터: {} / 끝.', 'validation': '가상 기록({})을 읽었다.', 'test': '검사용 [{}] 항목이다.'}
    rows = []
    for split, groups in values.items():
        for label, pair in zip(TYPES, groups):
            for index, value in enumerate(pair):
                text = templates[split].format(value)
                start = text.index(value)
                rows.append({'id': split + '_' + label + str(index), 'split': split,
                             'family_id': split + '_template', 'text': text,
                             'spans': [{'start': start, 'end': start + len(value), 'label': label}],
                             'annotation_status': 'assistant_authored_synthetic_study'})
        for index, text in enumerate({'train': ['오늘 수업은 세 시에 시작한다.', '문서를 간단히 요약했다.'],
                                       'validation': ['다음 주 일정이 확정되었다.', '파일 내용은 공개 자료다.'],
                                       'test': ['회의는 내일 오전에 열린다.', '이 표는 예제 숫자만 포함한다.']}[split]):
            rows.append({'id': split + '_normal' + str(index), 'split': split,
                         'family_id': split + '_normal', 'text': text, 'spans': [],
                         'annotation_status': 'assistant_authored_synthetic_study'})
    return rows


def token_targets(offsets, spans):
    targets = []
    previous = None
    for start, end in offsets:
        if start == end:
            targets.append(-100)
            previous = None
            continue
        overlaps = [i for i, s in enumerate(spans) if start < s['end'] and end > s['start']]
        if len(overlaps) > 1:
            raise ValueError('one token overlaps multiple entities')
        if not overlaps:
            targets.append(0)
            previous = None
        else:
            which = overlaps[0]
            prefix = 'I-' if previous == which else 'B-'
            targets.append(TAGS.index(prefix + spans[which]['label']))
            previous = which
    return targets


def decode_spans(text, offsets, tag_ids, scores, threshold=0.5):
    if not (len(offsets) == len(tag_ids) == len(scores)):
        raise ValueError('token arrays differ in length')
    if any(not isinstance(i, int) or not 0 <= i < len(TAGS) for i in tag_ids):
        raise ValueError('invalid BIO tag')
    if any(not math.isfinite(s) or not 0 <= s <= 1 for s in scores):
        raise ValueError('invalid BIO probability')
    spans, active = [], None
    def flush():
        nonlocal active
        if active is not None:
            while active['start'] < active['end'] and text[active['start']].isspace():
                active['start'] += 1
            while active['end'] > active['start'] and text[active['end']-1].isspace():
                active['end'] -= 1
            if active['end'] > active['start']:
                spans.append(active)
        active = None
    for (start, end), tag_id, score in zip(offsets, tag_ids, scores):
        if not 0 <= start <= end <= len(text):
            raise ValueError('invalid tokenizer offset')
        tag = TAGS[tag_id]
        if start == end or tag == 'O' or score < threshold:
            flush()
            continue
        label = tag[2:]
        if tag.startswith('B-') or active is None or active['label'] != label:
            flush()
            active = {'start': start, 'end': end, 'label': label, 'score': float(score)}
        else:
            active['end'] = end
            active['score'] = min(active['score'], float(score))
    flush()
    return spans


def exact_span_metrics(gold_rows, predicted_rows):
    if len(gold_rows) != len(predicted_rows):
        raise ValueError('prediction count differs from gold count')
    tp = fp = fn = 0
    for gold, predicted in zip(gold_rows, predicted_rows):
        expected = {(x['start'], x['end'], x['label']) for x in gold['spans']}
        actual = {(x['start'], x['end'], x['label']) for x in predicted}
        tp += len(expected & actual); fp += len(actual - expected); fn += len(expected - actual)
    return {'tp': tp, 'fp': fp, 'fn': fn,
            'precision': tp/(tp+fp) if tp+fp else None, 'recall': tp/(tp+fn) if tp+fn else None,
            'f1': 2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None,
            'scope': 'synthetic_study_exact_character_spans_only'}


def validate_span_rows(rows):
    ids, texts, families = set(), set(), {}
    counts = {key: 0 for key in ('train', 'validation', 'test')}
    for row in rows:
        split = row['split']
        if split not in counts or row['annotation_status'] != 'assistant_authored_synthetic_study':
            raise ValueError('invalid span dataset scope')
        text = row['text']
        if row['id'] in ids or text in texts or not text:
            raise ValueError('duplicate/empty span example')
        if families.setdefault(row['family_id'], split) != split:
            raise ValueError('span family leakage')
        last_end = 0
        for span in sorted(row['spans'], key=lambda s: s['start']):
            if span['label'] not in TYPES or not last_end <= span['start'] < span['end'] <= len(text):
                raise ValueError('invalid span bounds, type or overlap')
            last_end = span['end']
        ids.add(row['id']); texts.add(text); counts[split] += 1
    if any(n == 0 for n in counts.values()):
        raise ValueError('empty span dataset split')
    return counts
