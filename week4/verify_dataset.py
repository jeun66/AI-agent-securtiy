import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
TRAIN = Path(__file__).resolve().parent / "dataset_w4_train.jsonl"
REVIEW = Path(__file__).resolve().parent / "dataset_w4_review.jsonl"
ATTACK_DIR = ROOT / "week3" / "attacks"
SANDBOX = ROOT / "week2" / "sandbox"
SCHEMA = Path(__file__).resolve().parent / "label_schema.md"
SUMMARY = Path(__file__).resolve().parent / "dataset_w4_refine_summary.json"

url_pattern = re.compile(r'https?://[^\s\}]+')

def normalize_text(s):
    if s is None:
        return None
    s = s.strip()
    s = re.sub(r'\s+', ' ', s)
    parts = []
    last = 0
    for m in url_pattern.finditer(s):
        parts.append(s[last:m.start()].lower())
        parts.append(s[m.start():m.end()])
        last = m.end()
    parts.append(s[last:].lower())
    return ''.join(parts)

# load entries
train = [json.loads(line) for line in TRAIN.read_text(encoding='utf-8').splitlines() if line.strip()]
review = [json.loads(line) for line in REVIEW.read_text(encoding='utf-8').splitlines() if line.strip()]

# helper: map name -> yaml path and payload_file

def find_fixture_for_name(name):
    for p in ATTACK_DIR.rglob('*.yaml'):
        t = p.read_text(encoding='utf-8')
        # id match
        if re.search(r"id:\s*\"?%s\"?" % re.escape(name), t):
            # find payload_file
            m_pf = re.search(r"payload_file:\s*\"?([\w\-\.]+)\"?", t)
            pf = m_pf.group(1) if m_pf else None
            return str(p), pf
        # payload_file mention
        if re.search(r"payload_file:\s*\"?%s\"?" % re.escape(f"{name}.txt"), t):
            m_pf = re.search(r"payload_file:\s*\"?([\w\-\.]+)\"?", t)
            pf = m_pf.group(1) if m_pf else None
            return str(p), pf
    return None, None

# Build result list for train entries
results = []
for i, rec in enumerate(train, 1):
    primary_id = rec.get('orig_ids', [None])[0]
    # attempt to infer file locations from orig_ids
    file_locations = set()
    for oid in rec.get('orig_ids', []):
        if oid.startswith('prov:'):
            file_locations.add('provenance_test')
            continue
        parts = oid.split(':', 1)
        if len(parts) == 2:
            mode, name = parts
        else:
            name = oid
        yaml_path, payload_file = find_fixture_for_name(name)
        if yaml_path:
            file_locations.add(yaml_path)
            if payload_file:
                sandbox_path = SANDBOX / payload_file
                if sandbox_path.exists():
                    file_locations.add(str(sandbox_path))
                else:
                    file_locations.add(str((SANDBOX / payload_file)))
        else:
            # map known normals
            if name.startswith('normal_'):
                # try note.txt
                note = SANDBOX / 'note.txt'
                if note.exists():
                    file_locations.add(str(note))
                else:
                    file_locations.add(str(note))
            elif name in ('json_inside_file_injection',):
                file_locations.add(str(SANDBOX / 'config.json'))
            else:
                # fallback: include orig_id
                file_locations.add(f'unknown_fixture_for:{name}')
    norm = normalize_text(rec.get('text'))
    results.append({
        'id': primary_id,
        'orig_ids': rec.get('orig_ids'),
        'text': rec.get('text'),
        'norm_text': norm,
        'file_locations': sorted(list(file_locations)),
        'safety_label': rec.get('safety_label'),
        'attack_categories': rec.get('names'),
        'family_id': rec.get('families')[0] if rec.get('families') else None,
        'split': rec.get('split'),
        'review_status': 'auto-draft' if rec.get('review_reason') is None else 'needs_review'
    })

# 1) print 7 training candidates
print('\n=== Training candidates (7) ===\n')
for r in results:
    print(json.dumps({
        'id': r['id'],
        'orig_ids': r['orig_ids'],
        'text': r['text'],
        'file_locations': r['file_locations'],
        'safety_label': r['safety_label'],
        'attack_categories': r['attack_categories'],
        'family_id': r['family_id'],
        'split': r['split'],
        'review_status': r['review_status']
    }, ensure_ascii=False, indent=2))

# 2) check normalized text duplicates within train
norms = [r['norm_text'] for r in results if r['norm_text']]
dupe_norms = [n for n in set(norms) if norms.count(n) > 1]
print('\nNormalized text duplicates in train (should be 0):', len(dupe_norms))
if dupe_norms:
    print(dupe_norms)

# 3) check train vs review for same text or conflicting labels
review_norm_map = {}
for r in review:
    nt = normalize_text(r.get('text')) if r.get('text') else None
    if nt:
        review_norm_map[nt] = r

conflicts = []
common_texts = []
for r in results:
    nt = r['norm_text']
    if nt and nt in review_norm_map:
        common_texts.append(nt)
        # compare safety_label
        train_label = r['safety_label']
        rev_label = review_norm_map[nt].get('safety_label')
        if rev_label and train_label != rev_label:
            conflicts.append({'norm_text': nt, 'train_label': train_label, 'review_label': rev_label})

print('\nTrain/Review common texts count:', len(common_texts))
if conflicts:
    print('Conflicting labels:')
    print(json.dumps(conflicts, ensure_ascii=False, indent=2))
else:
    print('No conflicting labels between train and review')

# 4) label and split distributions
from collections import Counter
labels = Counter([r['safety_label'] for r in results])
splits = Counter([r['split'] for r in results])
print('\nLabel distribution (train):', dict(labels))
print('Split distribution (train):', dict(splits))

# review reasons counts
review_reasons = Counter()
for r in review:
    # parse review reason from earlier structure if present
    rr = r.get('review_reason') or r.get('review_reason')
    if rr:
        review_reasons[rr] += 1
    else:
        # detect missing text
        if not r.get('text'):
            review_reasons['missing_text'] += 1
        else:
            review_reasons['other'] += 1
print('\nReview reasons counts (from review file):', dict(review_reasons))

# Ensure auto-draft preserved in train
print('\nAll train items review_status should be auto-draft:')
for r in results:
    print(r['id'], '->', r['review_status'])

# Update label_schema.md and summary to reflect final counts
schema_md = SCHEMA.read_text(encoding='utf-8')
new_schema = schema_md + '\n\n## Dataset status\n- Total raw cases before dedupe: 39\n- Total cases after dedupe: 20\n- Unique original-texts: 8\n- Training candidates: 7\n- Review candidates (needs human review): 13\n\nNote: This dataset is small and intended as a draft. Keep `needs_review` items separate until human validation.\n'
SCHEMA.write_text(new_schema, encoding='utf-8')

summary = {
    'total_before': 39,
    'total_after_dedupe': 20,
    'unique_original_texts': 8,
    'train_count': len(results),
    'review_count': len(review)
}
SUMMARY.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')

print('\nUpdated label schema and summary files.')

# Suggest commit message
commit_msg = 'chore: finalize W4 dataset draft (7 train, 13 review) — dedupe 39→20, unique_texts=8'
print('\nSuggested commit message:\n', commit_msg)
