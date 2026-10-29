import json
from pathlib import Path
from collections import defaultdict
import re

ROOT = Path(__file__).resolve().parents[1]
REPORT = Path(__file__).resolve().parent / "results" / "w4_report_final.json"
ATTACK_DIR = ROOT / "week3" / "attacks"
SANDBOX = ROOT / "week2" / "sandbox"

OUT_TRAIN = Path(__file__).resolve().parent / "dataset_w4_train.jsonl"
OUT_REVIEW = Path(__file__).resolve().parent / "dataset_w4_review.jsonl"
OUT_SUMMARY = Path(__file__).resolve().parent / "dataset_w4_refine_summary.json"

# normalization helper (strip whitespace, lower, remove repeated spaces, normalize urls)
url_pattern = re.compile(r'https?://[^\s]+')

def normalize_text(s):
    if s is None:
        return None
    s = s.strip()
    # collapse whitespace
    s = re.sub(r'\s+', ' ', s)
    # lower non-URLs
    parts = []
    last = 0
    for m in url_pattern.finditer(s):
        parts.append(s[last:m.start()].lower())
        parts.append(s[m.start():m.end()])
        last = m.end()
    parts.append(s[last:].lower())
    return ''.join(parts)

# load report
report = json.loads(REPORT.read_text(encoding='utf-8'))

# helper to extract original payload text from fixtures
def load_payload_for_attack(name):
    # map names from run_attacks to fixture ids
    # e.g., 'json_inside_file_injection' -> find in week3/attacks files where payload_file or id matches
    for p in ATTACK_DIR.rglob('*.yaml'):
        t = p.read_text(encoding='utf-8')
        if f"id: \"{name}\"" in t or f"id: '{name}'" in t:
            # parse payload naive
            m = re.search(r'payload:\s*\|\n([\s\S]+?)(?:\n[^ \t]|$)', t)
            if m:
                return m.group(1).strip()
        # also match by payload_file
        if f"payload_file: \"{name}.txt\"" in t or f"payload_file: '{name}.txt'" in t:
            f = SANDBOX / f"{name}.txt"
            if f.exists():
                return f.read_text(encoding='utf-8')
    # fallback: try direct mapping common names
    mapping = {
        'param_escape_read_outside': 'evil.txt',
        'json_inside_file_injection': 'config.json',
        'confused_deputy_userinfo': 'n/a',
        'param_pollution_extra_prop': 'n/a',
        'schema_key_confusion': 'n/a',
        'indirect_http_injection': 'evil.txt',
    }
    fn = mapping.get(name)
    if fn and (SANDBOX / fn).exists():
        return (SANDBOX / fn).read_text(encoding='utf-8')
    return None

# Collect candidate records with original text
candidates = []

# from attacks in report: use attack 'name' to find payloads
for mode, cases in report.get('attacks', {}).items():
    for c in cases:
        name = c.get('name')
        payload_text = load_payload_for_attack(name)
        # If attack payload not found, check trace for sources or proposed args containing attacker url
        if not payload_text:
            # inspect trace for proposed args
            for step in c.get('trace', []):
                prop = step.get('proposed_args')
                if prop:
                    # prefer 'payload' like fields
                    candidate = json.dumps(prop, ensure_ascii=False)
                    payload_text = candidate
                    break
        rec = {
            'orig_id': f"{mode}:{name}",
            'family': name.split('_')[0],
            'mode': mode,
            'name': name,
            'payload_text': payload_text,
            'task_success': c.get('success', False),
        }
        candidates.append(rec)

# from normals: extract read_file contents (only if file has content)
for mode, items in report.get('normal_requests', {}).items():
    for item in items:
        name = item.get('name')
        # find read_file step with result
        payload_text = None
        for step in item.get('trace', []):
            if step.get('tool') == 'read_file' and step.get('status') == 'ok':
                payload_text = step.get('result')
                break
        rec = {
            'orig_id': f"{mode}:{name}",
            'family': name.split('_')[0],
            'mode': mode,
            'name': name,
            'payload_text': payload_text,
            'task_success': item.get('task_success', False),
        }
        candidates.append(rec)

# provenance tests: include raw if textual
for mode, items in report.get('provenance_tests', {}).items():
    for item in items:
        raw = item.get('raw')
        text = None
        if isinstance(raw, dict):
            # stringify any values
            text = json.dumps(raw, ensure_ascii=False)
        elif isinstance(raw, str):
            text = raw
        rec = {
            'orig_id': f"prov:{mode}:{item.get('test')}",
            'family': item.get('test', 'prov'),
            'mode': mode,
            'name': item.get('test'),
            'payload_text': text,
            'task_success': None,
        }
        candidates.append(rec)

# normalize texts and filter
for c in candidates:
    c['norm_text'] = normalize_text(c['payload_text']) if c['payload_text'] else None

# now group by normalized text to merge copies from different modes
by_text = defaultdict(list)
for c in candidates:
    key = c['norm_text'] if c['norm_text'] else f"__MISSING__:{c['orig_id']}"
    by_text[key].append(c)

# produce train vs review sets
train = []
review = []

# ensure family split: assign split by family deterministically
families = defaultdict(list)
for c in candidates:
    families[c['family']].append(c)
family_keys = sorted(families.keys())
# assign splits cyclically small dataset
splits = ['train','val','test']
fam_split_map = {f: splits[i % len(splits)] for i, f in enumerate(family_keys)}

# dedupe: if multiple modes share same normalized text, merge metadata but keep one record
merged = []
for key, group in by_text.items():
    # prefer record that has non-null payload_text
    primary = None
    for g in group:
        if g['payload_text']:
            primary = g
            break
    if not primary:
        primary = group[0]
    merged_rec = {
        'text': primary['payload_text'],
        'norm_text': primary['norm_text'],
        'families': list(set([g['family'] for g in group])),
        'orig_ids': [g['orig_id'] for g in group],
        'modes': list(set([g['mode'] for g in group])),
        'names': list(set([g['name'] for g in group])),
        'task_successes': list(set([g['task_success'] for g in group if g.get('task_success') is not None])),
    }
    # labeling rules
    if merged_rec['text'] is None:
        merged_rec['review_reason'] = 'missing_text'
        review.append(merged_rec)
    else:
        # if text contains attacker domain or explicit instruction -> unsafe
        if 'attacker.evil' in merged_rec['norm_text'] or 'http_get' in merged_rec['norm_text']:
            merged_rec['safety_label'] = 'unsafe'
            merged_rec['review_reason'] = None
            # assign split by first family
            f = merged_rec['families'][0]
            merged_rec['split'] = fam_split_map.get(f, 'train')
            train.append(merged_rec)
        else:
            merged_rec['safety_label'] = 'safe'
            # ambiguous cases (schema confusion) -> review
            if any(n in ('schema_key_confusion','param_pollution_extra_prop') for n in merged_rec['names']):
                merged_rec['review_reason'] = 'ambiguous_schema'
                review.append(merged_rec)
            else:
                merged_rec['review_reason'] = None
                f = merged_rec['families'][0]
                merged_rec['split'] = fam_split_map.get(f, 'train')
                train.append(merged_rec)
    merged.append(merged_rec)

# ensure family split consistency: check
family_split_issues = []
for rec in merged:
    if 'split' in rec:
        splits_for_fams = set(fam_split_map.get(f, 'train') for f in rec['families'])
        if len(splits_for_fams - {'review'}) > 1:
            family_split_issues.append({'orig_ids': rec['orig_ids'], 'family_splits': list(splits_for_fams)})

# write outputs
with OUT_TRAIN.open('w', encoding='utf-8') as fh:
    for r in train:
        fh.write(json.dumps(r, ensure_ascii=False) + '\n')
with OUT_REVIEW.open('w', encoding='utf-8') as fh:
    for r in review:
        fh.write(json.dumps(r, ensure_ascii=False) + '\n')

summary = {
    'total_before': len(candidates),
    'total_after_dedupe': len(merged),
    'unique_texts': sum(1 for r in merged if r.get('text') is not None),
    'train_count': len(train),
    'review_count': len(review),
    'family_split_issues': family_split_issues,
}

OUT_SUMMARY.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
print(json.dumps(summary, ensure_ascii=False, indent=2))
print('Wrote', OUT_TRAIN, OUT_REVIEW, OUT_SUMMARY)
