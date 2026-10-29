"""Reproduce actual inference diagnostics without modifying installed model packages."""
import argparse
from contextlib import contextmanager
import importlib.metadata
import json
from pathlib import Path
import types
from week5.model_adapters import GLiClassGuard
from week5.run_zero_shot import binary_metrics, load_local_model, load_samples, verify_manifest


@contextmanager
def diagnostic_variant(backend, variant):
    original_prepare = backend.prepare_input
    original_flag = backend.model.config.embed_class_token
    if variant not in ('installed', 'next_token', 'published_0.1.0_format'):
        raise ValueError('unknown diagnostic variant')
    try:
        if variant == 'next_token':
            backend.model.config.embed_class_token = False
        elif variant == 'published_0.1.0_format':
            # GLiClass 0.1.0 published wheel: each label has a separator, then text.
            # This is a diagnostic input format, not an automatic compatibility fix.
            def prepare(self, text, labels, examples=None, prompt=None):
                return ''.join('<<LABEL>>' + label + '<<SEP>>' for label in labels) + text
            backend.prepare_input = types.MethodType(prepare, backend)
        yield
    finally:
        backend.prepare_input = original_prepare
        backend.model.config.embed_class_token = original_flag


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model-manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if importlib.metadata.version('gliclass') != '0.1.21':
        raise ValueError('diagnostic was written for the pinned GLiClass 0.1.21 package')
    snapshot, manifest = verify_manifest(args.model_manifest)
    pipe, info = load_local_model(snapshot, 2)
    samples = load_samples(Path(__file__).with_name('fixtures') / 'zero_shot_smoke.jsonl')
    variants = []
    for variant in ('installed', 'next_token', 'published_0.1.0_format'):
        rows = []
        with diagnostic_variant(pipe.pipe, variant):
            control = pipe('One day I will see the world!',
                           ['travel', 'dreams', 'sport', 'science', 'politics'], threshold=0.0)
            for sample in samples:
                scores = {r['label']: float(r['score']) for r in pipe(
                    sample['text'] + '\n', list(GLiClassGuard.labels), threshold=0.0)[0]}
                block = any(value >= 0.5 for label, value in scores.items() if label != 'benign')
                rows.append({'id': sample['id'], 'expected_label': sample['expected_label'],
                             'decision': 'block' if block else 'allow', 'all_scores': scores})
        variants.append({'variant': variant, 'topical_control': control, 'cases': rows,
                         'synthetic_metrics': binary_metrics(rows)})
    report = {'evidence': {'run_kind': 'actual_local_model_diagnostics', 'mock': False,
                           'training_executed': False, 'package_modified': False},
              'revision': manifest['revision'], 'model': info, 'threshold': 0.5,
              'variants': variants, 'root_cause_determined': False,
              'deployment_validated': False}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    for row in variants:
        print('VARIANT=' + row['variant'] + ' SYNTHETIC_METRICS=' + json.dumps(row['synthetic_metrics'], sort_keys=True))
    print('ROOT_CAUSE_DETERMINED=false PACKAGE_MODIFIED=false TRAINING=false')
    print('REPORT=' + str(args.output))


if __name__ == '__main__':
    main()
