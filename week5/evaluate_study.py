"""Compare base and trained heads on the same eight synthetic study test cases."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from week5.model_adapters import GLiClassGuard
from week5.study_data import load_rows
from week5.run_zero_shot import (AuditedPipeline, binary_metrics, load_local_model,
                                run_measurements, run_pipeline_probe, verify_manifest)
from week5.run_demo import latency_stats


def verify_study_checkpoint(path):
    path = Path(path).resolve()
    report = json.loads((path / 'study_report.json').read_text(encoding='utf-8'))
    if not report['evidence']['training_executed'] or report['evidence']['mock_training']:
        raise ValueError('an actual training report is required')
    digest = hashlib.sha256()
    with (path / 'model.safetensors').open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    if digest.hexdigest() != report['trained_weight_sha256']:
        raise ValueError('trained checkpoint checksum mismatch')
    return path, report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--variant', choices=('base', 'trained'), required=True)
    parser.add_argument('--model-manifest', type=Path)
    parser.add_argument('--trained-model', type=Path)
    parser.add_argument('--data', type=Path, default=Path(__file__).with_name('fixtures') / 'study_classification.jsonl')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--threads', type=int, default=2)
    parser.add_argument('--repeats', type=int, default=5)
    args = parser.parse_args()
    if args.threads < 1 or args.repeats < 1:
        parser.error('threads and repeats must be positive')
    data = load_rows(args.data)
    test = [{'id': r['id'], 'text': r['text'], 'language': 'study', 'expected_label': r['label']}
            for r in data if r['split'] == 'test']
    training = None
    if args.variant == 'base':
        if args.model_manifest is None:
            parser.error('base requires --model-manifest')
        snapshot, manifest = verify_manifest(args.model_manifest)
        identity = manifest['model_id'] + '@' + manifest['revision']
    else:
        if args.trained_model is None:
            parser.error('trained requires --trained-model')
        snapshot, training = verify_study_checkpoint(args.trained_model)
        identity = 'study-head:' + training['trained_weight_sha256']
        if training['data_sha256'] != hashlib.sha256(args.data.read_bytes()).hexdigest():
            raise ValueError('study evaluation data differ from training report')
    pipe, model_info = load_local_model(snapshot, args.threads)
    audited = AuditedPipeline(pipe)
    guard = GLiClassGuard(audited, model_id=identity)
    cases, times = run_measurements(guard, audited, test, args.repeats, warmup=1)
    measured_and_warmup = audited.calls
    probes = run_pipeline_probe(guard, audited)
    if training is not None:
        expected = training['after_training']['test']['cases']
        for current, saved in zip(cases, expected):
            if current['id'] != saved['id'] or current['decision'] != saved['decision']:
                raise RuntimeError('saved checkpoint does not reproduce recorded test decisions')
            if any(abs(current['all_scores'][label] - saved['all_scores'][label]) > 1e-5 for label in guard.labels):
                raise RuntimeError('saved checkpoint scores differ from the training report')
    report = {'evidence': {'run_kind': 'actual_local_model_inference', 'variant': args.variant,
                           'mock_guard': False, 'model_inference_executed': True, 'real_http': False,
                           'real_mcp': False, 'llm_generation': False, 'training_executed_in_this_command': False,
                           'data_kind': 'assistant_authored_synthetic_study',
                           'created_at_utc': datetime.now(timezone.utc).isoformat()},
              'model': dict(model_info, identity=identity),
              'data_sha256': hashlib.sha256(args.data.read_bytes()).hexdigest(),
              'threshold': 0.5, 'cases': cases, 'latency': latency_stats(times),
              'synthetic_test_metrics': binary_metrics(cases),
              'forwards': {'warmup': 8, 'measured': len(times), 'pipeline_probe': audited.calls - measured_and_warmup},
              'pipeline_probe': probes, 'checkpoint_reloaded_and_verified': training is not None,
              'benchmark_f1': None, 'deployment_validated': False}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print('RUN_KIND=actual_local_model_inference VARIANT=' + args.variant + ' MOCK_GUARD=false')
    print('SYNTHETIC_TEST=' + json.dumps(report['synthetic_test_metrics'], sort_keys=True))
    print('CPU_LATENCY=' + json.dumps(report['latency'], sort_keys=True))
    print('CHECKPOINT_RELOADED_AND_VERIFIED=' + str(training is not None).lower())
    for row in cases:
        print('CASE=' + row['id'] + ' EXPECTED=' + row['expected_label'] + ' DECISION=' + row['decision'])
    for row in probes:
        print('PIPELINE=' + row['case'] + ' MODEL_CALLS=' + str(row['model_forward_passes'])
              + ' TOOL_EXECUTED=' + str(row['trace']['tool_executed']).lower()
              + ' OUTPUT_RELEASED=' + str(row['trace']['output_released']).lower())
    print('BENCHMARK_F1=null DEPLOYMENT_VALIDATED=false')
    print('REPORT=' + str(args.output))


if __name__ == '__main__':
    main()
