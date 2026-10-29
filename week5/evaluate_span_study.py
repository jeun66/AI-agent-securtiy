"""Reload the synthetic span head and classifier, then exercise both shared hooks."""
import argparse
import hashlib
import json
from pathlib import Path
from week5.evaluate_study import verify_study_checkpoint
from week5.run_zero_shot import load_local_model
from week5.span_study import TAGS, build_span_rows, validate_span_rows, exact_span_metrics
from week5.train_span_study import SharedStudyGuard


def load_shared_guard(directory):
    directory = Path(directory)
    report = json.loads((directory / 'span_report.json').read_text())
    if not report['evidence']['training_executed'] or report['evidence']['mock_training']:
        raise ValueError('actual span training report required')
    if report['tag_map'] != list(TAGS):
        raise ValueError('unexpected BIO tag map')
    if hashlib.sha256((directory / 'span_head.safetensors').read_bytes()).hexdigest() != report['span_head_sha256']:
        raise ValueError('span head checksum mismatch')
    snapshot, classification = verify_study_checkpoint(report['classification_checkpoint'])
    if classification['trained_weight_sha256'] != report['classification_weight_sha256']:
        raise ValueError('classification checkpoint differs from the span training encoder')
    pipe, _ = load_local_model(snapshot, 2)
    import torch
    from safetensors.torch import load_file
    head = torch.nn.Linear(pipe.pipe.model.config.encoder_config.hidden_size, len(TAGS))
    head.load_state_dict(load_file(str(directory / 'span_head.safetensors')))
    head.eval()
    return SharedStudyGuard(pipe, head), report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--span-checkpoint', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    guard, training = load_shared_guard(args.span_checkpoint)
    all_rows = build_span_rows(); validate_span_rows(all_rows)
    rows = [r for r in all_rows if r['split'] == 'test']
    predicted = [guard.spans(r['text']) for r in rows]
    recorded = training['synthetic_test_predictions']
    if len(recorded) != len(rows):
        raise RuntimeError('recorded span test count differs from fixture count')
    for row, current, saved in zip(rows, predicted, recorded):
        if row['id'] != saved['id'] or len(current) != len(saved['predicted_spans']):
            raise RuntimeError('saved span model did not reproduce test predictions')
        for a, b in zip(current, saved['predicted_spans']):
            if (a['start'], a['end'], a['label']) != (b['start'], b['end'], b['label']) or abs(a['score']-b['score']) > 1e-5:
                raise RuntimeError('saved span model prediction mismatch')
    from week5.defense import DefenseHook
    from week4.run_attacks import FakeToolCall
    from week2 import agent_tools
    hook = DefenseHook(guard, guard)
    probes = []
    url = 'https://study.example/info'
    original = agent_tools.MOCK_PAGES[url]
    try:
        for name, text in [('clean_output', rows[-1]['text']), ('synthetic_person_output', rows[0]['text'])]:
            agent_tools.MOCK_PAGES[url] = text
            agent_tools.TRACE.clear(); agent_tools.reset_mock_counters()
            agent_tools.execute_tool_with_mode(
                FakeToolCall('http_get', {'url': url}), mode='policy+taint+guard',
                defense_hook=hook, input_text='이 문서를 한국어로 요약해줘.')
            probes.append({'case': name, 'trace': agent_tools.TRACE[-1],
                           'mock_tool_calls': dict(agent_tools.MOCK_CALL_COUNT)})
    finally:
        agent_tools.MOCK_PAGES[url] = original
    report = {'evidence': {'model_inference_executed': True, 'mock_guard': False,
                           'tools_are_mock': True, 'real_http': False, 'real_mcp': False,
                           'encoder_instances': 1, 'classification_and_span_share_encoder': True,
                           'training_executed_in_this_command': False},
              'synthetic_span_metrics': exact_span_metrics(rows, predicted),
              'saved_predictions_reproduced': True, 'pipeline_probes': probes,
              'benchmark_f1': None, 'deployment_validated': False}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print('MODEL_INFERENCE=true MOCK_GUARD=false ENCODER_INSTANCES=1 TOOLS_ARE_MOCK=true')
    print('SAVED_SPAN_PREDICTIONS_REPRODUCED=true')
    print('SYNTHETIC_SPAN_METRICS=' + json.dumps(report['synthetic_span_metrics'], sort_keys=True))
    for probe in probes:
        trace = probe['trace']
        print('CASE=' + probe['case'] + ' STATUS=' + trace['status']
              + ' TOOL_EXECUTED=' + str(trace['tool_executed']).lower()
              + ' OUTPUT_RELEASED=' + str(trace['output_released']).lower())
    print('BENCHMARK_F1=null DEPLOYMENT_VALIDATED=false')
    print('REPORT=' + str(args.output))


if __name__ == '__main__':
    main()
