"""Train an educational BIO token head on the SAME frozen encoder as the classifier.

This is a custom shared-encoder teaching model, not pretrained GLiNER or end-to-end
joint training. Classification heads were fine-tuned separately in train_study.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import random
from week5.evaluate_study import verify_study_checkpoint
from week5.run_zero_shot import load_local_model, AuditedPipeline, run_pipeline_probe
from week5.model_adapters import GLiClassGuard
from week5.guards import Finding, GuardResult, GuardRequest
from week5.span_study import TAGS, build_span_rows, token_targets, decode_spans, exact_span_metrics, validate_span_rows


class SharedStudyGuard:
    kind = 'model'
    name = 'educational-shared-encoder-classification-span'

    def __init__(self, pipe, head):
        self.pipe, self.head = pipe, head
        self.encoder = pipe.pipe.model.model.encoder_model
        self.class_guard = GLiClassGuard(AuditedPipeline(pipe), model_id='synthetic-study-head')

    def spans(self, text):
        import torch
        encoded = self.pipe.pipe.tokenizer(text, return_offsets_mapping=True, truncation=True,
                                           max_length=256, return_tensors='pt')
        offsets = encoded.pop('offset_mapping')[0].tolist()
        with torch.inference_mode():
            features = self.encoder(**encoded).last_hidden_state
            probs = torch.softmax(self.head(features)[0], dim=-1)
            scores, labels = probs.max(dim=-1)
        return decode_spans(text, offsets, labels.tolist(), scores.tolist())

    def check(self, request):
        if request.direction == 'input':
            result = self.class_guard.check(request)
            return GuardResult(result.decision, self.name, self.kind, result.findings)
        hits = tuple(Finding(s['label'], s['score'], s['start'], s['end']) for s in self.spans(request.text))
        return GuardResult('block' if hits else 'allow', self.name, self.kind, hits, 'synthetic_span_head')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--classification-checkpoint', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('output must be a new directory')
    snapshot, classification_report = verify_study_checkpoint(args.classification_checkpoint)
    pipe, info = load_local_model(snapshot, 2)
    import torch
    from safetensors.torch import save_file
    torch.manual_seed(42)
    rng = random.Random(42)
    base = pipe.pipe.model
    for p in base.parameters():
        p.requires_grad_(False)
    base.eval()
    encoder = base.model.encoder_model
    head = torch.nn.Linear(base.config.encoder_config.hidden_size, len(TAGS))
    before = {k: v.detach().clone() for k, v in head.state_dict().items()}
    rows = build_span_rows()
    validate_span_rows(rows)
    splits = {s: [r for r in rows if r['split'] == s] for s in ('train', 'validation', 'test')}
    cache = {}
    with torch.inference_mode():
        for row in rows:
            encoded = pipe.pipe.tokenizer(row['text'], return_offsets_mapping=True, truncation=True,
                                          max_length=256, return_tensors='pt')
            offsets = encoded.pop('offset_mapping')[0].tolist()
            features = encoder(**encoded).last_hidden_state[0]
            targets = torch.tensor(token_targets(offsets, row['spans']), dtype=torch.long)
            cache[row['id']] = (features.clone(), targets)
    # Inference tensors are copied outside inference_mode before autograd uses them.
    cache = {key: (x.clone(), y.clone()) for key, (x, y) in cache.items()}
    weights = torch.tensor([0.25] + [1.0] * (len(TAGS)-1))
    def loss_for(row):
        features, targets = cache[row['id']]
        return torch.nn.functional.cross_entropy(head(features), targets, weight=weights, ignore_index=-100)
    optimizer = torch.optim.AdamW(head.parameters(), lr=1e-3)
    best, best_epoch, selected = float('inf'), None, None
    history, steps = [], 0
    for epoch in range(1, 21):
        order = list(splits['train']); rng.shuffle(order)
        losses = []
        for row in order:
            optimizer.zero_grad(set_to_none=True)
            loss = loss_for(row)
            if not torch.isfinite(loss):
                raise RuntimeError('nonfinite span loss')
            loss.backward(); optimizer.step(); steps += 1
            losses.append(float(loss.detach()))
        with torch.no_grad():
            validation_loss = sum(float(loss_for(r)) for r in splits['validation']) / len(splits['validation'])
        if validation_loss < best:
            best, best_epoch = validation_loss, epoch
            selected = {k: v.detach().clone() for k, v in head.state_dict().items()}
        history.append({'epoch': epoch, 'train_loss': sum(losses)/len(losses), 'validation_loss': validation_loss})
    head.load_state_dict(selected); head.eval()
    changed = [k for k, v in head.state_dict().items() if not torch.equal(v, before[k])]
    if not changed:
        raise RuntimeError('no span parameter update')
    guard = SharedStudyGuard(pipe, head)
    predictions = [guard.spans(r['text']) for r in splits['test']]
    metrics = exact_span_metrics(splits['test'], predictions)
    # Both input and output hooks share this ONE encoder instance.
    from week5.defense import DefenseHook
    hook = DefenseHook(guard, guard)
    same_encoder = hook.input_guard.encoder is hook.output_guard.encoder
    probes = [{'id': r['id'], 'guard': hook.check('output', r['text'])} for r in splits['test']]
    args.output.mkdir(parents=True)
    save_file(head.state_dict(), str(args.output / 'span_head.safetensors'))
    report = {'evidence': {'run_kind': 'actual_cpu_span_head_training', 'training_executed': True,
                           'mock_training': False, 'encoder_frozen': True, 'encoder_instances': 1,
                           'same_encoder_for_input_and_output': same_encoder,
                           'joint_end_to_end_training': False, 'gliner_package_used': False,
                           'created_at_utc': datetime.now(timezone.utc).isoformat()},
              'classification_checkpoint': str(snapshot),
              'classification_weight_sha256': classification_report['trained_weight_sha256'],
              'encoder': info, 'tag_map': list(TAGS), 'epochs': 20, 'optimizer_steps': steps,
              'trainable_parameters': sum(p.numel() for p in head.parameters()),
              'changed_tensors': changed, 'best_epoch': best_epoch, 'history': history,
              'splits': {s: len(v) for s, v in splits.items()},
              'synthetic_test_exact_spans': metrics, 'output_guard_probes': probes,
              'synthetic_test_predictions': [{'id': row['id'], 'gold_spans': row['spans'], 'predicted_spans': predicted}
                                             for row, predicted in zip(splits['test'], predictions)],
              'span_head_sha256': hashlib.sha256((args.output / 'span_head.safetensors').read_bytes()).hexdigest(),
              'benchmark_f1': None, 'deployment_validated': False}
    (args.output / 'span_report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print('TRAINING=true MOCK_TRAINING=false TASK=synthetic_BIO_span_head')
    print('ENCODER_INSTANCES=1 SAME_ENCODER_INPUT_OUTPUT=' + str(same_encoder).lower())
    print('OPTIMIZER_STEPS=' + str(steps) + ' CHANGED_TENSORS=' + str(len(changed)))
    print('SYNTHETIC_TEST_EXACT_SPANS=' + json.dumps(metrics, sort_keys=True))
    print('GLINER_PACKAGE_USED=false JOINT_END_TO_END_TRAINING=false BENCHMARK_F1=null')
    print('REPORT=' + str(args.output / 'span_report.json'))


if __name__ == '__main__':
    main()
