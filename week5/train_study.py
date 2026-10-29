"""Offline CPU classification-head fine-tuning on a tiny synthetic teaching dataset.

This explicit PyTorch loop exposes optimizer steps. It is not the GLiClass Trainer
example, joint span learning, or a production guardrail training run.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import random
import time
from week5.model_adapters import GLiClassGuard
from week5.study_data import load_rows, validate_rows
from week5.run_zero_shot import load_local_model, verify_manifest, binary_metrics


def require_new_output(path, snapshot):
    path, snapshot = Path(path).resolve(), Path(snapshot).resolve()
    if path.exists() or path == snapshot or path.is_relative_to(snapshot) or snapshot.is_relative_to(path):
        raise ValueError('training output must be a new directory outside the source snapshot')
    return path


def evaluate(pipe, rows, torch):
    model = pipe.pipe.model
    model.eval()
    labels = list(GLiClassGuard.labels)
    results, losses = [], []
    with torch.inference_mode():
        for row in rows:
            inputs = pipe.pipe.prepare_inputs([row['text'] + '\n'], labels, same_labels=True)
            logits = model(**inputs, max_num_classes=len(labels)).logits
            targets = torch.tensor([[float(label == row['label']) for label in labels]])
            losses.append(float(torch.nn.functional.binary_cross_entropy_with_logits(logits, targets)))
            scores = torch.sigmoid(logits[0]).tolist()
            block = any(score >= 0.5 for label, score in zip(labels, scores) if label != 'benign')
            results.append({'id': row['id'], 'expected_label': row['label'],
                            'decision': 'block' if block else 'allow',
                            'all_scores': dict(zip(labels, scores))})
    return {'mean_bce_loss': sum(losses) / len(losses),
            'synthetic_binary_metrics': binary_metrics(results), 'cases': results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model-manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--data', type=Path, default=Path(__file__).with_name('fixtures') / 'study_classification.jsonl')
    parser.add_argument('--epochs', type=int, default=5)
    parser.add_argument('--batch-size', type=int, default=2)
    parser.add_argument('--learning-rate', type=float, default=2e-5)
    parser.add_argument('--threads', type=int, default=2)
    args = parser.parse_args()
    if args.epochs < 1 or args.batch_size < 1 or args.threads < 1 or not math.isfinite(args.learning_rate) or args.learning_rate <= 0:
        parser.error('invalid training configuration')
    rows = load_rows(args.data)
    splits = {split: [r for r in rows if r['split'] == split] for split in ('train', 'validation', 'test')}
    snapshot, manifest = verify_manifest(args.model_manifest)
    output = require_new_output(args.output, snapshot)
    pipe, model_info = load_local_model(snapshot, args.threads)
    import torch
    model = pipe.pipe.model
    torch.manual_seed(42)
    rng = random.Random(42)
    for name, parameter in model.named_parameters():
        parameter.requires_grad_('text_projector.' in name or 'classes_projector.' in name)
    trainable = {name: value for name, value in model.named_parameters() if value.requires_grad}
    if not trainable:
        raise RuntimeError('no trainable classification-head parameters')
    before_head = {name: value.detach().clone() for name, value in trainable.items()}
    labels = list(GLiClassGuard.labels)
    optimizer = torch.optim.AdamW(trainable.values(), lr=args.learning_rate, weight_decay=0.01)
    baseline = {'validation': evaluate(pipe, splits['validation'], torch),
                'test': evaluate(pipe, splits['test'], torch)}
    best_loss, best_epoch, best_head = float('inf'), None, None
    history, optimizer_steps = [], 0
    started = time.perf_counter()
    for epoch in range(1, args.epochs + 1):
        model.train()
        model.model.encoder_model.eval()  # Frozen encoder: preserve its inference-mode behavior.
        order = list(splits['train'])
        rng.shuffle(order)
        train_losses = []
        for index in range(0, len(order), args.batch_size):
            batch = order[index:index + args.batch_size]
            inputs = pipe.pipe.prepare_inputs([r['text'] + '\n' for r in batch], labels, same_labels=True)
            targets = torch.tensor([[float(label == row['label']) for label in labels] for row in batch])
            optimizer.zero_grad(set_to_none=True)
            logits = model(**inputs, max_num_classes=len(labels)).logits
            loss = torch.nn.functional.binary_cross_entropy_with_logits(logits, targets)
            if not torch.isfinite(loss):
                raise RuntimeError('nonfinite training loss')
            loss.backward()
            norm = torch.nn.utils.clip_grad_norm_(trainable.values(), 1.0)
            if not torch.isfinite(norm):
                raise RuntimeError('nonfinite gradients')
            optimizer.step()
            optimizer_steps += 1
            train_losses.append(float(loss.detach()))
        validation = evaluate(pipe, splits['validation'], torch)
        if validation['mean_bce_loss'] < best_loss:
            best_loss, best_epoch = validation['mean_bce_loss'], epoch
            best_head = {name: value.detach().clone() for name, value in trainable.items()}
        history.append({'epoch': epoch, 'train_mean_bce': sum(train_losses)/len(train_losses),
                        'validation_mean_bce': validation['mean_bce_loss'], 'optimizer_steps': optimizer_steps})
        print('EPOCH=' + json.dumps(history[-1], sort_keys=True), flush=True)
    with torch.no_grad():
        for name, value in trainable.items():
            value.copy_(best_head[name])
    changed = [name for name, value in trainable.items() if not torch.equal(value, before_head[name])]
    if not changed or optimizer_steps == 0:
        raise RuntimeError('no verified parameter update')
    final = {'validation': evaluate(pipe, splits['validation'], torch),
             'test': evaluate(pipe, splits['test'], torch)}
    model.eval()
    output.mkdir(parents=True, exist_ok=False)
    model.save_pretrained(output, safe_serialization=True)
    pipe.pipe.tokenizer.save_pretrained(output)
    trained_sha = hashlib.sha256()
    with (output / 'model.safetensors').open('rb') as source:
        for chunk in iter(lambda: source.read(1024*1024), b''):
            trained_sha.update(chunk)
    report = {'evidence': {'run_kind': 'actual_cpu_classification_head_training', 'training_executed': True,
                           'mock_training': False, 'real_http': False, 'real_mcp': False,
                           'joint_span_training': False, 'data_kind': 'assistant_authored_synthetic_study',
                           'created_at_utc': datetime.now(timezone.utc).isoformat()},
              'base_model': manifest['model_id'], 'base_revision': manifest['revision'],
              'runtime': model_info, 'config': {'epochs': args.epochs, 'batch_size': args.batch_size,
                                               'learning_rate': args.learning_rate, 'seed': 42,
                                               'threshold': 0.5, 'loss': 'BCEWithLogitsLoss',
                                               'selection': 'validation_BCE_only', 'encoder_frozen': True},
              'splits': validate_rows(rows), 'data_sha256': hashlib.sha256(args.data.read_bytes()).hexdigest(),
              'trainable_parameters': sum(p.numel() for p in trainable.values()),
              'changed_parameter_tensors': changed, 'optimizer_steps': optimizer_steps,
              'best_epoch': best_epoch, 'history': history, 'baseline': baseline, 'after_training': final,
              'elapsed_training_and_evaluation_ms': (time.perf_counter() - started)*1000,
              'trained_weight_sha256': trained_sha.hexdigest(), 'benchmark_f1': None,
              'deployment_validated': False}
    (output / 'study_report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print('RUN_KIND=actual_cpu_classification_head_training TRAINING=true MOCK_TRAINING=false')
    print('SPLITS=' + json.dumps(report['splits'], sort_keys=True))
    print('OPTIMIZER_STEPS=' + str(optimizer_steps) + ' CHANGED_TENSORS=' + str(len(changed)))
    print('BEST_EPOCH=' + str(best_epoch) + ' TRAINABLE_PARAMETERS=' + str(report['trainable_parameters']))
    print('BEFORE_SYNTHETIC_TEST=' + json.dumps(baseline['test']['synthetic_binary_metrics'], sort_keys=True))
    print('AFTER_SYNTHETIC_TEST=' + json.dumps(final['test']['synthetic_binary_metrics'], sort_keys=True))
    print('JOINT_SPAN_TRAINING=false BENCHMARK_F1=null DEPLOYMENT_VALIDATED=false')
    print('REPORT=' + str(output / 'study_report.json'))


if __name__ == '__main__':
    main()
