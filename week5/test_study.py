import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from week5.evaluate_study import verify_study_checkpoint
from week5.study_data import build_rows, validate_rows
from week5.train_study import require_new_output


class StudyTests(unittest.TestCase):
    def test_study_splits_and_annotation_scope(self):
        rows = build_rows()
        self.assertEqual(validate_rows(rows), {'train': 16, 'validation': 8, 'test': 8})
        self.assertEqual({r['annotation_status'] for r in rows}, {'assistant_authored_synthetic_study'})
        families = {s: {r['family_id'] for r in rows if r['split'] == s} for s in ['train', 'validation', 'test']}
        self.assertFalse(families['train'] & families['test'])
        self.assertFalse(families['train'] & families['validation'])

    def test_duplicate_normalized_text_is_rejected(self):
        rows = build_rows()
        duplicate = dict(rows[0], id='new', text='  ' + rows[0]['text'] + '  ')
        with self.assertRaises(ValueError):
            validate_rows(rows + [duplicate])

    def test_cross_split_family_leakage_is_rejected(self):
        rows = build_rows()
        next(r for r in rows if r['split'] == 'test')['family_id'] = rows[0]['family_id']
        with self.assertRaises(ValueError):
            validate_rows(rows)

    def test_unreviewed_w4_records_are_not_implicitly_training_data(self):
        rows = build_rows()
        rows[0]['annotation_status'] = 'needs_review'
        with self.assertRaises(ValueError):
            validate_rows(rows)

    def test_output_cannot_overwrite_source_or_existing_folder(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'source'
            source.mkdir()
            for dest in [source, Path(folder), source / 'child']:
                with self.assertRaises(ValueError):
                    require_new_output(dest, source)
            self.assertEqual(require_new_output(Path(folder) / 'new', source), (Path(folder) / 'new').resolve())

    def test_saved_checkpoint_hash_is_verified(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder)
            (p / 'model.safetensors').write_bytes(b'synthetic fixture, not weights')
            report = {'evidence': {'training_executed': True, 'mock_training': False},
                      'trained_weight_sha256': hashlib.sha256((p / 'model.safetensors').read_bytes()).hexdigest()}
            (p / 'study_report.json').write_text(json.dumps(report))
            self.assertEqual(verify_study_checkpoint(p)[0], p.resolve())
            (p / 'model.safetensors').write_bytes(b'changed')
            with self.assertRaises(ValueError):
                verify_study_checkpoint(p)



if __name__ == '__main__':
    unittest.main(verbosity=2)
