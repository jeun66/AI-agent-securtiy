import unittest
from week5.span_study import (TAGS, build_span_rows, token_targets, decode_spans,
                              exact_span_metrics, validate_span_rows)


class SpanStudyTests(unittest.TestCase):
    def test_unicode_offsets_align_to_bio_without_special_tokens(self):
        spans = [{'start': 1, 'end': 3, 'label': 'person'}]
        self.assertEqual(token_targets([(0,0),(0,1),(1,2),(2,3),(3,4),(0,0)],spans),
                         [-100,0,TAGS.index('B-person'),TAGS.index('I-person'),0,-100])

    def test_decode_offsets_and_low_confidence_filter(self):
        spans = decode_spans('가나다라',[(0,0),(0,1),(1,2),(2,3),(3,4)],
                             [0,0,TAGS.index('B-person'),TAGS.index('I-person'),0],[0.9]*5)
        self.assertEqual([(s['start'],s['end'],s['label']) for s in spans],[(1,3,'person')])
        self.assertEqual(decode_spans('가',[(0,1)],[TAGS.index('B-person')],[0.1]),[])

    def test_invalid_offsets_scores_and_tags_fail(self):
        for offsets,tags,scores in [([(0,2)],[0],[0.9]), ([(0,1)],[-1],[0.9]),
                                     ([(0,1)],[0],[float('nan')]), ([(0,1)],[],[])]:
            with self.assertRaises(ValueError):
                decode_spans('가',offsets,tags,scores)

    def test_exact_metrics_do_not_credit_partial_spans(self):
        rows=[{'spans':[{'start':0,'end':3,'label':'person'}]}]
        metrics=exact_span_metrics(rows,[[{'start':0,'end':2,'label':'person'}]])
        self.assertEqual((metrics['tp'],metrics['fp'],metrics['fn']),(0,1,1))
        with self.assertRaises(ValueError):
            exact_span_metrics(rows,[])

    def test_synthetic_span_splits_and_annotations(self):
        rows=build_span_rows()
        self.assertEqual(validate_span_rows(rows),{'train':10,'validation':10,'test':10})
        self.assertTrue(all(r['annotation_status']=='assistant_authored_synthetic_study' for r in rows))

    def test_span_leakage_and_bounds_rejected(self):
        rows=build_span_rows()
        next(r for r in rows if r['split']=='test')['family_id']=rows[0]['family_id']
        with self.assertRaises(ValueError):
            validate_span_rows(rows)
        rows=build_span_rows();rows[0]['spans'][0]['end']=9999
        with self.assertRaises(ValueError):
            validate_span_rows(rows)


if __name__ == '__main__':
    unittest.main(verbosity=2)
