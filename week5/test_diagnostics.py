import unittest
from types import SimpleNamespace
from week5.run_compat_diagnostics import diagnostic_variant


class DiagnosticTests(unittest.TestCase):
    def test_diagnostic_state_restored_after_error(self):
        class FakeBackend:
            def __init__(self):
                self.model = SimpleNamespace(config=SimpleNamespace(embed_class_token=True))
            def prepare_input(self, text, labels):
                return 'original:' + text
        backend = FakeBackend()
        with self.assertRaises(RuntimeError):
            with diagnostic_variant(backend, 'next_token'):
                self.assertFalse(backend.model.config.embed_class_token)
                raise RuntimeError('test')
        self.assertTrue(backend.model.config.embed_class_token)
        with diagnostic_variant(backend, 'published_0.1.0_format'):
            self.assertEqual(backend.prepare_input('text', ['a', 'b']), '<<LABEL>>a<<SEP>><<LABEL>>b<<SEP>>text')
        self.assertEqual(backend.prepare_input('text', []), 'original:text')
        with self.assertRaises(ValueError):
            with diagnostic_variant(backend, 'unknown'):
                pass


if __name__ == "__main__":
    unittest.main(verbosity=2)
