import unittest
from aegis import db, store, digest
class T(unittest.TestCase):
    def setUp(self):
        self.c = db.connect(":memory:"); a, _ = store.upsert_asset(self.c, 1, "ip", "45.33.32.156")
        store.observe(self.c, a, "intel", "internetdb", {"ports": [22, 80]})
    def test_validate(self):
        f = {"F1": "[info] PORTS_SEEN: 45.33.32.156: порты [22, 80]"}
        d = {"items": [{"text": "Открыты порты 22 и 80 на 45.33.32.156", "severity": "info", "cites": ["F1"]},
                       {"text": "Открыт порт 3389 на 45.33.32.156", "severity": "high", "cites": ["F1"]},
                       {"text": "Без ссылки", "severity": "low", "cites": []},
                       {"text": "Левый факт", "severity": "low", "cites": ["F9"]}], "next_steps": []}
        items, steps, dropped = digest.validate(d, f); self.assertEqual(len(items), 1); self.assertEqual(dropped, 3)
    def test_make_llm_and_fallback(self):
        good = lambda s, u: {"summary": "Один IP.", "items": [{"text": "Порты 22 и 80 открыты", "severity": "info", "cites": ["F1"]}], "next_steps": []}
        self.assertIn("Проверка", digest.make(self.c, 1, 48, llm_fn=good))
        def bad(s, u): raise OSError()
        self.assertIn("LLM недоступна", digest.make(self.c, 1, 48, llm_fn=bad))
        self.assertIn("без LLM", digest.make(self.c, 1, 48, use_llm=False))
if __name__ == "__main__": unittest.main()
