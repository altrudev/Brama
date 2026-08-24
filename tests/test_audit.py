import tempfile
import unittest
from pathlib import Path

from brama_assurance.audit import audit

class AuditTests(unittest.TestCase):
    def test_clean_tree_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text("Українська та English only.", encoding="utf-8")
            self.assertEqual(audit(root), [])

    def test_russian_specific_character_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bad = "bad " + chr(1099)
            (root / "bad.txt").write_text(bad, encoding="utf-8")
            self.assertTrue(audit(root))
    def test_schema_raw_content_field_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            schema_dir = root / "schema"
            schema_dir.mkdir()
            field = "raw_" + "content"
            (schema_dir / "bad.json").write_text('{"properties":{"' + field + '":{"type":"string"}}}', encoding="utf-8")
            self.assertTrue(audit(root))


if __name__ == "__main__":
    unittest.main()
