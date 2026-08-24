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
            # Construct the prohibited character by code point so the repository fixture
            # itself remains free of that script character.
            bad = "bad " + chr(1099)
            (root / "bad.txt").write_text(bad, encoding="utf-8")
            self.assertTrue(audit(root))


if __name__ == "__main__":
    unittest.main()
