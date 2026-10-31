import tempfile
import unittest
from pathlib import Path
from sentinel.core import connect, csv_export, initialize, record_assets, validate_scope


class ScopeTests(unittest.TestCase):
    def test_reject_external_or_oversized_scope(self):
        for scope in ["8.8.8.8", "192.168.0.0/16", "::1", "192.168.20.0/23", "--script=default", ""]:
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                validate_scope(scope)

    def test_normalize_and_deduplicate(self):
        self.assertEqual(validate_scope("192.168.10.10,192.168.10.10/32"), "192.168.10.10/32")

    def test_inventory_preserves_unseen_assets(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "state.db"
            initialize(path)
            record_assets(path, [("192.168.20.57", "iot")])
            record_assets(path, [])
            with connect(path) as db:
                asset = dict(db.execute("SELECT * FROM assets").fetchone())
            self.assertEqual(asset["segment"], "IoT")
            self.assertEqual(asset["hostname"], "iot")

    def test_csv_neutralizes_formula_strings(self):
        text = csv_export([{"name": " =HYPERLINK(1)", "severity": 8.5}])
        self.assertIn("' =HYPERLINK(1)", text)


if __name__ == "__main__":
    unittest.main()
