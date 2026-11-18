"""False-positive controls: confidence levels, inline ignores, .vibe-lube-ignore and baselines."""

import contextlib
import io
import json
import pathlib
import tempfile
import unittest

from vibe_lube.__main__ import main
from vibe_lube.core import inspect

REAL_KEY = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"  # split so this test file is not itself a finding
APP = {
    "README.md": "# app\n",
    "tests/test_app.py": "def test_x():\n    assert True\n",
    "server.py": (
        "import os\n"
        f'STRIPE = "{REAL_KEY}"\n'
        'PASSWORD = "your-password-here"\n'
        'API_KEY = "aaaaaaaaaaaaaaaa"\n'
        'token = "Zq8vL2xN0pR7tY4wB1mK"\n'
        "# eval(user_input)\n"
        "eval(user_input)\n"
    ),
}


def make(root: pathlib.Path, files: dict):
    for name, text in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def run(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = main(list(argv))
    return code, out.getvalue()


class NoiseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        make(self.root, APP)

    def tearDown(self):
        self.tmp.cleanup()

    def found(self, **kw):
        return {(f.rule, f.line): f.confidence for f in inspect(str(self.root), **kw).findings}

    def test_confidence_separates_real_keys_from_placeholders(self):
        got = self.found()
        self.assertEqual(got[("secret_in_code", 2)], "high")  # provider-format key
        self.assertEqual(got[("secret_in_code", 3)], "low")  # "your-password-here"
        self.assertEqual(got[("secret_in_code", 4)], "low")  # one repeated character
        self.assertEqual(got[("secret_in_code", 5)], "medium")  # random-looking generic token
        self.assertEqual(got[("eval", 6)], "low")  # commented out
        self.assertEqual(got[("eval", 7)], "high")

    def test_low_confidence_findings_cost_no_points(self):
        rep = inspect(str(self.root))
        lows = [f for f in rep.findings if f.confidence == "low"]
        self.assertTrue(lows)
        (self.root / "server.py").write_text(
            f'STRIPE = "{REAL_KEY}"\ntoken = "Zq8vL2xN0pR7tY4wB1mK"\neval(user_input)\n', encoding="utf-8"
        )
        self.assertEqual(inspect(str(self.root)).score, rep.score)

    def test_inline_ignore_on_the_line_or_above(self):
        (self.root / "server.py").write_text(
            "eval(a)  # vibe-lube: ignore\n"
            "# vibe-lube: ignore[eval]\n"
            "eval(b)\n"
            "# vibe-lube: ignore[cors_wildcard]\n"
            "eval(c)\n",
            encoding="utf-8",
        )
        rep = inspect(str(self.root))
        self.assertEqual([f.line for f in rep.findings if f.rule == "eval"], [5])  # wrong rule named: kept
        self.assertEqual(rep.suppressed, 2)

    def test_ignore_file_by_rule_path_and_fingerprint(self):
        fp = next(f.fingerprint for f in inspect(str(self.root)).findings if f.rule == "eval" and f.line == 7)
        (self.root / ".vibe-lube-ignore").write_text(
            f"# accepted risks\n{fp}\nsecret_in_code:server.py\n", encoding="utf-8"
        )
        rules = {f.rule for f in inspect(str(self.root)).findings}
        self.assertNotIn("secret_in_code", rules)
        self.assertEqual(
            [f.line for f in inspect(str(self.root)).findings if f.rule == "eval"], [6]
        )  # only the fingerprinted line is hidden
        (self.root / ".vibe-lube-ignore").write_text("vendor/\n", encoding="utf-8")
        make(self.root, {"vendor/lib.js": "eval(x)\n"})
        self.assertFalse(any(f.file.startswith("vendor/") for f in inspect(str(self.root)).findings))

    def test_baseline_shows_only_new_findings_even_after_lines_move(self):
        base = self.root / "baseline.json"
        code, out = run("inspect", str(self.root), "--write-baseline", str(base))
        self.assertEqual(code, 0)
        self.assertIn("recorded", out)
        text = (self.root / "server.py").read_text(encoding="utf-8")
        (self.root / "server.py").write_text("\n\n" + text + "os.system(f'rm {x}')\n", encoding="utf-8")
        code, out = run("inspect", str(self.root), "--baseline", str(base), "--json")
        rep = json.loads(out)
        self.assertEqual([f["rule"] for f in rep["findings"]], ["shell_injection"])
        self.assertGreater(rep["suppressed"], 0)

    def test_min_confidence_filter(self):
        _, out = run("inspect", str(self.root), "--min-confidence", "high", "--json")
        self.assertTrue(all(f["confidence"] == "high" for f in json.loads(out)["findings"]))


if __name__ == "__main__":
    unittest.main()
