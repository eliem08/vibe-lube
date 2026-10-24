import os
import tempfile
import unittest

from vibe_lube import apply_safe_fixes, inspect

FAKE_OPENAI = "sk-proj-" + "a1B2c3D4" * 5


def write(root, rel, content):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        r = self.root = self.tmp.name
        write(r, "package.json", '{"dependencies": {"react": "latest", "next": "14.2.3"}}')
        write(r, ".env", "OPENAI_API_KEY=real\n")
        write(
            r,
            "src/lib/ai.ts",
            f'const client = new OpenAI({{ apiKey: "{FAKE_OPENAI}" }});\n'
            "const url = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;\n"
            "const x = eval(userInput);\n",
        )
        write(
            r,
            "server/db.py",
            'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")\napp.run(debug=True)\n'
            'key = os.environ.get("STRIPE_KEY")\n',
        )
        write(r, "node_modules/pkg/index.js", f'const k = "{FAKE_OPENAI}"')

    def tearDown(self):
        self.tmp.cleanup()

    def test_findings(self):
        rep = inspect(self.root)
        rules = {f.rule for f in rep.findings}
        expected = {
            "secret_in_code",
            "env_not_ignored",
            "public_secret",
            "service_role_client",
            "eval",
            "sql_concat",
            "debug_mode",
            "no_lockfile",
            "unpinned_dep",
            "missing_env_example",
            "no_tests",
            "no_readme",
        }
        self.assertTrue(expected <= rules, expected - rules)
        self.assertFalse(any("node_modules" in f.file for f in rep.findings))
        self.assertEqual(rep.grade, "F")
        secret = next(f for f in rep.findings if f.rule == "secret_in_code")
        self.assertNotIn(FAKE_OPENAI, secret.detail)
        self.assertIn("STRIPE_KEY", rep.env_vars)

    def test_safe_fixes(self):
        rep = inspect(self.root)
        done = apply_safe_fixes(self.root, rep)
        self.assertEqual(len(done), 2)
        with open(os.path.join(self.root, ".env.example")) as fh:
            example = fh.read()
        self.assertIn("STRIPE_KEY=\n", example)
        self.assertNotIn("=real", example)  # names only, never values
        rules = {f.rule for f in inspect(self.root).findings}
        self.assertNotIn("env_not_ignored", rules)
        self.assertNotIn("missing_env_example", rules)

    def test_clean_project(self):
        with tempfile.TemporaryDirectory() as r:
            write(r, "README.md", "# app")
            write(r, "app.py", "print('hi')\n")
            write(r, "tests/test_app.py", "def test(): pass\n")
            rep = inspect(r)
            self.assertEqual(rep.findings, [])
            self.assertEqual(rep.grade, "A")


if __name__ == "__main__":
    unittest.main()
