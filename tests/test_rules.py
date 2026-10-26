import os
import tempfile
import unittest

from vibe_lube.core import SERVICE_MENU, inspect

# Fake keys are assembled at runtime so this file never contains a scannable secret.
FILES = {
    "server/db.py": "DB = 'postgres://admin:hunter22@db.internal:5432/app'\n",
    "server/mail.py": "KEY = '" + "SG." + "a" * 22 + "." + "b" * 43 + "'\n",
    "server/google.js": "const k = '" + "AIza" + "c" * 35 + "';\n",
    "server/hf.py": "token = '" + "hf_" + "d" * 34 + "'\n",
    "server/fetch.py": "import requests\nrequests.get(url, verify=False)\n",
    "server/run.py": "import subprocess\nsubprocess.run(cmd, shell=True)\n",
    "src/components/Bio.jsx": "export const Bio = ({html}) => <div dangerouslySetInnerHTML={{__html: html}} />;\n",
    "firestore.rules": "service cloud.firestore {\n  match /{doc=**} { allow read, write: if true; }\n}\n",
    "supabase/migrations/001.sql": "alter table profiles disable row level security;\n",
}


class NewRuleTests(unittest.TestCase):
    def test_each_new_rule_fires_and_has_a_price(self):
        with tempfile.TemporaryDirectory() as root:
            for rel, text in FILES.items():
                path = os.path.join(root, rel)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(text)
            rep = inspect(root)
        rules = {f.rule for f in rep.findings}
        for rule in ("tls_disabled", "shell_injection", "xss_sink", "open_database_rules", "rls_disabled"):
            self.assertIn(rule, rules)
        secrets = " ".join(f.detail for f in rep.findings if f.rule == "secret_in_code")
        for name in ("database_url_password", "sendgrid_key", "google_api_key", "huggingface_token"):
            self.assertIn(name, secrets)
        self.assertNotIn("hunter22", secrets)  # findings are masked
        self.assertTrue(rules <= set(SERVICE_MENU), rules - set(SERVICE_MENU))

    def test_safe_code_stays_quiet(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "app.py"), "w", encoding="utf-8") as fh:
                fh.write("import subprocess, os\nsubprocess.run(['ls'])\nDB = os.environ['DATABASE_URL']\n")
            rules = {f.rule for f in inspect(root).findings}
        self.assertFalse(rules & {"shell_injection", "secret_in_code", "tls_disabled"})


if __name__ == "__main__":
    unittest.main()
