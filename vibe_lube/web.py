"""Hosted API and web app for this product, generated from its CLI (shared runtime, identical in every product).

Every CLI command becomes POST /api/<command> (JSON in, JSON out) and a form at GET /. Each request runs the
real CLI in an isolated subprocess with a timeout, so the web app and the CLI can never disagree.

Security model:
- File and folder arguments come only from uploads written into a private per-request directory; a client can
  never name a path on the server. Folder uploads are zip archives extracted with path-traversal checks.
- Values are passed as separate argv items, options as --flag=value and positionals after "--", so user text
  can never become an option or a shell command.
- State/store options are pinned by the server to its data directory (--data-dir), never client-controlled.
- 5 MB request cap, 30 s run timeout, CSP / nosniff / frame-deny headers, binds 127.0.0.1 unless --host is set.

Run:  <product>-web --port 8000 [--host 0.0.0.0] [--data-dir ./data]
"""

import argparse
import base64
import contextlib
import hashlib
import hmac
import importlib
import io
import json
import os
import pathlib
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PKG = __package__ or "app"
SPEC = importlib.import_module(f"{PKG}._webspec").SPEC
OPS = {op["id"]: op for op in SPEC["ops"]}
MAX_BODY = 5 * 1024 * 1024
TIMEOUT = 30
HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; "
    "connect-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'",
}


class BadRequest(ValueError):
    pass


def _write_upload(field: dict, value, workdir: pathlib.Path) -> str:
    """Materialise an uploaded file or folder inside workdir and return its path."""
    if not isinstance(value, dict):
        raise BadRequest(f"{field['dest']}: expected an upload object")
    if field["kind"] == "dir":
        target = workdir / f"in-{field['dest']}"
        target.mkdir()
        if "files" in value:  # [{"name": "a.txt", "content": "..."}]
            for f in value["files"]:
                _safe_member(target, str(f.get("name", ""))).write_text(str(f.get("content", "")), encoding="utf-8")
        elif "base64" in value:  # a zip archive
            try:
                with zipfile.ZipFile(io.BytesIO(base64.b64decode(value["base64"], validate=True))) as z:
                    for info in z.infolist():
                        if not info.is_dir():
                            _safe_member(target, info.filename).write_bytes(z.read(info))
            except (zipfile.BadZipFile, ValueError) as e:
                raise BadRequest(f"{field['dest']}: not a valid zip archive ({e})") from None
        else:
            raise BadRequest(f"{field['dest']}: folder uploads need 'files' or a base64 zip")
        return str(target)
    name = pathlib.PurePath(str(value.get("name") or field["dest"])).name or field["dest"]
    path = workdir / f"in-{field['dest']}-{name}"
    if "base64" in value:
        try:
            path.write_bytes(base64.b64decode(value["base64"], validate=True))
        except ValueError:
            raise BadRequest(f"{field['dest']}: invalid base64") from None
    else:
        path.write_text(str(value.get("content", "")), encoding="utf-8")
    return str(path)


def _safe_member(root: pathlib.Path, name: str) -> pathlib.Path:
    dest = (root / name).resolve()
    if root.resolve() not in dest.parents:
        raise BadRequest(f"unsafe path in upload: {name!r}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    return dest


def build_argv(op: dict, payload: dict, workdir: pathlib.Path, data_dir: pathlib.Path) -> tuple[list, dict]:
    """Translate a JSON payload into CLI argv. Returns (argv, outputs) where outputs maps dest -> output path."""
    if not isinstance(payload, dict):
        raise BadRequest("request body must be a JSON object")
    unknown = set(payload) - {f["dest"] for f in op["fields"]}
    if unknown:
        raise BadRequest(f"unknown fields: {sorted(unknown)}")
    head, opts, pos, outputs = [], [], [], {}
    for flag, filename in SPEC.get("state", {}).items():  # server-pinned stores go before the subcommand
        head.append(f"{flag}={data_dir / filename}")
    for f in op["fields"]:
        kind, value = f["kind"], payload.get(f["dest"])
        if kind == "output":
            value = str(workdir / f"out-{f['dest']}")
            outputs[f["dest"]] = value
        elif kind == "state":  # a per-command store: always the server's own file, never client-chosen
            value = str(data_dir / f["file"])
        elif value is None or value == "" or value == []:
            if f.get("required"):
                raise BadRequest(f"{f['dest']} is required")
            continue
        elif kind in ("file", "dir"):
            value = _write_upload(f, value, workdir)
        elif kind == "bool":
            if value is True:
                (head if f.get("scope") == "global" else opts).append(f["flag"])
            continue
        elif kind in ("int", "number"):
            try:
                value = str(int(value) if kind == "int" else float(value))
            except (TypeError, ValueError):
                raise BadRequest(f"{f['dest']} must be a number") from None
        elif kind == "list":
            values = value if isinstance(value, list) else [value]
            if f.get("choices") and any(str(v) not in f["choices"] for v in values):
                raise BadRequest(f"{f['dest']} must be among {f['choices']}")
            if f["flag"] is None:
                pos.extend(str(v) for v in values)
            elif f.get("append"):
                opts.extend(f"{f['flag']}={v}" for v in values)
            elif values:  # nargs list option: items follow the flag, so none may look like an option
                if any(str(v).startswith("-") for v in values):
                    raise BadRequest(f"{f['dest']} items cannot start with '-'")
                opts.extend([f["flag"], *[str(v) for v in values]])
            continue
        else:
            value = str(value)
            if f.get("choices") and value not in f["choices"]:
                raise BadRequest(f"{f['dest']} must be one of {f['choices']}")
        if f["flag"] is None:
            pos.append(value)
        else:
            (head if f.get("scope") == "global" else opts).append(f"{f['flag']}={value}")
    # positionals after "--" so user text that starts with "-" can never be read as an option
    argv = [*head, *op["prefix"], *opts]
    if pos:
        argv += ["--", *pos]
    return argv, outputs


def run_op(op: dict, payload: dict, data_dir: pathlib.Path) -> dict:
    with tempfile.TemporaryDirectory(prefix="web-") as tmp:
        work = pathlib.Path(tmp)
        argv, outputs = build_argv(op, payload, work, data_dir)
        env = {k: v for k, v in os.environ.items() if k != "AGENT_ECONOMY_DEBUG"}
        env.update(PYTHONIOENCODING="utf-8", HOME=str(data_dir), USERPROFILE=str(data_dir))
        try:
            r = subprocess.run(
                [sys.executable, "-m", PKG, *argv],
                cwd=work,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            return {"ok": False, "exit_code": None, "error": f"timed out after {TIMEOUT}s"}
        # exit 1 is a domain answer ("nothing found", "failing grade") only when the command said something;
        # a silent exit 1 is a failure, and stderr is always passed through so the user sees why
        # never echo the server's private temp paths back to the client
        r.stdout = r.stdout.replace(str(work), "upload").replace(str(work.resolve()), "upload")
        r.stderr = r.stderr.replace(str(work), "upload").replace(str(work.resolve()), "upload")
        said = bool(r.stdout.strip())
        result = {
            "ok": r.returncode == 0 or (r.returncode == 1 and said),
            "exit_code": r.returncode,
            "stdout": r.stdout[-200_000:],
        }
        if r.stderr.strip():
            result["stderr"] = r.stderr.strip()[-2000:]
        if not result["ok"]:
            result["error"] = result.get("stderr") or "command failed without output"
        with contextlib.suppress(ValueError):
            result["json"] = json.loads(r.stdout)
        for dest, path in outputs.items():
            p = pathlib.Path(path)
            if p.is_file():
                result.setdefault("files", {})[dest] = p.read_text(encoding="utf-8", errors="replace")[-500_000:]
        return result


class Gate:
    """API keys, a per-caller rate limit and usage metering (the record billing is built on).

    Keys come from API_KEYS (comma-separated) and/or <data-dir>/api-keys.json, which stores only SHA-256
    hashes. With no keys configured the API is open, which `main` allows only on a loopback address.
    """

    def __init__(self, data_dir: pathlib.Path, env_keys: str = "", rate_per_min: int = 60):
        self.keys_file, self.usage_file = data_dir / "api-keys.json", data_dir / "usage.jsonl"
        self.env = {_digest(k.strip()): f"env-{i}" for i, k in enumerate(env_keys.split(","), 1) if k.strip()}
        self.rate = rate_per_min
        self.hits: dict[str, list[float]] = {}
        self.lock = threading.Lock()

    def stored(self) -> dict:
        try:
            data = json.loads(self.keys_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def active(self) -> dict:
        """hash -> key id for every key that may call the API."""
        keys = dict(self.env)
        keys.update({rec["hash"]: kid for kid, rec in self.stored().items() if not rec.get("revoked")})
        return keys

    def required(self) -> bool:
        return bool(self.active())

    def identify(self, header: str | None) -> str | None:
        if not header or not header.startswith("Bearer "):
            return None
        digest = _digest(header[7:].strip())
        found = None
        for h, kid in self.active().items():  # compare every key in constant time; never short-circuit
            if hmac.compare_digest(h, digest):
                found = kid
        return found

    def retry_after(self, caller: str) -> int | None:
        """Sliding one-minute window; returns seconds to wait when the caller is over the limit."""
        now = time.monotonic()
        with self.lock:
            window = [t for t in self.hits.get(caller, []) if now - t < 60]
            if len(window) >= self.rate:
                self.hits[caller] = window
                return max(1, int(60 - (now - window[0])) + 1)
            window.append(now)
            self.hits[caller] = window
        return None

    def record(self, caller: str, op: str, status: int, ms: int):
        line = json.dumps(
            {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "key": caller,
                "op": op,
                "status": status,
                "ms": ms,
            }
        )
        with self.lock, open(self.usage_file, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    def create(self, label: str, meta: dict | None = None) -> tuple[str, str]:
        key = "sk_" + secrets.token_urlsafe(24)
        digest = _digest(key)
        kid = digest[:10]
        keys = self.stored()
        keys[kid] = {
            "hash": digest,
            "label": label,
            "created": time.strftime("%Y-%m-%d"),
            "revoked": False,
            **(meta or {}),
        }
        self._save(keys)
        return kid, key

    def revoke(self, kid: str) -> bool:
        keys = self.stored()
        if kid not in keys:
            return False
        keys[kid]["revoked"] = True
        self._save(keys)
        return True

    def revoke_where(self, field: str, value: str) -> int:
        """Revoke every key whose record has field == value (e.g. a cancelled Stripe subscription)."""
        keys, n = self.stored(), 0
        for rec in keys.values():
            if value and rec.get(field) == value and not rec.get("revoked"):
                rec["revoked"], n = True, n + 1
        if n:
            self._save(keys)
        return n

    def _save(self, keys: dict):
        tmp = self.keys_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(keys, indent=2), encoding="utf-8")
        os.replace(tmp, self.keys_file)

    def usage(self) -> dict:
        summary: dict[str, dict] = {}
        try:
            lines = self.usage_file.read_text(encoding="utf-8").splitlines()
        except OSError:
            return summary
        for ln in lines:
            with contextlib.suppress(ValueError, KeyError):
                rec = json.loads(ln)
                s = summary.setdefault(rec["key"], {"calls": 0, "ok": 0, "by_op": {}})
                s["calls"] += 1
                s["ok"] += rec["status"] == 200
                s["by_op"][rec["op"]] = s["by_op"].get(rec["op"], 0) + 1
        return summary


def _digest(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


class Billing:
    """Self-serve purchase: Stripe Checkout -> signed webhook -> an API key shown to the buyer exactly once.

    Configured by env: STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, STRIPE_PRICES ("plan=price_id,..."),
    PUBLIC_URL (the address customers reach). Disabled, with /pricing saying so, until all are set.
    A cancelled subscription revokes its keys. A plaintext key waits in pending-keys.json only until the buyer
    opens the success page; the Checkout session id, known only to Stripe and the buyer, unlocks it.
    """

    API = "https://api.stripe.com/v1"
    TOLERANCE = 300

    def __init__(self, data_dir: pathlib.Path, gate: Gate, env: dict | None = None):
        env = os.environ if env is None else env
        self.secret = env.get("STRIPE_SECRET_KEY", "")
        self.hook_secret = env.get("STRIPE_WEBHOOK_SECRET", "")
        self.public_url = env.get("PUBLIC_URL", "").rstrip("/")
        self.prices = dict(item.split("=", 1) for item in env.get("STRIPE_PRICES", "").split(",") if "=" in item)
        self.gate, self.pending_file = gate, data_dir / "pending-keys.json"
        self.lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return bool(self.secret and self.hook_secret and self.prices and self.public_url)

    def _stripe(self, path: str, form: dict) -> dict:  # network call; tests replace it
        import urllib.parse
        import urllib.request

        req = urllib.request.Request(
            f"{self.API}/{path}",
            data=urllib.parse.urlencode(form).encode(),
            headers={"Authorization": f"Bearer {self.secret}"},
        )
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read())

    def checkout(self, plan: str) -> str:
        if not self.enabled:
            raise BadRequest("self-serve checkout is not configured on this server")
        price = self.prices.get(plan)
        if not price:
            raise BadRequest(f"unknown plan {plan!r}; choose one of {sorted(self.prices)}")
        session = self._stripe(
            "checkout/sessions",
            {
                "mode": "subscription",
                "line_items[0][price]": price,
                "line_items[0][quantity]": "1",
                "metadata[plan]": plan,
                "success_url": f"{self.public_url}/billing/success?session_id={{CHECKOUT_SESSION_ID}}",
                "cancel_url": f"{self.public_url}/pricing",
            },
        )
        return session["url"]

    def verify(self, body: bytes, header: str, now: float | None = None) -> dict:
        """Stripe-Signature check: HMAC-SHA256 of "<t>.<body>", constant time, within a 5-minute window."""
        parts: dict[str, list] = {}
        for item in (header or "").split(","):
            k, _, v = item.partition("=")
            parts.setdefault(k.strip(), []).append(v.strip())
        try:
            ts = int(parts["t"][0])
        except (KeyError, ValueError):
            raise BadRequest("bad signature header") from None
        expected = hmac.new(self.hook_secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
        if not self.hook_secret or not any(hmac.compare_digest(expected, sig) for sig in parts.get("v1", [])):
            raise BadRequest("signature mismatch")
        if abs((time.time() if now is None else now) - ts) > self.TOLERANCE:
            raise BadRequest("signature too old")
        return json.loads(body)

    def handle(self, event: dict) -> str:
        kind, obj = event.get("type"), (event.get("data") or {}).get("object") or {}
        if kind == "checkout.session.completed":
            sid = obj.get("id", "")
            with self.lock:
                pending = self._pending()
                if not sid or sid in pending:
                    return "duplicate"  # Stripe retries webhooks; one key per purchase
                email = (obj.get("customer_details") or {}).get("email") or "customer"
                kid, key = self.gate.create(
                    email,
                    {
                        "plan": (obj.get("metadata") or {}).get("plan", ""),
                        "subscription": obj.get("subscription") or "",
                        "customer": obj.get("customer") or "",
                    },
                )
                pending[sid] = {"key": key, "kid": kid}
                self._save(pending)
            return f"issued {kid}"
        if kind == "customer.subscription.deleted":
            return f"revoked {self.gate.revoke_where('subscription', obj.get('id', ''))}"
        return "ignored"

    def claim(self, session_id: str) -> str | None:
        """Hand the key over once, then forget the plaintext."""
        with self.lock:
            pending = self._pending()
            rec = pending.get(session_id)
            if not rec or "key" not in rec:
                return None
            key = rec.pop("key")
            rec["claimed"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            self._save(pending)
            return key

    def _pending(self) -> dict:
        try:
            data = json.loads(self.pending_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def _save(self, data: dict):
        tmp = self.pending_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(tmp, self.pending_file)


class Handler(BaseHTTPRequestHandler):
    server_version = f"{PKG}-web"
    data_dir: pathlib.Path
    gate: Gate
    billing: Billing

    def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in {**HEADERS, **(extra or {})}.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, obj, extra: dict | None = None):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8", extra)

    def log_message(self, fmt, *args):  # one line per request on stderr, no bodies
        sys.stderr.write(f"{self.address_string()} {fmt % args}\n")

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            self._json(200, {"status": "ok", "product": SPEC["name"]})
        elif path == "/api/spec":
            self._json(200, SPEC)
        elif path == "/app.js":
            self._send(200, APP_JS.encode("utf-8"), "text/javascript; charset=utf-8")
        elif path in ("/", "/index.html"):
            self._send(200, page().encode("utf-8"), "text/html; charset=utf-8")
        elif path == "/pricing":
            self._send(200, pricing_page(self.billing).encode("utf-8"), "text/html; charset=utf-8")
        elif path == "/billing/success":
            from urllib.parse import parse_qs, urlsplit

            sid = (parse_qs(urlsplit(self.path).query).get("session_id") or [""])[0]
            key = self.billing.claim(sid) if sid else None
            html_out = success_page(key, bool(sid)).encode("utf-8")
            self._send(200, html_out, "text/html; charset=utf-8", {"Cache-Control": "no-store"})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self._json(400, {"error": "bad Content-Length"})
        if length > MAX_BODY:
            return self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": f"request over {MAX_BODY} bytes"})
        # always read the body before answering: closing with unread data makes some stacks reset the connection
        body = self.rfile.read(length)
        if path == "/billing/webhook":
            try:
                note = self.billing.handle(self.billing.verify(body, self.headers.get("Stripe-Signature", "")))
            except (ValueError, BadRequest) as e:
                return self._json(400, {"error": str(e)})
            return self._json(200, {"received": True, "result": note})
        if path == "/billing/checkout":
            from urllib.parse import parse_qs

            plan = (parse_qs(body.decode("utf-8", "replace")).get("plan") or [""])[0]
            try:
                url = self.billing.checkout(plan)
            except (BadRequest, OSError, KeyError, ValueError) as e:
                return self._json(400, {"error": str(e)})
            return self._send(303, b"", "text/plain", {"Location": url})
        op = OPS.get(path.removeprefix("/api/")) if path.startswith("/api/") else None
        if not op:
            return self._json(404, {"error": "unknown command", "commands": sorted(OPS)})
        caller = self.gate.identify(self.headers.get("Authorization"))
        if caller is None and (self.gate.required() or self.billing.enabled):
            self.gate.record("unauthenticated", op["id"], 401, 0)
            return self._json(401, {"error": "missing or invalid API key"}, {"WWW-Authenticate": "Bearer"})
        caller = caller or f"ip:{self.client_address[0]}"
        wait = self.gate.retry_after(caller)
        if wait:
            return self._json(
                429, {"error": f"rate limit: {self.gate.rate} requests per minute"}, {"Retry-After": str(wait)}
            )
        started = time.monotonic()
        try:
            payload = json.loads(body or b"{}")
            result = run_op(op, payload, self.data_dir)
            status = 200
        except (ValueError, BadRequest) as e:
            result, status = {"error": str(e)}, 400
        self.gate.record(caller, op["id"], status, int((time.monotonic() - started) * 1000))
        self._json(status, result)


def _shell(title: str, inner: str) -> str:
    import html

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{html.escape(title)}</title>
<style>:root{{--bg:#fbfaf7;--fg:#1c1b19;--muted:#5d5a54;--card:#fff;--line:#e4e0d8;--accent:#2f5d50;--accent-fg:#fff;--code:#f1eee8}}
@media (prefers-color-scheme: dark){{:root{{--bg:#141412;--fg:#ecebe7;--muted:#a8a49c;--card:#1d1c1a;--line:#33312d;--accent:#7fc4ad;--accent-fg:#10201b;--code:#22211e}}}}
body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}}
main{{max-width:720px;margin:0 auto;padding:32px 16px}}a{{color:var(--accent)}}
section{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin:16px 0}}
button{{padding:9px 16px;border-radius:8px;border:0;background:var(--accent);color:var(--accent-fg);font-weight:600;cursor:pointer}}
code,pre{{background:var(--code);border-radius:6px;padding:2px 6px;word-break:break-all;white-space:pre-wrap}}small{{color:var(--muted)}}</style>
</head><body><main><p><a href="/">{html.escape(SPEC["name"])}</a></p>{inner}</main></body></html>"""


def pricing_page(billing: Billing) -> str:
    import html

    e = html.escape
    if not billing.enabled:
        return _shell(
            "Pricing",
            "<h1>Pricing</h1><p>Self-serve checkout is not enabled on this server yet. "
            "See the product README for plans.</p>",
        )
    cards = "".join(
        f'<section><h2>{e(plan.title())}</h2><form method="post" action="/billing/checkout">'
        f'<input type="hidden" name="plan" value="{e(plan)}"><button>Subscribe</button></form></section>'
        for plan in billing.prices
    )
    return _shell(
        "Pricing",
        f"<h1>{e(SPEC['name'])} plans</h1><p>{e(SPEC['tagline'])}</p>{cards}"
        "<p><small>Payments by Stripe. Your API key appears right after checkout.</small></p>",
    )


def success_page(key: str | None, had_session: bool) -> str:
    import html

    if key:
        return _shell(
            "Your API key",
            "<h1>You are in</h1><p>Your API key, shown once. Store it now:</p>"
            f"<pre>{html.escape(key)}</pre><p>Send it as <code>Authorization: Bearer &lt;key&gt;</code> "
            'or paste it into the <a href="/">web app</a>.</p>',
        )
    if had_session:
        return _shell(
            "Almost there",
            "<h1>Payment received</h1><p>Your key is being issued: reload this page in a few seconds. "
            "A key is shown only once; if you already saw it, ask support to rotate it.</p>",
        )
    return _shell("Not found", "<h1>Nothing to show</h1>")


def page() -> str:
    import html

    e = html.escape
    forms = []
    for op in SPEC["ops"]:
        rows = []
        for f in op["fields"]:
            if f["kind"] in ("output", "state"):
                continue
            label = e(f["dest"].replace("_", " ")) + (" *" if f.get("required") else "")
            hint = f"<small>{e(f.get('help') or '')}</small>" if f.get("help") else ""
            name = e(f["dest"])
            if f["kind"] == "bool":
                ctl = f'<input type="checkbox" name="{name}">'
            elif f.get("choices") and f["kind"] != "list":
                opts = "".join(f"<option>{e(str(c))}</option>" for c in f["choices"])
                ctl = f'<select name="{name}"><option value=""></option>{opts}</select>'
            elif f["kind"] == "file":
                ctl = f'<textarea name="{name}" data-kind="file" rows="6" placeholder="paste file contents or choose a file"></textarea><input type="file" data-for="{name}">'
            elif f["kind"] == "dir":
                ctl = f'<input type="file" name="{name}" data-kind="dir" multiple><small>choose files, or one .zip</small>'
            else:
                typ = "number" if f["kind"] in ("int", "number") else "text"
                step = ' step="any"' if f["kind"] == "number" else ""
                ph = " (comma-separated)" if f["kind"] == "list" else ""
                default = "" if f.get("default") in (None, "") else e(str(f["default"]))
                ctl = f'<input type="{typ}"{step} name="{name}" data-kind="{e(f["kind"])}" placeholder="{default}{ph}">'
            rows.append(f"<label>{label}{ctl}{hint}</label>")
        forms.append(
            f'<section><h2>{e(op["title"])}</h2><form data-op="{e(op["id"])}">{"".join(rows)}'
            f'<button type="submit">Run</button></form><pre class="out" hidden></pre></section>'
        )
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{e(SPEC["name"])}</title>
<style>:root{{--bg:#fbfaf7;--fg:#1c1b19;--muted:#5d5a54;--card:#fff;--line:#e4e0d8;--accent:#2f5d50;--accent-fg:#fff;--code:#f1eee8}}
@media (prefers-color-scheme: dark){{:root{{--bg:#141412;--fg:#ecebe7;--muted:#a8a49c;--card:#1d1c1a;--line:#33312d;--accent:#7fc4ad;--accent-fg:#10201b;--code:#22211e}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}}
main{{max-width:880px;margin:0 auto;padding:24px 16px 64px}}header p{{color:var(--muted)}}
section{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin:16px 0}}
h1{{margin:8px 0}}h2{{font-size:17px;margin:0 0 12px}}label{{display:block;margin:0 0 10px;font-weight:600}}
input,select,textarea{{display:block;width:100%;margin-top:4px;padding:8px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg);font:inherit}}
input[type=checkbox]{{width:auto;display:inline-block;margin-left:8px}}small{{display:block;color:var(--muted);font-weight:400}}
button{{padding:9px 16px;border-radius:8px;border:0;background:var(--accent);color:var(--accent-fg);font-weight:600;cursor:pointer}}
pre{{background:var(--code);border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto;max-height:420px;white-space:pre-wrap}}</style>
</head><body><main><header><h1>{e(SPEC["name"])}</h1><p>{e(SPEC["tagline"])}</p>
<p><small>API: POST /api/&lt;command&gt; with JSON and <code>Authorization: Bearer &lt;key&gt;</code>. Spec: <a href="/api/spec">/api/spec</a></small></p>
<label>API key<input type="password" id="api-key" autocomplete="off" placeholder="sk_... (kept for this tab only)"></label></header>
{"".join(forms)}</main><script src="/app.js"></script></body></html>"""


APP_JS = """
const readText = (f) => new Promise((ok, no) => { const r = new FileReader(); r.onload = () => ok(r.result); r.onerror = no; r.readAsText(f); });
const readB64 = (f) => new Promise((ok, no) => { const r = new FileReader(); r.onload = () => ok(String(r.result).split(',')[1]); r.onerror = no; r.readAsDataURL(f); });
try { document.getElementById('api-key').value = sessionStorage.getItem('apiKey') || ''; } catch (e) { /* storage blocked */ }
document.querySelectorAll('input[type=file][data-for]').forEach((inp) => inp.addEventListener('change', async () => {
  const ta = inp.form.querySelector('textarea[name="' + inp.dataset.for + '"]');
  if (inp.files[0]) { ta.value = await readText(inp.files[0]); ta.dataset.filename = inp.files[0].name; }
}));
document.querySelectorAll('form[data-op]').forEach((form) => form.addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const out = form.parentElement.querySelector('.out'); out.hidden = false; out.textContent = 'Running...';
  const body = {};
  for (const el of form.elements) {
    if (!el.name || el.type === 'submit') continue;
    const kind = el.dataset.kind;
    if (el.type === 'checkbox') { if (el.checked) body[el.name] = true; continue; }
    if (kind === 'file') { if (el.value) body[el.name] = { name: el.dataset.filename || el.name + '.txt', content: el.value }; continue; }
    if (kind === 'dir') {
      if (!el.files.length) continue;
      if (el.files.length === 1 && el.files[0].name.endsWith('.zip')) { body[el.name] = { base64: await readB64(el.files[0]) }; continue; }
      body[el.name] = { files: await Promise.all([...el.files].map(async (f) => ({ name: f.name, content: await readText(f) }))) };
      continue;
    }
    if (el.value === '') continue;
    body[el.name] = kind === 'list' ? el.value.split(',').map((s) => s.trim()).filter(Boolean) : el.value;
  }
  try {
    const headers = { 'Content-Type': 'application/json' };
    const key = document.getElementById('api-key').value.trim();
    if (key) { headers.Authorization = 'Bearer ' + key; sessionStorage.setItem('apiKey', key); }
    const res = await fetch('/api/' + form.dataset.op, { method: 'POST', headers, body: JSON.stringify(body) });
    const data = await res.json();
    out.textContent = data.error ? 'Error: ' + data.error + (data.stdout ? '\\n\\n' + data.stdout : '')
      : (data.json ? JSON.stringify(data.json, null, 2) : data.stdout) + (data.files ? '\\n\\n' + Object.values(data.files).join('\\n') : '');
  } catch (err) { out.textContent = 'Request failed: ' + err; }
}));
"""


LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def make_server(
    host: str, port: int, data_dir: pathlib.Path, env_keys: str = "", rate: int = 60, env: dict | None = None
) -> ThreadingHTTPServer:
    data_dir.mkdir(parents=True, exist_ok=True)
    gate = Gate(data_dir.resolve(), env_keys, rate)
    billing = Billing(data_dir.resolve(), gate, env)
    bound = {"data_dir": data_dir.resolve(), "gate": gate, "billing": billing}
    handler = type("BoundHandler", (Handler,), bound)
    return ThreadingHTTPServer((host, port), handler)


def keys_main(argv: list) -> int:
    """<cli>-web keys create|list|revoke and <cli>-web usage: manage API keys and read metering."""
    ap = argparse.ArgumentParser(prog=f"{SPEC['cli']}-web")
    ap.add_argument("--data-dir", default=os.environ.get("DATA_DIR", "data"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keys").add_subparsers(dest="action", required=True)
    k.add_parser("create").add_argument("--label", required=True, help="who the key is for, e.g. a customer")
    k.add_parser("list")
    k.add_parser("revoke").add_argument("key_id")
    sub.add_parser("usage", help="calls per key, for billing")
    a = ap.parse_args(argv)
    data_dir = pathlib.Path(a.data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    gate = Gate(data_dir.resolve())
    if a.cmd == "usage":
        print(json.dumps(gate.usage(), indent=2))
    elif a.action == "create":
        kid, key = gate.create(a.label)
        print(f"key id {kid} for {a.label!r}\n{key}\nShown once; only its hash is stored.")
    elif a.action == "list":
        for kid, rec in gate.stored().items():
            print(f"{kid}  {rec['created']}  {'REVOKED ' if rec.get('revoked') else ''}{rec['label']}")
    elif not gate.revoke(a.key_id):
        print(f"no key {a.key_id!r}", file=sys.stderr)
        return 2
    else:
        print(f"revoked {a.key_id}")
    return 0


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] in (["keys"], ["usage"]) or (len(argv) > 2 and argv[2] in ("keys", "usage")):
        return keys_main(argv)
    ap = argparse.ArgumentParser(prog=f"{SPEC['cli']}-web", description=f"{SPEC['name']} hosted API and web app")
    ap.add_argument(
        "--host", default="127.0.0.1", help="use 0.0.0.0 to accept outside connections (e.g. in a container)"
    )
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    ap.add_argument("--data-dir", default=os.environ.get("DATA_DIR", "data"), help="where server-side state is kept")
    ap.add_argument(
        "--rate", type=int, default=int(os.environ.get("RATE_LIMIT_PER_MIN", "60")), help="calls/min per caller"
    )
    ap.add_argument(
        "--allow-public",
        action="store_true",
        default=os.environ.get("ALLOW_PUBLIC") == "1",
        help="serve a non-loopback address without API keys (not recommended)",
    )
    a = ap.parse_args(argv)
    srv = make_server(a.host, a.port, pathlib.Path(a.data_dir), os.environ.get("API_KEYS", ""), a.rate)
    gate = srv.RequestHandlerClass.gate
    selling = srv.RequestHandlerClass.billing.enabled  # a server that sells keys will require them
    if a.host not in LOOPBACK and not gate.required() and not selling and not a.allow_public:
        srv.server_close()
        print(
            f"refusing to serve {a.host} with no API keys: run `{SPEC['cli']}-web keys create --label NAME` "
            "or set API_KEYS (or pass --allow-public)",
            file=sys.stderr,
        )
        return 2
    access = "API keys required" if gate.required() else "open (no API keys)"
    if selling:
        access += "; Stripe checkout on /pricing"
    print(
        f"{SPEC['name']} on http://{a.host}:{srv.server_address[1]}  ({access}; data: {pathlib.Path(a.data_dir).resolve()})"
    )
    with contextlib.suppress(KeyboardInterrupt):
        srv.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
