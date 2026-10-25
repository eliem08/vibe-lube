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
import importlib
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
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


class Handler(BaseHTTPRequestHandler):
    server_version = f"{PKG}-web"
    data_dir: pathlib.Path

    def _send(self, status: int, body: bytes, ctype: str):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, obj):
        self._send(status, json.dumps(obj, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

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
        op = OPS.get(path.removeprefix("/api/")) if path.startswith("/api/") else None
        if not op:
            return self._json(404, {"error": "unknown command", "commands": sorted(OPS)})
        try:
            payload = json.loads(body or b"{}")
            result = run_op(op, payload, self.data_dir)
        except (ValueError, BadRequest) as e:
            return self._json(400, {"error": str(e)})
        self._json(200, result)


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
<p><small>API: POST /api/&lt;command&gt; with JSON. Spec: <a href="/api/spec">/api/spec</a></small></p></header>
{"".join(forms)}</main><script src="/app.js"></script></body></html>"""


APP_JS = """
const readText = (f) => new Promise((ok, no) => { const r = new FileReader(); r.onload = () => ok(r.result); r.onerror = no; r.readAsText(f); });
const readB64 = (f) => new Promise((ok, no) => { const r = new FileReader(); r.onload = () => ok(String(r.result).split(',')[1]); r.onerror = no; r.readAsDataURL(f); });
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
    const res = await fetch('/api/' + form.dataset.op, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const data = await res.json();
    out.textContent = data.error ? 'Error: ' + data.error + (data.stdout ? '\\n\\n' + data.stdout : '')
      : (data.json ? JSON.stringify(data.json, null, 2) : data.stdout) + (data.files ? '\\n\\n' + Object.values(data.files).join('\\n') : '');
  } catch (err) { out.textContent = 'Request failed: ' + err; }
}));
"""


def make_server(host: str, port: int, data_dir: pathlib.Path) -> ThreadingHTTPServer:
    data_dir.mkdir(parents=True, exist_ok=True)
    handler = type("BoundHandler", (Handler,), {"data_dir": data_dir.resolve()})
    return ThreadingHTTPServer((host, port), handler)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog=f"{SPEC['cli']}-web", description=f"{SPEC['name']} hosted API and web app")
    ap.add_argument(
        "--host", default="127.0.0.1", help="use 0.0.0.0 to accept outside connections (e.g. in a container)"
    )
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    ap.add_argument("--data-dir", default=os.environ.get("DATA_DIR", "data"), help="where server-side state is kept")
    a = ap.parse_args(argv)
    srv = make_server(a.host, a.port, pathlib.Path(a.data_dir))
    print(f"{SPEC['name']} on http://{a.host}:{srv.server_address[1]}  (data: {pathlib.Path(a.data_dir).resolve()})")
    with contextlib.suppress(KeyboardInterrupt):
        srv.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
