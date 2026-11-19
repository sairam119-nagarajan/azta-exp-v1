"""The operator console server: a typed API over durable files (`core_runtime.state`) and one append-only intent log. Loopback only.

The browser never sends a broker command, a topic, an address or a credential. A mutation is a typed intent, written to the hash-chained intent log; the guarded PEP service (`enforcement.authority.AuthorityRunner`) is the only process that acts on it, and it rechecks everything. A restart of
this server loses only login sessions: state comes from the files, and it re-reads them on every request. A failure to read a file is shown as UNKNOWN; the page shows STALE when the server stops answering.
"""
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import threading
import time
from urllib.parse import urlsplit

from core_runtime import state as st
from core_runtime.console.auth import Authenticator
from enforcement.audit import AuditLog
from enforcement.authority import AuthorityScope, INTENT_KINDS, make_intent
from enforcement.clock import SystemClock
from enforcement.errors import AuditIntegrityError, EnforcementError

HOSTS = ("127.0.0.1", "localhost")
MAX_BODY = 64 * 1024
KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@-]{7,127}\Z")
REVIEW = re.compile(r"rv-[0-9a-f]{24}\Z")
STATIC = {"/": ("page.html", "text/html; charset=utf-8"), "/app.js": ("app.js", "text/javascript; charset=utf-8"), "/app.css": ("app.css", "text/css; charset=utf-8")}
HEADERS = {"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store",
           "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"}


class Console:
    """Everything a request needs. `session_directory` holds the recommendations, the intents and (when one exists) the pinned authority scope and map."""

    def __init__(self, session_directory, *, pep_log=None, operator_record, clock=None, simulator=None, presence_file=None):
        self.directory = Path(session_directory)
        self.authority_map = self._json("authority_map.json")
        self.files = st.SessionFiles(self.directory, pep_log=pep_log or self.directory.parent / "pep" / "continuous.jsonl", authority_map=self.authority_map)
        self.auth = Authenticator(operator_record)
        self.clock = clock or SystemClock()
        self.lock = threading.Lock()
        self.presence_file = Path(presence_file) if presence_file else None
        self.simulator = simulator               # the attack-control directory of a valid simulator session, or None (the controls stay disabled)

    def _json(self, name):
        try:
            return json.loads((self.directory / name).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def log_request(self, **fields):
        """One line per mutating request that reached the console, for the session record: what was asked, the answer and which client sent it. It holds no credential and decides nothing; a failure to write it refuses nothing."""
        try:
            with self.lock, (self.directory / "console_requests.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(dict(fields, utc_ns=self.clock.utc_ns()), sort_keys=True) + "\n")
        except OSError:
            pass

    def session_info(self, now):
        scope = None
        data = self._json("authority_scope.json")
        if data is not None:
            try:
                scope = AuthorityScope(data)
            except EnforcementError:
                return dict(mode="UNKNOWN", scope="INVALID", approval_valid=False)
        if scope is None:
            return dict(mode="SHADOW_OR_NOT_RUNNING", scope=None, approval_valid=False, note="no written authority scope in this session: nothing can be applied")
        return dict(mode=scope.data["mode"], scope=scope.scope_id, session_run_id=scope.data["session_run_id"], environment=scope.data["environment"], approval_valid=scope.data["issued_utc_ns"] <= now < scope.data["expires_utc_ns"], expires_utc_ns=scope.data["expires_utc_ns"],
                    devices={d: dict(actions=e["actions"], automatic=e["automatic"]) for d, e in scope.data["devices"].items()})

    def view(self):
        now = self.clock.utc_ns()
        if self.files.authority_map is None:       # the console may be open before the session creates its directory
            self.files.authority_map = self.authority_map = self._json("authority_map.json")
        self.files.session = self.session_info(now)
        return dict(st.snapshot(self.files, now), guide=self.guide())

    def guide(self):
        """The last instructions of the session's scenario driver, so the operator need not watch a second window. Display only."""
        try:
            return (self.directory / "owner_guide.log").read_text(encoding="utf-8").splitlines()[-8:]
        except OSError:
            return []

    def mark_present(self):
        """A signed-in page is polling. A session and its driver read this: nobody present, nothing starts or continues. It records only the time; a failure to write means absent, which is the safe answer."""
        if self.presence_file is None:
            return
        try:
            temporary = self.presence_file.with_suffix(".tmp")
            temporary.write_text(json.dumps(dict(utc_ns=self.clock.utc_ns())), encoding="utf-8")
            temporary.replace(self.presence_file)
        except OSError:
            pass

    def write_intent(self, intent):
        """One writer at a time; a broken or foreign log refuses instead of being repaired."""
        with self.lock:
            log = AuditLog.open_or_create(self.files.intents, self.clock)
            if any(e["body"].get("idempotency_key") == intent["idempotency_key"] for e in log.entries):
                return dict(accepted=True, duplicate=True)
            entry = log.append("INTENT", **intent)
            return dict(accepted=True, duplicate=False, intent_seq=entry["seq"])

    def submit(self, operator_ref, body):
        """Typed validation of one operator intent. For a review the pins come from the PEP's own record and the client's echo must equal them: an operator always approves exactly what was displayed."""
        kind = body.get("kind")
        key = body.get("idempotency_key")
        if kind not in INTENT_KINDS or not (isinstance(key, str) and KEY.fullmatch(key)):
            return 400, dict(error="MALFORMED_INTENT")
        view = self.view()
        if view["problems"].get("pep_log"):
            return 503, dict(error="PEP_LOG_UNREADABLE", detail=view["problems"]["pep_log"])
        if not view["session"].get("approval_valid") and kind not in ("STOP_NEW_ACTIONS", ):
            return 409, dict(error="NO_VALID_AUTHORITY_SCOPE")
        if kind in ("STOP_NEW_ACTIONS", "RESUME_ACTIONS"):
            return 202, self.write_intent(make_intent(kind, operator_ref=operator_ref, idempotency_key=key))
        device = body.get("device")
        if device not in st.DEVICES:
            return 400, dict(error="UNKNOWN_DEVICE")
        note = body.get("note")
        if note is not None and not (isinstance(note, str) and len(note) <= 300):
            return 400, dict(error="NOTE_TOO_LONG")
        row = next(d for d in view["devices"] if d["device"] == device)
        if kind == "RESTORE":
            if body.get("confirm_device") != device:
                return 400, dict(error="RESTORE_NOT_CONFIRMED")
            if body.get("generation") != row["generation"]:
                return 409, dict(error="STALE_VIEW", generation=row["generation"])
            # A RESTORE supersedes every review still pending for the device (enforcement.authority, even when the broker is already at FULL_ACCESS). It must never do so unseen: the
            # operator names exactly the pending reviews it will cancel, or it is refused (stabilization stb-l02, C1 finding).
            pending_ids = sorted(r["review_id"] for r in row.get("pending_reviews") or [])
            if pending_ids and sorted(body.get("acknowledge_superseded") or []) != pending_ids:
                return 409, dict(error="RESTORE_WOULD_CANCEL_PENDING_REVIEWS", pending_review_ids=pending_ids,
                                 pending_reviews=[dict(review_id=r["review_id"], action=r["action"], origin=r["origin"]) for r in row.get("pending_reviews") or []])
            return 202, self.write_intent(make_intent("RESTORE", operator_ref=operator_ref, idempotency_key=key, device=device, confirm_device=device, generation=row["generation"]))
        review_id = body.get("review_id")
        if not (isinstance(review_id, str) and REVIEW.fullmatch(review_id)):
            return 400, dict(error="MALFORMED_REVIEW_ID")
        review = next((r for r in view["reviews"] if r["review_id"] == review_id), None)
        if review is None or review["device"] != device:
            return 404, dict(error="REVIEW_UNKNOWN")
        if review["state"] != "PENDING":
            return 409, dict(error="REVIEW_NOT_PENDING", state=review["state"])
        if self.clock.utc_ns() >= review["expires_utc_ns"]:
            return 409, dict(error="REVIEW_EXPIRED")
        for name in ("action", "evidence_ids", "generation"):
            if body.get(name) != review[name]:
                return 409, dict(error="STALE_VIEW", field=name)
        return 202, self.write_intent(make_intent(kind, operator_ref=operator_ref, idempotency_key=key, device=device, review_id=review_id, action=review["action"], evidence_ids=review["evidence_ids"], generation=review["generation"], note=note))

    def simulator_view(self):
        from engineering import attack_control as ac
        return dict(enabled=self.simulator is not None, catalogue=sorted(ac.CATALOGUE), status=ac.read_status(self.simulator) if self.simulator is not None else None,
                    limits="bounded DEVELOPMENT_ONLY scenarios of the running session; allowlisted simulated devices only; no address, topic or credential input")

    def simulate(self, operator_ref, body):
        if self.simulator is None:
            return 409, dict(error="NO_SIMULATOR_SESSION")
        from engineering import attack_control as ac
        action, device, anomaly = body.get("action"), body.get("device"), body.get("anomaly")
        if action not in ac.ACTIONS or device not in st.DEVICES or (action == "start" and anomaly not in ac.CATALOGUE):
            return 400, dict(error="NOT_ALLOWLISTED")
        ok, message = ac.perform(self.simulator, action, device, anomaly if action == "start" else None, None, operator_ref, timeout_s=5.0)     # refuses unless the run's control channel reports RUNNING with fresh status
        return (202, dict(accepted=True, outcome=message)) if ok else (409, dict(error="SIMULATOR_REFUSED", detail=str(message)[:200]))


def make_handler(console, port):
    allowed_hosts = {f"{h}:{port}" for h in HOSTS}
    allowed_origins = {f"http://{h}" for h in allowed_hosts}
    static_dir = Path(__file__).parent / "static"

    class Handler(BaseHTTPRequestHandler):
        server_version, sys_version = "azta-console", ""

        def log_message(self, *args):
            pass

        def _send(self, code, payload, *, content_type="application/json; charset=utf-8", extra=()):
            blob = payload if isinstance(payload, bytes) else json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(blob)))
            for name, value in HEADERS.items():
                self.send_header(name, value)
            for name, value in extra:
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(blob)

        def _host_ok(self):
            return self.headers.get("Host") in allowed_hosts

        def _token(self):
            jar = cookies.SimpleCookie()
            try:
                jar.load(self.headers.get("Cookie") or "")
            except cookies.CookieError:
                return None
            return jar["azta_session"].value if "azta_session" in jar else None

        def _session(self):
            return console.auth.session(self._token())

        def do_GET(self):
            if not self._host_ok():
                return self._send(403, dict(error="BAD_HOST"))
            path = urlsplit(self.path).path
            if path in STATIC:
                name, content_type = STATIC[path]
                return self._send(200, (static_dir / name).read_bytes(), content_type=content_type)
            if self._session() is None:
                return self._send(401, dict(error="LOGIN_REQUIRED"))
            if path == "/api/state":
                console.mark_present()
                return self._send(200, console.view())
            if path == "/api/simulator":
                return self._send(200, console.simulator_view())
            if path == "/api/metrics":
                now = console.clock.utc_ns()
                console.files.session = console.session_info(now)
                return self._send(200, st.metrics(console.files, now))
            if path.startswith("/api/device/"):
                detail = st.device_detail(console.files, path.rsplit("/", 1)[1])
                return self._send(200 if detail else 404, detail or dict(error="UNKNOWN_DEVICE"))
            return self._send(404, dict(error="NOT_FOUND"))

        def do_POST(self):
            try:
                length = int(self.headers.get("Content-Length") or -1)
            except ValueError:
                length = -1
            if not 0 <= length <= MAX_BODY:
                self.close_connection = True
                return self._send(413, dict(error="BODY_SIZE"))
            raw = self.rfile.read(length)                  # the bounded body is read before any refusal: answering with unread bytes can reset the connection on Windows, and the client then never sees the refusal. It is not parsed or used until the checks pass
            if not self._host_ok() or self.headers.get("Origin") not in allowed_origins:
                return self._send(403, dict(error="BAD_ORIGIN"))
            if (self.headers.get("Content-Type") or "").split(";")[0].strip() != "application/json":
                return self._send(415, dict(error="JSON_REQUIRED"))
            try:
                body = json.loads(raw.decode("utf-8"), parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))
            except (ValueError, UnicodeDecodeError):
                return self._send(400, dict(error="NOT_JSON"))
            if not isinstance(body, dict):
                return self._send(400, dict(error="NOT_AN_OBJECT"))
            path = urlsplit(self.path).path
            if path == "/api/login":
                login, error = console.auth.login(body.get("password"))
                if error:
                    return self._send(429 if error == "LOCKED_OUT" else 401, dict(error=error))
                return self._send(200, dict(csrf=login["csrf"], operator_ref=login["operator_ref"]), extra=[("Set-Cookie", f"azta_session={login['token']}; HttpOnly; SameSite=Strict; Path=/")])
            session = self._session()
            if session is None:
                return self._send(401, dict(error="LOGIN_REQUIRED"))
            if self.headers.get("X-CSRF-Token") != session["csrf"]:
                return self._send(403, dict(error="BAD_CSRF"))
            if path == "/api/logout":
                console.auth.logout(self._token())
                return self._send(200, dict(ok=True), extra=[("Set-Cookie", "azta_session=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/")])
            if not console.auth.allow_mutation():
                return self._send(429, dict(error="RATE_LIMITED"))
            try:
                if path == "/api/intent":
                    code, payload = console.submit(console.auth.record["operator_ref"], body)
                elif path == "/api/simulator":
                    code, payload = console.simulate(console.auth.record["operator_ref"], body)
                else:
                    code, payload = 404, dict(error="NOT_FOUND")
            except (EnforcementError, AuditIntegrityError) as exc:
                code, payload = 409, dict(error=getattr(exc, "code", type(exc).__name__))
            console.log_request(path=path, code=code, kind=body.get("kind"), device=body.get("device"), accepted_key=body.get("idempotency_key") if code == 202 else None, origin=self.headers.get("Origin"), user_agent=(self.headers.get("User-Agent") or "")[:160])
            return self._send(code, payload)

    return Handler


def serve(console, *, port=8765, host="127.0.0.1"):
    if host not in HOSTS:
        raise ValueError("the console serves on the loopback interface only")
    server = ThreadingHTTPServer((host, port), make_handler(console, port))
    if port == 0:
        server.RequestHandlerClass = make_handler(console, server.server_address[1])
    return server


def main(args):
    record = json.loads(Path(args.operator_file).read_text(encoding="utf-8"))
    console = Console(args.session_dir, pep_log=args.pep_log, operator_record=record, simulator=Path(args.simulator_control) if args.simulator_control else None, presence_file=args.presence_file)
    server = serve(console, port=args.port)
    print(f"AZTA operator console on http://127.0.0.1:{server.server_address[1]}/ (session directory {args.session_dir})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
