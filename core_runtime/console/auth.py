"""Console authentication: one local operator record (PBKDF2-SHA256 of a password, never the password), server-side sessions with an unguessable cookie and a separate CSRF token, and rate limits. Localhost alone is never treated as authorization for a mutation.

    python -B -m core_runtime.console.auth create --out results/engineering/core_final/operator.json --operator-ref OPERATOR_NAME      # prompts for the password; the file stays Git-ignored
"""
import argparse
import getpass
import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets
import sys
import time

ITERATIONS = 390_000
SESSION_TTL_S = 8 * 3600
IDLE_TTL_S = 30 * 60
MAX_FAILURES, LOCKOUT_S = 5, 60
MUTATIONS_PER_MINUTE = 30
OPERATOR = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}\Z")
SCHEMA = "azta.core.operator_record"


def _hash(password, salt, iterations=ITERATIONS):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), iterations).hex()


def make_record(password, operator_ref):
    if not OPERATOR.fullmatch(operator_ref or "") or len(password or "") < 12:
        raise ValueError("an operator reference and a password of at least 12 characters are required")
    salt = secrets.token_hex(16)
    return dict(schema=SCHEMA, operator_ref=operator_ref, salt=salt, iterations=ITERATIONS, pbkdf2_sha256=_hash(password, salt))


class Authenticator:
    def __init__(self, record, *, clock=time.monotonic):
        if not isinstance(record, dict) or record.get("schema") != SCHEMA or not OPERATOR.fullmatch(str(record.get("operator_ref"))):
            raise ValueError("not an operator record")
        self.record, self.clock = record, clock
        self.sessions, self.failures, self.locked_until, self.mutations = {}, 0, 0.0, []

    def login(self, password):
        now = self.clock()
        if now < self.locked_until:
            return None, "LOCKED_OUT"
        expected = self.record["pbkdf2_sha256"]
        if not isinstance(password, str) or not hmac.compare_digest(_hash(password, self.record["salt"], self.record["iterations"]), expected):
            self.failures += 1
            if self.failures >= MAX_FAILURES:
                self.locked_until, self.failures = now + LOCKOUT_S, 0
            return None, "INVALID_CREDENTIALS"
        self.failures = 0
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        self.sessions[token] = dict(csrf=csrf, created=now, seen=now)
        return dict(token=token, csrf=csrf, operator_ref=self.record["operator_ref"]), None

    def session(self, token):
        entry = self.sessions.get(token) if isinstance(token, str) else None
        if entry is None:
            return None
        now = self.clock()
        if now - entry["created"] > SESSION_TTL_S or now - entry["seen"] > IDLE_TTL_S:
            self.sessions.pop(token, None)
            return None
        entry["seen"] = now
        return entry

    def logout(self, token):
        self.sessions.pop(token, None)

    def allow_mutation(self):
        now = self.clock()
        self.mutations = [t for t in self.mutations if now - t < 60]
        if len(self.mutations) >= MUTATIONS_PER_MINUTE:
            return False
        self.mutations.append(now)
        return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create")
    create.add_argument("--out", required=True)
    create.add_argument("--operator-ref", required=True)
    args = parser.parse_args(argv)
    password = getpass.getpass("console password: ")
    if password != getpass.getpass("again: "):
        print("the two entries differ", file=sys.stderr)
        return 2
    with Path(args.out).open("x", encoding="utf-8") as stream:
        json.dump(make_record(password, args.operator_ref), stream)
    print("written", args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
