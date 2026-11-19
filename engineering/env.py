"""Host-side helpers for the isolated engineering environment: engineering-only credentials, run directories and the compose command shape.

    python -m engineering.env secrets          generate (exclusively, mode 0600) the engineering credentials under results/engineering/secrets
    python -m engineering.env run-dir RUN_ID   create the per-run evidence directory tree under results/engineering/runs/RUN_ID

Credentials are random 32-byte URL-safe tokens that exist only in Git-ignored files under results/engineering (`results/**` is excluded); an existing file is never overwritten or
printed; the research credentials in pep/mosquitto/secrets are never read, copied or referenced. Nothing here starts Docker.
"""
import argparse
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
ENGINEERING = ROOT / "results" / "engineering"
SECRETS = ENGINEERING / "secrets"
PROJECT = os.environ.get("AZTA_ENG_PROJECT", "azta-eng")          # "azta-pilot" selects the dedicated pilot project (own broker, volume, network); the research project is refused below
OVERLAY = os.environ.get("AZTA_ENG_COMPOSE_OVERLAY")                # optional extra compose file (compose.pilot.yaml)
COMPOSE_FILE = "compose.engineering.yaml"
RESEARCH_PROJECT = "azta-journal"
RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
PRINCIPALS = ("admin",) + tuple(f"azta-device-{n:02d}" for n in range(1, 11)) + ("azta-pdp", "azta-operations-receiver", "azta-observer", "azta-eng-isolation-sentinel", "azta-pilot-isolation-sentinel")
RUN_SUBDIRS = ("observation", "gate5d3_workload", "gate5d3_fixtures", "pep", "audit", "decisions", "probes", "collection", "logs")


def secret_file(principal):
    return SECRETS / ("admin-password" if principal == "admin" else f"{principal}-password")


def compose_prefix():
    """The only compose command shape this tooling issues: the engineering file and the engineering project, nothing else."""
    if PROJECT == RESEARCH_PROJECT:
        raise SystemExit("REFUSED the engineering tooling never targets the research project")
    return ["docker", "compose", "-p", PROJECT, "-f", COMPOSE_FILE] + (["-f", OVERLAY] if OVERLAY else [])


def generate_secrets():
    SECRETS.mkdir(parents=True, exist_ok=True)
    created = []
    for principal in PRINCIPALS:
        path = secret_file(principal)
        if path.exists():
            continue
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(secrets.token_urlsafe(32) + "\n")
        created.append(principal)
    return created


def make_run_dir(run_id):
    if not RUN_ID.fullmatch(run_id or ""):
        raise ValueError("invalid run id")
    base = ENGINEERING / "runs" / run_id
    base.mkdir(parents=True, exist_ok=False)
    for name in RUN_SUBDIRS:
        (base / name).mkdir()
    return base


def stop_run_containers(run_id, logs):
    """Retain logs and remove only this engineering run's observer/publisher.

    The broker cannot be selected; both names and Compose project are checked.
    """
    if not RUN_ID.fullmatch(run_id or ""):
        raise ValueError("invalid run id")
    for name in (f"{PROJECT}-ob-{run_id}", f"{PROJECT}-wl-{run_id}"):
        inspected = subprocess.run(["docker", "inspect", "--format", '{{index .Config.Labels "com.docker.compose.project"}}', name],
                                   capture_output=True, text=True, timeout=30)
        if inspected.returncode != 0:
            continue
        if inspected.stdout.strip() != PROJECT:
            raise ValueError("run container does not belong to the engineering project")
        subprocess.run(["docker", "stop", "-t", "10", name], capture_output=True, timeout=30, check=True)
        text = subprocess.run(["docker", "logs", name], capture_output=True, text=True, timeout=30)
        (Path(logs) / f"{name}.log").write_text(text.stdout + text.stderr, encoding="utf-8")
        subprocess.run(["docker", "rm", name], capture_output=True, timeout=30, check=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("secrets")
    run = sub.add_parser("run-dir")
    run.add_argument("run_id")
    args = parser.parse_args(argv)
    try:
        if args.command == "secrets":
            created = generate_secrets()
            print(f"ENGINEERING_SECRETS created={len(created)} existing={len(PRINCIPALS) - len(created)} directory=results/engineering/secrets (values never printed)")
        else:
            print(f"ENGINEERING_RUN_DIR {make_run_dir(args.run_id).relative_to(ROOT).as_posix()}")
    except (ValueError, OSError) as exc:
        print(f"ENGINEERING_ENV_REFUSED {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
