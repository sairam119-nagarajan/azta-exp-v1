"""Stabilization requirement 2 (item 7), offline: the REAL console page in a REAL headless browser shows the PEP's own confirmation count, also after a RESTORE. Fake broker, no MQTT.

    python -B rehearsal_tools/stb_console_counter_check.py --browser "C:/Program Files/Google/Chrome/Application/chrome.exe" --out-dir results/engineering/stabilization/console_counter_check

Sequence on device02 (AUTO_ELIGIBLE, active-authorized): two AE windows -> automatic QUARANTINE; RESTORE through the page's form; one anomalous window (the recovery window, held);
one more anomalous window (PEP count 1 of 2). After every step the page's confirmation cell is compared with the PEP filter's own pending count. JavaScript exceptions fail the check.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "tests"), str(ROOT / "rehearsal_tools")]

import core_console_browser_check as cb               # noqa: E402
import test_core_authority as tca                     # noqa: E402
from test_stabilization_r2_r4 import ae               # noqa: E402
from core_runtime.console import auth, server         # noqa: E402
from enforcement.model import QUARANTINE              # noqa: E402

PASSWORD = cb.PASSWORD
CELL = "Array.from(document.querySelectorAll('#fleet tbody tr')).find(r => r.dataset.device === 'device02').cells[{}].textContent"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--browser", required=True)
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args(argv)
    out = ROOT / args.out_dir
    out.mkdir(parents=True, exist_ok=False)
    checks, steps = {}, []
    with tempfile.TemporaryDirectory(prefix="azta-console-") as session, tempfile.TemporaryDirectory(prefix="azta-browser-", ignore_cleanup_errors=True) as profile:
        directory = Path(session)
        scope = tca.scope("active-authorized")
        h = tca.Harness(directory, mode="active-authorized", authority_scope=scope, ttl_s=3600)
        (directory / "authority_scope.json").write_text(json.dumps(scope.data), encoding="utf-8")
        (directory / "authority_map.json").write_text(json.dumps(tca.MAP.data), encoding="utf-8")
        console = server.Console(directory, pep_log=directory / "pep.jsonl", operator_record=auth.make_record(PASSWORD, "counter-check"), clock=h.clock)
        srv = server.serve(console, port=0)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        port = srv.server_address[1]
        process, page = cb.devtools(args.browser, profile)
        index = [0]

        def feed(state):
            h.feed(ae("device02", state, index[0], h.clock.utc_ns()))
            index[0] += 1

        def compare(name):
            pep = h.runner.filter.pending.get("device02", (None, 0))[1]
            expected = f"{pep}/2 (PEP)"
            page.wait(f"{CELL.format(10)}.startsWith({json.dumps(expected)})", timeout=20)
            shown = page.js(CELL.format(10))
            steps.append(dict(step=name, pep_filter_count=pep, page=shown, broker=page.js(CELL.format(11))))
            checks[f"counter_agrees_{name}"] = shown.startswith(expected)
        try:
            page.call("Runtime.enable")
            page.call("Page.enable")
            page.call("Page.navigate", url=f"http://127.0.0.1:{port}/")
            page.wait("document.readyState === 'complete' && !!document.getElementById('login')")
            page.js(f"document.getElementById('password').value = {json.dumps(PASSWORD)}; document.getElementById('login').requestSubmit(); true")
            page.wait("document.querySelectorAll('#fleet tbody tr').length === 10")
            feed(QUARANTINE)
            compare("after_one_anomalous_window")
            feed(QUARANTINE)
            page.wait(f"{CELL.format(11)}.includes('QUARANTINE')")
            checks["automatic_quarantine_shown"] = h.disabled("device02")
            compare("after_the_automatic_quarantine")
            page.js("document.querySelector('#fleet tbody tr[data-device=device02]').click(); true")
            page.wait("!document.getElementById('detail').hidden")
            page.js("document.getElementById('restore-confirm').value = 'device02'; document.getElementById('restore').requestSubmit(); true")
            page.wait("document.getElementById('restore-result').textContent.includes('RESTORE sent')")
            h.runner.process_available()
            page.wait(f"{CELL.format(11)}.includes('FULL_ACCESS')")
            checks["restore_verified_through_the_page"] = not h.disabled("device02")
            checks["recovery_window_shown_after_restore"] = bool(page.wait(f"{CELL.format(10)}.includes('recovery window')"))
            compare("after_restore")
            page.screenshot(out / "1_after_restore.png")
            feed(QUARANTINE)
            compare("after_the_held_recovery_window")
            feed(QUARANTINE)
            compare("after_one_counted_anomalous_window")
            checks["not_requarantined"] = not h.disabled("device02")
            page.screenshot(out / "2_one_of_two.png")
            checks["no_javascript_exception"] = not page.exceptions
        finally:
            srv.shutdown()
            srv.server_close()
            process.terminate()
            try:
                process.wait(timeout=15)
            except Exception:
                process.kill()
    document = dict(schema="azta.stabilization.console_counter_check", label="real page, real browser, real server and authority runner; FAKE broker; no MQTT", checks=checks, steps=steps, exceptions=page.exceptions,
                    all_pass=all(checks.values()), screenshots={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.glob("*.png"))})
    (out / "result.json").write_bytes((json.dumps(document, indent=1, sort_keys=True) + "\n").encode("utf-8"))
    print(json.dumps(dict(checks=checks, steps=steps), indent=1), "ALL_PASS" if document["all_pass"] else "FAIL")
    return 0 if document["all_pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
