#!/usr/bin/env python3
"""Container supervisor for the honeypot dashboard.

In the Docker deployment this single process replaces what used to be a systemd
unit (serve.py) plus two cron jobs (generate.py and analytics.py every 5 min):

  * serve.py runs as a child process and owns the HTTP port.
  * generate.py + analytics.py are run on a fixed interval (REGEN_INTERVAL,
    default 300s — the same cadence as the old cron).

The web server is the liveness anchor: if serve.py exits, this supervisor exits
too, so Docker's restart policy recreates the container. A failing generate.py
or analytics.py run is logged and retried on the next tick — one bad run never
takes the dashboard offline.
"""
import os
import signal
import subprocess
import sys
import threading

APP_DIR = os.path.dirname(os.path.abspath(__file__))
PYTHON = sys.executable
INTERVAL = int(os.environ.get("REGEN_INTERVAL", "300"))   # seconds (old cron cadence)
JOB_TIMEOUT = int(os.environ.get("JOB_TIMEOUT", "600"))   # per-job hard cap

_stop = threading.Event()


def run_job(script):
    """Run a pipeline script once, surfacing its result to container logs."""
    label = os.path.splitext(script)[0]
    try:
        r = subprocess.run(
            [PYTHON, os.path.join(APP_DIR, script)],
            cwd=APP_DIR, capture_output=True, text=True, timeout=JOB_TIMEOUT,
        )
        last = ((r.stdout or "").strip().splitlines() or [""])[-1]
        print(f"[scheduler] {label}: rc={r.returncode} | {last}", flush=True)
        if r.returncode != 0 and (r.stderr or "").strip():
            print(f"[scheduler] {label} stderr: {r.stderr.strip()[-800:]}", flush=True)
    except subprocess.TimeoutExpired:
        print(f"[scheduler] {label}: TIMEOUT after {JOB_TIMEOUT}s", flush=True)
    except Exception as e:
        print(f"[scheduler] {label}: error {e}", flush=True)


def scheduler_loop():
    # Populate immediately so the dashboard is fresh shortly after boot, then
    # settle into the fixed interval.
    run_job("generate.py")
    run_job("analytics.py")
    while not _stop.wait(INTERVAL):
        run_job("generate.py")
        run_job("analytics.py")


def main():
    # serve.py owns the HTTP port; the scheduler owns regeneration, so disable
    # serve.py's own startup regen to avoid a duplicate generate.py at boot.
    env = dict(os.environ, SERVE_REGEN_ON_START="0")
    server = subprocess.Popen([PYTHON, os.path.join(APP_DIR, "serve.py")], env=env)

    def _shutdown(signum, frame):
        _stop.set()
        server.terminate()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    threading.Thread(target=scheduler_loop, daemon=True).start()

    rc = server.wait()
    _stop.set()
    print(f"[scheduler] serve.py exited rc={rc}; supervisor shutting down", flush=True)
    sys.exit(rc if rc is not None else 1)


if __name__ == "__main__":
    main()
