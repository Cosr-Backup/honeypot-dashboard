#!/usr/bin/env python3
"""
Simple HTTP server for the Honeypot Dashboard.
Serves on localhost:9999, regenerates dashboard in the background.
"""

import http.server
import os
import subprocess
import sys
import threading
import time

# Network + paths overridable via env for containerized deploys. The defaults
# preserve the original on-host behavior (localhost:9999, files beside script).
HOST = os.environ.get("SERVE_HOST", "127.0.0.1")
PORT = int(os.environ.get("SERVE_PORT", "9999"))
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("HONEYPOT_DATA_DIR", SCRIPT_DIR)
DASHBOARD_PATH = os.path.join(DATA_DIR, "dashboard.html")
GENERATE_SCRIPT = os.path.join(SCRIPT_DIR, "generate.py")

# Minimum seconds between regenerations (avoid hammering GeoIP API)
MIN_REGEN_INTERVAL = 30
last_regen = 0
_regen_lock = threading.Lock()
_regen_running = False


def regenerate_sync():
    """Run generate.py synchronously. Called from background thread."""
    global last_regen, _regen_running
    print(f"[*] Regenerating dashboard...")
    try:
        result = subprocess.run(
            [sys.executable, GENERATE_SCRIPT],
            capture_output=True, text=True, timeout=300,
            cwd=SCRIPT_DIR
        )
        if result.returncode != 0:
            print(f"[!] Generate failed: {result.stderr[-500:]}")
        else:
            print(result.stdout.strip()[-500:])
        last_regen = time.time()
    except subprocess.TimeoutExpired:
        print(f"[!] Generate timed out after 300s")
    except Exception as e:
        print(f"[!] Error regenerating: {e}")
    finally:
        with _regen_lock:
            _regen_running = False


def regenerate():
    """Kick off regeneration in background if not already running."""
    global _regen_running
    now = time.time()
    if now - last_regen < MIN_REGEN_INTERVAL:
        return
    with _regen_lock:
        if _regen_running:
            return
        _regen_running = True
    t = threading.Thread(target=regenerate_sync, daemon=True)
    t.start()


class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=SCRIPT_DIR, **kwargs)

    def do_GET(self):
        if self.path in ("/", "/dashboard.html", "/index.html"):
            # Regeneration handled by cron every 5 minutes
            # regenerate()  # removed — avoid duplicate regeneration
            self.path = "/dashboard.html"
            # Serve whatever HTML we have (even if stale)
            try:
                with open(DASHBOARD_PATH, "r") as f:
                    content = f.read()
                # Add auto-refresh if not present
                if '<meta http-equiv="refresh"' not in content:
                    content = content.replace(
                        "<head>",
                        '<head>\n<meta http-equiv="refresh" content="30">',
                        1
                    )
                encoded = content.encode()
                self.send_response(200)
                self.send_header("Content-type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(encoded)))
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.end_headers()
                self.wfile.write(encoded)
                return
            except FileNotFoundError:
                self.send_response(200)
                self.send_header("Content-type", "text/html; charset=utf-8")
                msg = "<html><body style='background:#0a0a0a;color:#00ff41;font-family:monospace;padding:40px;text-align:center'><h1>仪表盘生成中...</h1><p>首次运行 LLM 生成需要几分钟，请稍后刷新。</p><meta http-equiv='refresh' content='15'></body></html>".encode()
                self.send_header("Content-Length", str(len(msg)))
                self.end_headers()
                self.wfile.write(msg)
                return
        self.send_error(404, "Not found")
        return

    def log_message(self, format, *args):
        print(f"[{self.log_date_time_string()}] {format % args}")


def main():
    # Start regeneration in background — don't block the server. In the
    # container the scheduler owns periodic regeneration, so this startup
    # kick is opt-out via SERVE_REGEN_ON_START=0.
    if os.environ.get("SERVE_REGEN_ON_START", "1") != "0":
        regenerate()

    server = http.server.HTTPServer((HOST, PORT), DashboardHandler)
    print(f"\n{'='*60}")
    print(f"  Honeypot Dashboard Server")
    print(f"  http://{HOST}:{PORT}")
    print(f"  Auto-refresh: 30 seconds")
    print(f"  Press Ctrl+C to stop")
    print(f"{'='*60}\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        server.shutdown()


if __name__ == "__main__":
    main()
