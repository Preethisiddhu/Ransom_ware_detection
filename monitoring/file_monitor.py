import os
import sys
import time
import threading
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutTimeout

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from watchdog.observers import Observer
from watchdog.events    import FileSystemEventHandler
import requests

from config import (
    WATCH_PATHS, PROJECT_DIR, DEBOUNCE_SECONDS,
    SKIP_SCAN_EXTS, FINAL_EXTS, ENCRYPTED_EXTS,
    API_BASE
)
from scanner.file_scanner import scan_file

MY_PID = os.getpid()
_timers:   dict = {}
_file_ops: dict = {}
_executor = ThreadPoolExecutor(max_workers=2)

EXCLUDE_PREFIXES = [os.path.normpath(PROJECT_DIR)]


# ── Helpers ──────────────────────────────────────────────────

def _is_excluded(path: str) -> bool:
    norm = os.path.normpath(path)
    return any(norm.startswith(p) for p in EXCLUDE_PREFIXES)


def _find_process(path: str) -> str:
    try:
        import psutil
        norm = os.path.normpath(path)
        for proc in psutil.process_iter(["pid", "name", "open_files"]):
            try:
                if proc.info["pid"] == MY_PID:
                    continue
                name = (proc.info["name"] or "").lower()
                if name in ("python.exe", "python", "python3.exe"):
                    continue
                for f in (proc.info.get("open_files") or []):
                    if os.path.normpath(f.path) == norm:
                        return f"{proc.info['name']} (pid {proc.info['pid']})"
            except Exception:
                continue
    except Exception:
        pass
    return "unknown"


def _get_process_name(path: str) -> str:
    try:
        return _executor.submit(_find_process, path).result(timeout=2.0)
    except (FutTimeout, Exception):
        return "unknown"


def _pick_final_op(ops: list) -> str:
    for op in ("delete", "rename", "create", "modify"):
        if op in ops:
            return op
    return ops[-1] if ops else "modify"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _post(url: str, data: dict) -> bool:
    try:
        r = requests.post(url, json=data, timeout=3.0)
        if r.status_code in (200, 201):
            return True
        print(f"  [warn] POST {url} → {r.status_code}: {r.text[:120]}")
        return False
    except Exception as e:
        print(f"  [send fail] {url}: {e}")
        return False


def compute_base_risk(path: str, op: str) -> float:
    _, ext = os.path.splitext(path.lower())
    if ext in ENCRYPTED_EXTS:
        return 0.95
    score = 0.1
    if op == "delete":
        score = max(score, 0.3)
    if op == "rename" and ext not in FINAL_EXTS:
        score = max(score, 0.4)
    return score


# ── Flush ────────────────────────────────────────────────────

def _flush_file(path: str):
    try:
        ops = _file_ops.pop(path, [])
        _timers.pop(path, None)
        if not ops:
            return

        final_op  = _pick_final_op(ops)
        base_risk = compute_base_risk(path, final_op)
        _, ext    = os.path.splitext(path.lower())
        exists    = os.path.isfile(path)

        print(f"\n[flush] '{os.path.basename(path)}'  op={final_op}  ext={ext}  exists={exists}")

        process = _get_process_name(path)
        print(f"  [proc] {process}")

        if final_op == "delete":
            print(f"  [delete] clearing scan results")
            _post(f"{API_BASE}/file-deleted", {"path": path})

        content_score = 0.0
        scan_payload  = None

        should_scan = (
            final_op in ("create", "modify", "rename")
            and exists
            and ext not in SKIP_SCAN_EXTS
        )

        if should_scan:
            try:
                res = scan_file(path)
                content_score = float(res.get("score", 0.0))
                scan_payload  = {
                    "path":              path,
                    "exists":            True,
                    "score":             float(res.get("score", 0.0)),
                    "entropy":           float(res.get("entropy", 0.0)),
                    "is_encrypted":      bool(res.get("is_encrypted", False)),
                    "encryption_conf":   float(res.get("encryption_conf", 0.0)),
                    "malicious":         bool(res.get("malicious", False)),
                    "reasons":           list(res.get("reasons", [])),
                    "has_encrypted_ext": bool(res.get("has_encrypted_ext", False)),
                    "has_suspicious_str":bool(res.get("has_suspicious_str", False)),
                    "file_size":         int(res.get("file_size", 0)),
                    "scanned_at":        _now_iso(),
                    "trigger_op":        final_op,
                }
                tag = "🔴 MALICIOUS" if scan_payload["malicious"] else "✅ Clean"
                print(f"  [scan] {tag}  score={scan_payload['score']}  entropy={scan_payload['entropy']:.2f}")
                print(f"         encrypted={scan_payload['is_encrypted']}(conf={scan_payload['encryption_conf']:.2f})")
                print(f"         reasons={scan_payload['reasons']}")
            except Exception as exc:
                print(f"  [scan error] {exc}")
        else:
            print(f"  [skip scan] ext={ext}")

        risk = round(max(base_risk, content_score), 2)

        event_data = {
            "timestamp":    _now_iso(),
            "process_name": process,
            "pid":          0,
            "operation":    final_op,
            "path":         path,
            "risk_score":   risk,
            "file_size":    int(os.path.getsize(path)) if exists else 0,
            "extension":    ext,
            "is_encrypted": bool(scan_payload.get("is_encrypted", False)) if scan_payload else False,
        }

        ok1 = _post(f"{API_BASE}/events", event_data)
        print(f"  [post event]  {'OK ✓' if ok1 else 'FAIL ✗'}")

        if scan_payload:
            ok2 = _post(f"{API_BASE}/scan-results", scan_payload)
            print(f"  [post scan]   {'OK ✓' if ok2 else 'FAIL ✗'}")

    except Exception as e:
        import traceback
        print(f"[flush ERROR] {e}")
        traceback.print_exc()


# ── Queue ────────────────────────────────────────────────────

def queue_event(path: str, op: str):
    if _is_excluded(path):
        return

    _, ext = os.path.splitext(path.lower())

    if op == "modify" and ext in SKIP_SCAN_EXTS:
        return
    if op == "modify" and ext in FINAL_EXTS and "rename" in _file_ops.get(path, []):
        return

    print(f"[queue] op={op:8s}  file={os.path.basename(path)}")

    if path not in _file_ops:
        _file_ops[path] = []
    _file_ops[path].append(op)

    old = _timers.get(path)
    if old:
        old.cancel()

    wait = 1.0 if (op == "rename" and ext in FINAL_EXTS) else DEBOUNCE_SECONDS
    t = threading.Timer(wait, _flush_file, args=[path])
    t.daemon = True
    t.start()
    _timers[path] = t


# ── Watchdog Handler ─────────────────────────────────────────

class Handler(FileSystemEventHandler):
    def on_created(self, e):
        if not e.is_directory:
            queue_event(e.src_path, "create")

    def on_modified(self, e):
        if not e.is_directory:
            queue_event(e.src_path, "modify")

    def on_deleted(self, e):
        if not e.is_directory:
            queue_event(e.src_path, "delete")

    def on_moved(self, e):
        if not e.is_directory:
            queue_event(e.dest_path, "rename")


# ── Main ────────────────────────────────────────────────────

def run_monitor():
    valid = [p for p in WATCH_PATHS if os.path.isdir(p)]
    if not valid:
        print("[monitor] ERROR: No valid watch paths found!")
        return

    observer = Observer()
    handler  = Handler()
    print("[monitor] Watching paths:")
    for p in valid:
        print(f"  {p}")
        observer.schedule(handler, path=p, recursive=True)
    print(f"[monitor] Excluding: {EXCLUDE_PREFIXES}")
    observer.start()
    print("[monitor] Running... Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    run_monitor()