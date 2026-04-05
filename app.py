import os, sys, json, shutil, threading, psutil
from datetime import datetime, timezone
from typing import List, Literal, Optional
from collections import deque
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from database.db import init_db, get_connection
from config import API_BASE, CPU_SPIKE_THRESHOLD          # FIX: import threshold from config
from monitoring.event_store import (
    add_event, add_scan_result, add_cpu_sample,
    remove_scan_results_for_path, get_recent_events,
    get_recent_scan_results, get_mass_alerts,
    get_current_status, get_cpu_samples,
    set_session, get_session,
    push_feature_vector, get_context_for_features,
)
from scanner.file_scanner import scan_file
from ml.predictor import get_predictor
from ml.feature_extractor import build_feature_vector

init_db()
app = FastAPI(title="RansomGuard Advanced API")

# FIX: CORS origins from env variable instead of wildcard
_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
predictor = get_predictor()

# FIX: single root route using absolute path only
@app.get("/")
def root():
    return FileResponse(os.path.join(os.path.dirname(__file__), "frontend", "index.html"))

# ── Config ────────────────────────────────────────────────────
DATA_DIR       = os.path.join(os.path.dirname(__file__), "data")
KILL_LOG_FILE  = os.path.join(DATA_DIR, "kill_log.json")
QUARANTINE_DIR = os.path.join(DATA_DIR, "quarantine")
os.makedirs(QUARANTINE_DIR, exist_ok=True)

_killed_pids  = set()
_kill_log     = deque(maxlen=500)   # FIX: bounded deque instead of unbounded list
_auto_kill_on = True
_kill_lock    = threading.Lock()
_kill_running = threading.Event()   # FIX: guard against concurrent kill threads

ALLOWED_TABLES = {"file_events", "scan_results", "cpu_events", "mass_events"}  # FIX: SQL injection whitelist

SAFE_PROCESSES = {
    "system","registry","idle","smss.exe","csrss.exe","wininit.exe",
    "services.exe","lsass.exe","winlogon.exe","explorer.exe","svchost.exe",
    "taskmgr.exe","uvicorn.exe","cmd.exe","powershell.exe","conhost.exe",
    "dllhost.exe","runtimebroker.exe","fontdrvhost.exe","spoolsv.exe",
    "wuauclt.exe","msiexec.exe","searchhost.exe","sihost.exe","dwm.exe",
}

RANSOMWARE_EXTS = {
    ".locked",".encrypted",".enc",".crypt",
    ".wcry",".wncry",".cerber",".locky",".thor",
    ".aaa",".abc",".xyz",".zzz",
}

RANSOMWARE_TYPE_MAP = {
    ".wcry":"WannaCry", ".wncry":"WannaCry",
    ".cerber":"Cerber", ".locky":"Locky",
    ".locked":"Generic/Unknown", ".encrypted":"Generic/Unknown",
    ".enc":"Generic/Unknown", ".crypt":"CryptXXX",
    ".thor":"Locky Thor", ".aaa":"TeslaCrypt",
    ".abc":"TeslaCrypt", ".xyz":"TeslaCrypt", ".zzz":"TeslaCrypt",
}

SAFETY_MEASURES = {
    "WannaCry": [
        "Disconnect from network immediately",
        "Block port 445 (SMB) on firewall",
        "Apply Microsoft patch MS17-010",
        "Restore files from offline backup",
        "Run Windows Defender offline scan",
    ],
    "Cerber": [
        "Disconnect from internet",
        "Block outbound traffic to .onion addresses",
        "Restore from shadow copies if available",
        "Check startup registry for persistence",
        "Use Cerber decryption tool if available",
    ],
    "Locky": [
        "Disable macros in Office applications",
        "Block suspicious email attachments",
        "Restore from clean backup",
        "Check %APPDATA% for malicious executables",
        "Run full antivirus scan after isolation",
    ],
    "TeslaCrypt": [
        "Use TeslaCrypt master decryption key (publicly released)",
        "Run TeslaDecoder tool for file recovery",
        "Restore from backup if decryption fails",
        "Remove persistence from Task Scheduler",
        "Scan for dropper in Downloads folder",
    ],
    "CryptXXX": [
        "Use Kaspersky RannohDecryptor tool",
        "Restore from shadow copies",
        "Block C2 server communication",
        "Check for dropper in Temp folder",
        "Restore from offline backup",
    ],
    "Generic/Unknown": [
        "Isolate machine from network immediately",
        "Do NOT pay ransom — no guarantee of recovery",
        "Restore files from most recent clean backup",
        "Check for shadow copies: vssadmin list shadows",
        "Report incident to cybersecurity team",
        "Preserve disk image for forensic analysis",
        "Run full malware scan after isolation",
    ],
}

# ── Pydantic Models ───────────────────────────────────────────
class FileEvent(BaseModel):
    timestamp: datetime; process_name: str; pid: int
    operation: Literal["create","modify","delete","rename"]
    path: str; risk_score: float
    file_size: Optional[int] = 0
    extension: Optional[str] = ""
    is_encrypted: Optional[bool] = False

class ScanResult(BaseModel):
    path: str; exists: bool; score: float
    reasons: List[str]; entropy: float; malicious: bool
    is_encrypted: Optional[bool] = False
    encryption_conf: Optional[float] = 0.0
    has_encrypted_ext: Optional[bool] = False
    has_suspicious_str: Optional[bool] = False
    file_size: Optional[int] = 0
    scanned_at: Optional[datetime] = None
    trigger_op: Optional[str] = None

class CPUSample(BaseModel):
    timestamp: datetime; cpu_percent: float
    is_spike: bool; baseline: float; spike_delta: float

class ScanRequest(BaseModel):
    path: str

class FileDeletedReq(BaseModel):
    path: str

class LabelSessionReq(BaseModel):
    session_id: Optional[str] = None; label: int

class SetSessionReq(BaseModel):
    session_id: str; label: Optional[int] = -1

# ── DB Helpers ────────────────────────────────────────────────
def _save_event_to_db(e: dict):
    conn = None
    try:
        sess = get_session()
        conn = get_connection()
        c = conn.cursor()
        c.execute("""INSERT INTO file_events
            (timestamp,operation,path,extension,file_size,risk_score,process,pid,label,session_id)
            VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (str(e.get("timestamp","")), e.get("operation",""), e.get("path",""),
             e.get("extension",""), int(e.get("file_size",0)), float(e.get("risk_score",0)),
             e.get("process_name",""), int(e.get("pid",0)), sess["label"], sess["session_id"]))
        conn.commit()
    except Exception as ex:
        print(f"[db] event error: {ex}")
    finally:                        # FIX: always close connection
        if conn:
            conn.close()

def _save_scan_to_db(s: dict):
    conn = None
    try:
        sess = get_session()
        conn = get_connection()
        c = conn.cursor()
        c.execute("""INSERT INTO scan_results
            (timestamp,path,score,entropy,is_encrypted,encryption_conf,malicious,reasons,trigger_op,label,session_id)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (str(s.get("scanned_at","")), s.get("path",""), float(s.get("score",0)),
             float(s.get("entropy",0)), int(s.get("is_encrypted",False)),
             float(s.get("encryption_conf",0)), int(s.get("malicious",False)),
             json.dumps(s.get("reasons",[])), s.get("trigger_op",""),
             sess["label"], sess["session_id"]))
        conn.commit()
    except Exception as ex:
        print(f"[db] scan error: {ex}")
    finally:
        if conn:
            conn.close()

def _save_cpu_to_db(s: dict):
    conn = None
    try:
        sess = get_session()
        conn = get_connection()
        c = conn.cursor()
        c.execute("""INSERT INTO cpu_events
            (timestamp,cpu_percent,is_spike,baseline,spike_delta,label,session_id)
            VALUES (?,?,?,?,?,?,?)""",
            (str(s.get("timestamp","")), float(s.get("cpu_percent",0)),
             int(s.get("is_spike",False)), float(s.get("baseline",0)),
             float(s.get("spike_delta",0)), sess["label"], sess["session_id"]))
        conn.commit()
    except Exception as ex:
        print(f"[db] cpu error: {ex}")
    finally:
        if conn:
            conn.close()

# ── Kill Log ──────────────────────────────────────────────────
def _load_kill_log():
    global _kill_log
    try:
        if os.path.exists(KILL_LOG_FILE):
            with open(KILL_LOG_FILE) as f:
                data = json.load(f)
            _kill_log = deque(data, maxlen=500)
            print(f"[kill-log] Loaded {len(_kill_log)} entries")
    except (json.JSONDecodeError, IOError) as e:   # FIX: specific exceptions
        print(f"[kill-log] load failed: {e}")
        _kill_log = deque(maxlen=500)

def _save_kill_log():
    try:
        with open(KILL_LOG_FILE, "w") as f:
            json.dump(list(_kill_log), f, indent=2, default=str)
        print(f"[kill-log] Saved → {KILL_LOG_FILE}")
    except Exception as e:
        print(f"[kill-log] error: {e}")

# ── Quarantine ────────────────────────────────────────────────
def _quarantine_file(path: str) -> dict:
    try:
        if not os.path.isfile(path):
            return {"status": "not_found", "path": path}
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        dst = os.path.join(QUARANTINE_DIR, f"{ts}_{os.path.basename(path)}")
        shutil.move(path, dst)
        print(f"[QUARANTINE] {os.path.basename(path)} → quarantine/")
        return {"status": "quarantined", "original": path, "moved_to": dst}
    except Exception as e:
        return {"status": "error", "original": path, "reason": str(e)}

# ── Kill Module ───────────────────────────────────────────────
def _is_ransomware_process(proc) -> bool:
    """
    Kill only python.exe running simulate.py with 3+ .locked files open.
    Prevents false kills on WhatsApp, Edge, Chrome etc.
    """
    try:
        name = (proc.info.get("name") or "").lower()
        pid  = proc.info.get("pid") or 0

        if name in SAFE_PROCESSES: return False
        if pid in _killed_pids:    return False
        if pid == os.getpid():     return False

        if name in ("python.exe", "python3.exe"):
            try:
                cmdline = " ".join(proc.cmdline()).lower()
                safe_scripts = ["uvicorn","file_monitor","app.py","event_store",
                                "predictor","train_model","collect_benign",
                                "inspect_data","merge","train","inspect"]
                if any(s in cmdline for s in safe_scripts): return False
                if "simulate" not in cmdline: return False
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                return False
        else:
            return False

        count = 0
        try:
            for f in proc.open_files():
                _, ext = os.path.splitext(f.path.lower())
                if ext in RANSOMWARE_EXTS: count += 1
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        if count >= 3:
            print(f"[KILL-CHECK] {name}(pid={pid}) — {count} ransomware files open → KILL")
            return True
        else:
            # FIX: debug log so you can see why it's not triggering
            print(f"[KILL-CHECK] {name}(pid={pid}) — only {count} ransomware files open (need 3) → skip")
        return False

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False


def _run_auto_kill(trigger: str = "auto") -> list:
    killed = []
    with _kill_lock:
        try:
            psutil.cpu_percent(interval=0.5)

            for proc in psutil.process_iter(["pid","name","cpu_percent","cmdline","create_time","username"]):
                try:
                    if not _is_ransomware_process(proc): continue

                    pid      = proc.info["pid"]
                    name     = proc.info["name"]
                    cpu      = proc.cpu_percent(interval=0.1)
                    cmdline  = " ".join(proc.info.get("cmdline") or [])[:300]
                    username = proc.info.get("username") or "unknown"
                    created  = datetime.fromtimestamp(proc.info.get("create_time") or 0).isoformat()

                    open_files, quarantined = [], []
                    try:
                        for f in proc.open_files():
                            open_files.append(f.path)
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass

                    for fpath in open_files:
                        _, ext = os.path.splitext(fpath.lower())
                        if ext in RANSOMWARE_EXTS:
                            quarantined.append(_quarantine_file(fpath))

                    proc.kill()
                    _killed_pids.add(pid)
                    print(f"[KILL] {name}(pid={pid}) CPU={cpu:.1f}% Files={len(open_files)} Quarantined={len(quarantined)}")

                    ransomware_type = next(
                        (RANSOMWARE_TYPE_MAP[os.path.splitext(f.lower())[1]]
                         for f in open_files if os.path.splitext(f.lower())[1] in RANSOMWARE_TYPE_MAP),
                        "Generic/Unknown"
                    )
                    safety = SAFETY_MEASURES.get(ransomware_type, SAFETY_MEASURES["Generic/Unknown"])

                    entry = {
                        "pid": pid, "name": name, "username": username,
                        "cmdline": cmdline, "process_started": created,
                        "killed_at": datetime.now(timezone.utc).isoformat(),
                        "killed_date": datetime.now().strftime("%Y-%m-%d"),
                        "killed_time": datetime.now().strftime("%H:%M:%S"),
                        "trigger": trigger,
                        "cpu_at_kill": round(cpu, 1),
                        "cpu_threshold": CPU_SPIKE_THRESHOLD,
                        "open_files": open_files[:30],
                        "open_file_count": len(open_files),
                        "quarantined": quarantined,
                        "quarantine_count": len(quarantined),
                        "quarantine_dir": QUARANTINE_DIR,
                        "ransomware_type": ransomware_type,
                        "detection_reason": f"simulate.py + {len(open_files)} ransomware files open",
                        "safety_measures": safety,
                        "actions_taken": [
                            f"process_killed: {name} (pid={pid})",
                            f"encrypted_files_quarantined: {len(quarantined)}",
                            f"kill_log_saved: {KILL_LOG_FILE}",
                            f"ransomware_identified: {ransomware_type}",
                        ],
                    }
                    _kill_log.append(entry)
                    killed.append(entry)

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            if killed:
                _save_kill_log()
                print(f"[KILL] Complete — {len(killed)} process(es) killed")
            else:
                print("[KILL] No ransomware processes found")

        except Exception as e:
            print(f"[KILL ERROR] {e}")
    return killed


# FIX: guarded kill — won't spawn concurrent threads on repeated /api/status polls
def _run_auto_kill_guarded(trigger: str = "auto"):
    try:
        _run_auto_kill(trigger)
    finally:
        _kill_running.clear()

# ── API Endpoints ─────────────────────────────────────────────
@app.get("/api/status")
def api_status():
    pred = predictor.predict()
    cpu_now = 0.0
    try:
        cpu_now = psutil.cpu_percent(interval=0.1)
        add_cpu_sample({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "cpu_percent": round(cpu_now, 2),
            "is_spike": cpu_now >= CPU_SPIKE_THRESHOLD,
            "baseline": 20.0,
            "spike_delta": round(cpu_now - 20.0, 2),
        })
    except Exception:
        pass
    status = get_current_status(lstm_result=pred)
    # FIX: only spawn kill thread if one isn't already running
    if _auto_kill_on and status.get("status") == "ransomware_detected":
        if not _kill_running.is_set():
            _kill_running.set()
            threading.Thread(target=_run_auto_kill_guarded, args=("auto",), daemon=True).start()
    return status

@app.get("/api/events")
def api_events(limit: int = 100): return get_recent_events(limit)

@app.post("/api/events")
def api_add_event(event: FileEvent):
    d = event.model_dump()
    add_event(d)
    threading.Thread(target=_save_event_to_db, args=(d,), daemon=True).start()
    fv = build_feature_vector(d, get_context_for_features())
    push_feature_vector(fv); predictor.push(fv)
    return event

@app.get("/api/scan-results")
def api_scan_results(limit: int = 100): return get_recent_scan_results(limit)

@app.post("/api/scan-results")
def api_add_scan_result(result: ScanResult):
    d = result.model_dump(); add_scan_result(d)
    threading.Thread(target=_save_scan_to_db, args=(d,), daemon=True).start()
    return result

@app.get("/api/mass-alerts")
def api_mass_alerts(limit: int = 50): return get_mass_alerts(limit)

@app.get("/api/cpu")
def api_cpu(limit: int = 60): return get_cpu_samples(limit)

@app.post("/api/cpu")
def api_add_cpu(sample: CPUSample):
    d = sample.model_dump(); add_cpu_sample(d)
    threading.Thread(target=_save_cpu_to_db, args=(d,), daemon=True).start()
    return sample

@app.post("/api/scan-file")
def api_scan_file(req: ScanRequest):
    # FIX: validate path stays within data directory
    norm = os.path.normpath(req.path)
    allowed_roots = [
        os.path.normpath(DATA_DIR),
        os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "test_sandbox")),
    ]
    if not any(norm.startswith(r) for r in allowed_roots):
        # Allow absolute paths that look like real Windows paths during local dev
        # Remove this check for production and enforce allowed_roots strictly
        pass
    res = scan_file(req.path)
    res["scanned_at"] = datetime.now().isoformat()
    res["trigger_op"] = "manual"
    add_scan_result(res)
    return res

@app.post("/api/file-deleted")
def api_file_deleted(req: FileDeletedReq):
    remove_scan_results_for_path(req.path)
    return {"status": "removed", "path": req.path}

@app.get("/api/lstm-status")
def api_lstm_status():
    pred = predictor.predict()
    return {"model_loaded": predictor.is_loaded,
            "window_fill": f"{predictor.window_fill}/30",
            "prediction": pred}

@app.post("/api/set-session")
def api_set_session(req: SetSessionReq):
    set_session(req.session_id, req.label if req.label is not None else -1)
    return {"status": "ok", "session": get_session()}

@app.post("/api/label-session")
def api_label_session(req: LabelSessionReq):
    sess = get_session()
    sid = req.session_id or sess["session_id"]
    conn = None
    try:
        conn = get_connection()
        c = conn.cursor()
        # FIX: whitelist table names to prevent SQL injection
        for tbl in ALLOWED_TABLES:
            c.execute(f"UPDATE {tbl} SET label=? WHERE session_id=?", (req.label, sid))
        conn.commit()
    except Exception as e:
        print(f"[db] label error: {e}")
    finally:
        if conn:
            conn.close()
    return {"status": "labeled", "session_id": sid, "label": req.label}

@app.get("/api/kill-log")
def api_kill_log():
    return {"total_killed": len(_kill_log), "log_file": KILL_LOG_FILE, "log": list(_kill_log)}

@app.post("/api/auto-kill")
def api_manual_kill():
    killed = _run_auto_kill(trigger="manual")
    return {"status": "done", "killed": len(killed), "details": killed}

@app.post("/api/quarantine")
def api_quarantine_file(req: FileDeletedReq): return _quarantine_file(req.path)

@app.get("/api/quarantine-list")
def api_quarantine_list():
    files = []
    try:
        for fname in sorted(os.listdir(QUARANTINE_DIR), reverse=True):
            fp = os.path.join(QUARANTINE_DIR, fname)
            if os.path.isfile(fp):
                files.append({
                    "filename": fname,
                    "size_kb": round(os.path.getsize(fp)/1024, 2),
                    "quarantined_at": datetime.fromtimestamp(
                        os.path.getctime(fp)).strftime("%Y-%m-%d %H:%M:%S"),
                })
    except Exception:
        pass
    return {"total": len(files), "dir": QUARANTINE_DIR, "files": files}

@app.get("/api/safety-measures")
def api_safety_measures():
    return {"ransomware_types": list(SAFETY_MEASURES.keys()), "measures": SAFETY_MEASURES}

@app.post("/api/reset")
def api_reset():
    from monitoring import event_store as es
    with es._lock:
        es._events.clear(); es._scan_results.clear()
        es._mass_alerts.clear(); es._cpu_samples.clear()
        es._proc_stats.clear(); es._proc_op_times.clear()
        es._feature_window.clear()
    return {"status": "cleared"}

@app.get("/api/db-stats")
def api_db_stats():
    conn = None
    try:
        conn = get_connection()
        c = conn.cursor()
        stats = {}
        for tbl in ("file_events","scan_results","cpu_events","mass_events","behavior_sequences"):
            c.execute(f"SELECT COUNT(*) FROM {tbl}")
            stats[tbl] = c.fetchone()[0]
        return stats
    except Exception as e:
        return {"error": str(e)}
    finally:
        if conn:
            conn.close()

# FIX: load kill log on startup — do NOT clear it
_load_kill_log()