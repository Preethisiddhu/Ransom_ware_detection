import os
import sys
import json
import threading
from datetime import datetime
from typing import List, Literal, Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database.db    import init_db, get_connection
from config         import API_BASE
from monitoring.event_store import (
    add_event, add_scan_result, add_cpu_sample,
    remove_scan_results_for_path,
    get_recent_events, get_recent_scan_results,
    get_mass_alerts, get_suspicious_processes,
    get_current_status, get_cpu_samples,
    set_session, get_session,
    push_feature_vector, get_feature_window, get_context_for_features,
)
from scanner.file_scanner    import scan_file
from ml.predictor            import get_predictor
from ml.feature_extractor    import build_feature_vector

# Initialise DB on startup
init_db()

app = FastAPI(title="RansomGuard Advanced API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)

predictor = get_predictor()


# ── Pydantic Models ──────────────────────────────────────────

class FileEvent(BaseModel):
    timestamp:    datetime
    process_name: str
    pid:          int
    operation:    Literal["create","modify","delete","rename"]
    path:         str
    risk_score:   float
    file_size:    Optional[int] = 0
    extension:    Optional[str] = ""
    is_encrypted: Optional[bool] = False

class ScanResult(BaseModel):
    path:              str
    exists:            bool
    score:             float
    reasons:           List[str]
    entropy:           float
    malicious:         bool
    is_encrypted:      Optional[bool]  = False
    encryption_conf:   Optional[float] = 0.0
    has_encrypted_ext: Optional[bool]  = False
    has_suspicious_str:Optional[bool]  = False
    file_size:         Optional[int]   = 0
    scanned_at:        Optional[datetime] = None
    trigger_op:        Optional[str]   = None

class CPUSample(BaseModel):
    timestamp:   datetime
    cpu_percent: float
    is_spike:    bool
    baseline:    float
    spike_delta: float

class MassAlert(BaseModel):
    timestamp:    datetime
    process_name: str
    operation:    str
    count:        int
    window_secs:  int
    severity:     str

class ScanRequest(BaseModel):
    path: str

class FileDeletedReq(BaseModel):
    path: str

class LabelSessionReq(BaseModel):
    session_id: Optional[str] = None
    label: int

class SetSessionReq(BaseModel):
    session_id: str
    label: Optional[int] = -1


# ── Helpers ──────────────────────────────────────────────────

def _save_event_to_db(event: dict):
    try:
        sess = get_session()
        conn = get_connection()
        c    = conn.cursor()
        c.execute("""
            INSERT INTO file_events
            (timestamp, operation, path, extension, file_size,
             risk_score, process, pid, label, session_id)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (
            str(event.get("timestamp","")),
            event.get("operation",""),
            event.get("path",""),
            event.get("extension",""),
            int(event.get("file_size",0)),
            float(event.get("risk_score",0)),
            event.get("process_name",""),
            int(event.get("pid",0)),
            sess["label"],
            sess["session_id"],
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[db] event save error: {e}")

def _save_scan_to_db(scan: dict):
    try:
        sess = get_session()
        conn = get_connection()
        c    = conn.cursor()
        c.execute("""
            INSERT INTO scan_results
            (timestamp, path, score, entropy, is_encrypted, encryption_conf,
             malicious, reasons, trigger_op, label, session_id)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (
            str(scan.get("scanned_at","")),
            scan.get("path",""),
            float(scan.get("score",0)),
            float(scan.get("entropy",0)),
            int(scan.get("is_encrypted",False)),
            float(scan.get("encryption_conf",0)),
            int(scan.get("malicious",False)),
            json.dumps(scan.get("reasons",[])),
            scan.get("trigger_op",""),
            sess["label"],
            sess["session_id"],
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[db] scan save error: {e}")

def _save_cpu_to_db(sample: dict):
    try:
        sess = get_session()
        conn = get_connection()
        c    = conn.cursor()
        c.execute("""
            INSERT INTO cpu_events
            (timestamp, cpu_percent, is_spike, baseline, spike_delta, label, session_id)
            VALUES (?,?,?,?,?,?,?)
        """, (
            str(sample.get("timestamp","")),
            float(sample.get("cpu_percent",0)),
            int(sample.get("is_spike",False)),
            float(sample.get("baseline",0)),
            float(sample.get("spike_delta",0)),
            sess["label"],
            sess["session_id"],
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[db] cpu save error: {e}")


# ── Core API Endpoints ───────────────────────────────────────

@app.get("/api/status")
def api_status():
    pred = predictor.predict()
    # Get live CPU via psutil directly (no cpu_monitor needed)
    try:
        import psutil
        cpu_now = psutil.cpu_percent(interval=0.1)
        from datetime import datetime, timezone
        sample = {
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "cpu_percent": round(cpu_now, 2),
            "is_spike":    cpu_now >= 70.0,
            "baseline":    20.0,
            "spike_delta": round(cpu_now - 20.0, 2),
        }
        add_cpu_sample(sample)
    except Exception:
        pass
    return get_current_status(lstm_result=pred)

@app.get("/api/events")
def api_events(limit: int = 100):
    return get_recent_events(limit)

@app.post("/api/events")
def api_add_event(event: FileEvent):
    d = event.model_dump()
    add_event(d)
    threading.Thread(target=_save_event_to_db, args=(d,), daemon=True).start()

    ctx = get_context_for_features()
    fv  = build_feature_vector(d, ctx)
    push_feature_vector(fv)
    predictor.push(fv)

    return event

@app.get("/api/scan-results")
def api_scan_results(limit: int = 100):
    return get_recent_scan_results(limit)

@app.post("/api/scan-results")
def api_add_scan_result(result: ScanResult):
    d = result.model_dump()
    add_scan_result(d)
    threading.Thread(target=_save_scan_to_db, args=(d,), daemon=True).start()
    return result

@app.get("/api/mass-alerts")
def api_mass_alerts(limit: int = 50):
    return get_mass_alerts(limit)

@app.get("/api/suspicious-processes")
def api_suspicious_processes():
    return get_suspicious_processes()

@app.get("/api/cpu")
def api_cpu(limit: int = 60):
    return get_cpu_samples(limit)

@app.post("/api/cpu")
def api_add_cpu(sample: CPUSample):
    d = sample.model_dump()
    add_cpu_sample(d)
    threading.Thread(target=_save_cpu_to_db, args=(d,), daemon=True).start()
    return sample

@app.post("/api/scan-file")
def api_scan_file(req: ScanRequest):
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
    return {
        "model_loaded":    predictor.is_loaded,
        "window_fill":     f"{predictor.window_fill}/{30}",
        "prediction":      pred,
    }

@app.post("/api/set-session")
def api_set_session(req: SetSessionReq):
    set_session(req.session_id, req.label if req.label is not None else -1)
    return {"status": "ok", "session": get_session()}

@app.post("/api/label-session")
def api_label_session(req: LabelSessionReq):
    sess = get_session()
    sid  = req.session_id or sess["session_id"]
    try:
        conn = get_connection()
        c    = conn.cursor()
        for tbl in ("file_events","scan_results","cpu_events","mass_events"):
            c.execute(f"UPDATE {tbl} SET label=? WHERE session_id=?", (req.label, sid))
        conn.commit()
        conn.close()
        print(f"[db] Labeled session '{sid}' → {req.label}")
    except Exception as e:
        print(f"[db] label error: {e}")
    return {"status": "labeled", "session_id": sid, "label": req.label}

@app.post("/api/reset")
def api_reset():
    from monitoring import event_store as es
    with es._lock:
        es._events.clear()
        es._scan_results.clear()
        es._mass_alerts.clear()
        es._cpu_samples.clear()
        es._proc_stats.clear()
        es._proc_op_times.clear()
        es._feature_window.clear()
    return {"status": "cleared"}

@app.get("/api/db-stats")
def api_db_stats():
    try:
        conn = get_connection()
        c    = conn.cursor()
        stats = {}
        for tbl in ("file_events","scan_results","cpu_events","mass_events","behavior_sequences"):
            c.execute(f"SELECT COUNT(*) FROM {tbl}")
            stats[tbl] = c.fetchone()[0]
            c.execute(f"SELECT COUNT(*) FROM {tbl} WHERE label=0")
            stats[f"{tbl}_benign"] = c.fetchone()[0]
            c.execute(f"SELECT COUNT(*) FROM {tbl} WHERE label=1")
            stats[f"{tbl}_ransom"] = c.fetchone()[0]
        conn.close()
        return stats
    except Exception as e:
        return {"error": str(e)}