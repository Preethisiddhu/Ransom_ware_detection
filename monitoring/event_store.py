from __future__ import annotations

import os
import json
import threading
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from config import (
    MASS_WINDOW_SECONDS, MASS_THRESHOLD,
    HIGH_RISK_THRESHOLD, SUSPICIOUS_THRESHOLD,
    STATUS_WINDOW_SECS, SEQUENCE_LENGTH, INPUT_FEATURES
)

_lock = threading.Lock()

_events:       deque = deque(maxlen=5000)
_scan_results: deque = deque(maxlen=2000)
_mass_alerts:  deque = deque(maxlen=500)
_cpu_samples:  deque = deque(maxlen=3600)   # 1hr of 1s samples

# Rolling feature window for LSTM
_feature_window: deque = deque(maxlen=SEQUENCE_LENGTH)

_proc_op_times: Dict[str, Dict[str, deque]] = defaultdict(
    lambda: defaultdict(lambda: deque(maxlen=1000))
)
_proc_stats: Dict[str, Dict] = defaultdict(
    lambda: {"files_touched": 0, "risk_score": 0.0, "pid": -1}
)

# Op count windows for mass detection
_op_counts: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))

# Current session info
_current_session = {"session_id": "default", "label": -1}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(ts) -> Optional[datetime]:
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", ""))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _prune(dq: deque, window: float):
    cutoff = _now() - timedelta(seconds=window)
    while dq and dq[0] < cutoff:
        dq.popleft()


# ── CPU ──────────────────────────────────────────────────────

def add_cpu_sample(sample: dict):
    with _lock:
        _cpu_samples.append(sample)


def get_latest_cpu() -> dict:
    with _lock:
        if _cpu_samples:
            return dict(_cpu_samples[-1])
    return {"cpu_percent": 0.0, "is_spike": False, "spike_delta": 0.0, "baseline": 0.0}


def get_cpu_samples(limit: int = 60) -> List[dict]:
    with _lock:
        return list(_cpu_samples)[-limit:]


# ── Events ───────────────────────────────────────────────────

def add_event(event: dict) -> Optional[dict]:
    with _lock:
        _events.append(event)

        proc = event.get("process_name", "unknown")
        op   = event.get("operation", "")
        pid  = event.get("pid", -1)
        risk = float(event.get("risk_score", 0.0))

        stats = _proc_stats[proc]
        stats["files_touched"] += 1
        stats["risk_score"]     = round(max(stats["risk_score"], risk), 2)
        stats["pid"]            = pid

        _proc_op_times[proc][op].append(_now())
        _op_counts[op].append(_now())

        alert = _check_mass(proc, op)
        if alert:
            _mass_alerts.append(alert)
        return alert


def _check_mass(process_name: str, op: str) -> Optional[dict]:
    times = _proc_op_times[process_name][op]
    _prune(times, MASS_WINDOW_SECONDS)
    count = len(times)
    if count >= MASS_THRESHOLD:
        return {
            "timestamp":    _now().isoformat(),
            "process_name": process_name,
            "operation":    op,
            "count":        count,
            "window_secs":  MASS_WINDOW_SECONDS,
            "severity":     "critical" if count >= MASS_THRESHOLD * 3 else "warning",
        }
    return None


def _get_mass_counts() -> Dict[str, int]:
    cutoff = _now() - timedelta(seconds=MASS_WINDOW_SECONDS)
    counts = {}
    for op, dq in _op_counts.items():
        counts[op] = sum(1 for t in dq if t >= cutoff)
    return counts


# ── Scan Results ────────────────────────────────────────────

def add_scan_result(result: dict):
    with _lock:
        _scan_results.append(result)


def remove_scan_results_for_path(path: str):
    norm = os.path.normpath(path)
    with _lock:
        keep: deque = deque(maxlen=2000)
        for s in _scan_results:
            if os.path.normpath(str(s.get("path", ""))) != norm:
                keep.append(s)
        _scan_results.clear()
        _scan_results.extend(keep)
    print(f"[store] removed scan results: {os.path.basename(path)}")


def get_recent_events(limit: int = 100) -> List[dict]:
    with _lock:
        items = list(_events)
    items.sort(key=lambda e: str(e.get("timestamp", "")), reverse=True)
    return items[:limit]


def get_recent_scan_results(limit: int = 100) -> List[dict]:
    with _lock:
        items = list(_scan_results)
    items.sort(key=lambda e: str(e.get("scanned_at", "")), reverse=True)
    return items[:limit]


def get_mass_alerts(limit: int = 50) -> List[dict]:
    with _lock:
        items = list(_mass_alerts)
    items.sort(key=lambda e: str(e.get("timestamp", "")), reverse=True)
    return items[:limit]


def get_suspicious_processes() -> List[dict]:
    with _lock:
        rows = []
        for name, stats in _proc_stats.items():
            if name == "unknown":
                continue
            if stats["risk_score"] >= SUSPICIOUS_THRESHOLD or stats["files_touched"] >= 3:
                rows.append({
                    "process_name":  name,
                    "pid":           stats["pid"],
                    "files_touched": stats["files_touched"],
                    "risk_score":    stats["risk_score"],
                })
    rows.sort(key=lambda r: r["risk_score"], reverse=True)
    return rows


# ── Feature Window (for LSTM) ───────────────────────────────

def push_feature_vector(vec):
    """Push a numpy/list feature vector into LSTM sliding window."""
    with _lock:
        _feature_window.append(vec)


def get_feature_window():
    with _lock:
        return list(_feature_window)


def get_context_for_features() -> dict:
    """Returns rolling stats needed by feature_extractor."""
    cpu = get_latest_cpu()
    mass = _get_mass_counts()
    with _lock:
        now    = _now()
        cutoff = now - timedelta(seconds=1)
        recent = [e for e in _events if _parse_dt(e.get("timestamp","")) and _parse_dt(e.get("timestamp","")) >= cutoff]
        exts   = set()
        for e in list(_events)[-50:]:
            p = e.get("path","")
            _, x = os.path.splitext(p.lower())
            if x:
                exts.add(x)
    return {
        "cpu_percent":      cpu.get("cpu_percent", 0.0),
        "cpu_is_spike":     cpu.get("is_spike", False),
        "cpu_spike_delta":  cpu.get("spike_delta", 0.0),
        "mass_create_count": mass.get("create", 0),
        "mass_delete_count": mass.get("delete", 0),
        "mass_modify_count": mass.get("modify", 0),
        "mass_rename_count": mass.get("rename", 0),
        "events_per_sec":    len(recent),
        "unique_extensions": len(exts),
    }


# ── Session ─────────────────────────────────────────────────

def set_session(session_id: str, label: int = -1):
    with _lock:
        _current_session["session_id"] = session_id
        _current_session["label"]      = label


def get_session() -> dict:
    with _lock:
        return dict(_current_session)


# ── Status ──────────────────────────────────────────────────

def get_current_status(lstm_result: Optional[dict] = None) -> dict:
    with _lock:
        events_list = list(_events)
        alerts_list = list(_mass_alerts)
        scan_list   = list(_scan_results)
        named_procs = {
            n: s for n, s in _proc_stats.items() if n != "unknown"
        }

    now         = _now()
    cutoff_24h  = now - timedelta(hours=24)
    cutoff_5s   = now - timedelta(seconds=STATUS_WINDOW_SECS)

    recent_24h, recent_5s = [], []
    for e in events_list:
        dt = _parse_dt(e.get("timestamp", ""))
        if dt:
            if dt >= cutoff_24h:
                recent_24h.append(e)
            if dt >= cutoff_5s:
                recent_5s.append(e)

    max_risk = max((float(e.get("risk_score", 0)) for e in recent_5s), default=0.0)

    last_high = next(
        (e["timestamp"] for e in reversed(events_list)
         if float(e.get("risk_score", 0)) >= HIGH_RISK_THRESHOLD),
        None,
    )

    recent_procs = {e.get("process_name", "") for e in recent_5s}
    susp_count   = sum(
        1 for n, s in named_procs.items()
        if s["risk_score"] >= SUSPICIOUS_THRESHOLD and n in recent_procs
    )

    active_alerts = [
        a for a in alerts_list
        if (now - (_parse_dt(a.get("timestamp","")) or now)).total_seconds() < 60
    ]

    active_malicious = [
        s for s in scan_list
        if bool(s.get("malicious", False)) and os.path.isfile(str(s.get("path", "")))
    ]

    cpu = get_latest_cpu()
    cpu_spike_active = cpu.get("is_spike", False)

    # LSTM signal
    lstm_ransomware = False
    lstm_prob       = 0.0
    if lstm_result and lstm_result.get("ready"):
        lstm_prob       = lstm_result.get("ransomware_prob", 0.0)
        lstm_ransomware = lstm_prob >= 0.65

    # Combined rule + LSTM score
    rule_score     = max_risk
    combined_score = round(0.4 * rule_score + 0.6 * lstm_prob, 3) if lstm_result and lstm_result.get("ready") else rule_score

    if active_malicious or active_alerts or lstm_ransomware or combined_score >= HIGH_RISK_THRESHOLD:
        status = "ransomware_detected"
    elif cpu_spike_active or susp_count > 0 or combined_score >= SUSPICIOUS_THRESHOLD:
        status = "suspicious"
    else:
        status = "safe"

    return {
        "status":                     status,
        "last_detection_time":        last_high,
        "total_events_24h":           len(recent_24h),
        "suspicious_processes_count": susp_count,
        "active_mass_alerts":         len(active_alerts),
        "active_malicious_files":     len(active_malicious),
        "cpu_spike_active":           cpu_spike_active,
        "cpu_percent":                cpu.get("cpu_percent", 0.0),
        "lstm_ransomware_prob":       round(lstm_prob, 4),
        "lstm_ready":                 bool(lstm_result and lstm_result.get("ready")),
        "combined_score":             combined_score,
    }