import numpy as np
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from config import SEQUENCE_LENGTH, INPUT_FEATURES


def build_feature_vector(event: dict, context: dict) -> np.ndarray:
    """
    Builds a 20-dimensional feature vector from one event + context.

    FEATURES:
    ─────────────────────────────────────────────────────────
    [0]  op_create           1 if create
    [1]  op_modify           1 if modify
    [2]  op_delete           1 if delete
    [3]  op_rename           1 if rename
    [4]  risk_score          0.0–1.0
    [5]  entropy             file entropy / 8.0
    [6]  has_encrypted_ext   1 if .locked/.wncry etc
    [7]  has_suspicious_str  1 if ransomware strings found
    [8]  is_encrypted_pattern 1 if crypto_detector positive
    [9]  file_size_log       log10(size+1) / 7.0
    ─────────────────────────────────────────────────────────
    [10] cpu_percent         / 100.0
    [11] cpu_is_spike        1 if CPU spike
    [12] cpu_spike_delta     / 100.0
    ─────────────────────────────────────────────────────────
    [13] mass_create_count   / 100.0
    [14] mass_delete_count   / 100.0
    [15] mass_modify_count   / 100.0
    [16] mass_rename_count   / 100.0
    ─────────────────────────────────────────────────────────
    [17] events_per_sec      / 10.0
    [18] unique_extensions   / 20.0
    [19] time_of_day         hour / 24.0
    ─────────────────────────────────────────────────────────
    """
    f = np.zeros(INPUT_FEATURES, dtype=np.float32)

    op = event.get("operation", "")
    f[0] = 1.0 if op == "create" else 0.0
    f[1] = 1.0 if op == "modify" else 0.0
    f[2] = 1.0 if op == "delete" else 0.0
    f[3] = 1.0 if op == "rename" else 0.0

    f[4] = float(min(event.get("risk_score", 0.0), 1.0))
    f[5] = float(min(event.get("entropy", 0.0) / 8.0, 1.0))
    f[6] = 1.0 if event.get("has_encrypted_ext", False) else 0.0
    f[7] = 1.0 if event.get("has_suspicious_str", False) else 0.0
    f[8] = 1.0 if event.get("is_encrypted", False) else 0.0

    size = int(event.get("file_size", 0) or 0)
    f[9] = float(min(np.log10(size + 1) / 7.0, 1.0))

    f[10] = float(min(context.get("cpu_percent", 0.0) / 100.0, 1.0))
    f[11] = 1.0 if context.get("cpu_is_spike", False) else 0.0
    f[12] = float(min(context.get("cpu_spike_delta", 0.0) / 100.0, 1.0))

    f[13] = float(min(context.get("mass_create_count", 0) / 100.0, 1.0))
    f[14] = float(min(context.get("mass_delete_count", 0) / 100.0, 1.0))
    f[15] = float(min(context.get("mass_modify_count", 0) / 100.0, 1.0))
    f[16] = float(min(context.get("mass_rename_count", 0) / 100.0, 1.0))

    f[17] = float(min(context.get("events_per_sec", 0) / 10.0, 1.0))
    f[18] = float(min(context.get("unique_extensions", 0) / 20.0, 1.0))

    try:
        ts = event.get("timestamp", "")
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        f[19] = dt.hour / 24.0
    except Exception:
        f[19] = 0.5

    return f


# ── Quick test ────────────────────────────────────────────────
if __name__ == "__main__":
    from datetime import timezone

    benign_event = {
        "operation": "create", "risk_score": 0.1, "entropy": 3.2,
        "has_encrypted_ext": False, "has_suspicious_str": False,
        "is_encrypted": False, "file_size": 51200,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    benign_ctx = {
        "cpu_percent": 18.0, "cpu_is_spike": False, "cpu_spike_delta": 2.0,
        "mass_create_count": 1, "mass_delete_count": 0,
        "mass_modify_count": 0, "mass_rename_count": 0,
        "events_per_sec": 1, "unique_extensions": 3,
    }

    ransom_event = {
        "operation": "rename", "risk_score": 0.9, "entropy": 7.8,
        "has_encrypted_ext": True, "has_suspicious_str": True,
        "is_encrypted": True, "file_size": 204800,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    ransom_ctx = {
        "cpu_percent": 85.0, "cpu_is_spike": True, "cpu_spike_delta": 65.0,
        "mass_create_count": 0, "mass_delete_count": 5,
        "mass_modify_count": 2, "mass_rename_count": 45,
        "events_per_sec": 8, "unique_extensions": 2,
    }

    fv_benign = build_feature_vector(benign_event, benign_ctx)
    fv_ransom = build_feature_vector(ransom_event, ransom_ctx)

    labels = [
        "op_create","op_modify","op_delete","op_rename",
        "risk_score","entropy_norm","enc_ext","susp_str","enc_pattern","size_log",
        "cpu_pct","cpu_spike","cpu_delta",
        "mass_create","mass_delete","mass_modify","mass_rename",
        "evt_per_sec","unique_ext","time_of_day"
    ]

    print(f"\n{'Feature':<18}  {'Benign':>8}  {'Ransomware':>10}")
    print("-" * 42)
    for i, lbl in enumerate(labels):
        print(f"  {lbl:<16}  {fv_benign[i]:>8.3f}  {fv_ransom[i]:>10.3f}")