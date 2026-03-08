import os
import math
import sys
from typing import Dict, List

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from config import (
    SUSPICIOUS_EXTS, COMPRESSED_EXTS, ENCRYPTED_EXTS,
    SUSPICIOUS_STRINGS
)
from scanner.crypto_detector import detect_encrypted_pattern


def _file_entropy(path: str, max_bytes: int = 1024 * 1024) -> float:
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)
    except Exception:
        return 0.0
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    n = float(len(data))
    for c in counts:
        if c > 0:
            p = c / n
            entropy -= p * math.log2(p)
    return entropy


def _scan_strings(path: str, max_bytes: int = 1024 * 1024) -> List[str]:
    hits: List[str] = []
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)
        text = data.decode("utf-8", errors="ignore").lower()
    except Exception:
        return hits
    for s in SUSPICIOUS_STRINGS:
        if s.lower() in text:
            hits.append(s)
    return hits


def _get_file_size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except Exception:
        return 0


def scan_file(path: str) -> Dict:
    result: Dict = {
        "path":              path,
        "exists":            os.path.isfile(path),
        "score":             0.0,
        "reasons":           [],
        "entropy":           0.0,
        "file_size":         0,
        "is_encrypted":      False,
        "encryption_conf":   0.0,
        "has_encrypted_ext": False,
        "has_suspicious_str": False,
        "malicious":         False,
    }

    if not result["exists"]:
        result["reasons"].append("file_not_found")
        return result

    _, ext = os.path.splitext(path.lower())
    result["file_size"] = _get_file_size(path)

    # 1. Extension check
    if ext in ENCRYPTED_EXTS:
        result["score"] = max(result["score"], 0.9)
        result["reasons"].append(f"encrypted_extension:{ext}")
        result["has_encrypted_ext"] = True

    if ext in SUSPICIOUS_EXTS:
        result["score"] = max(result["score"], 0.4)
        result["reasons"].append(f"suspicious_extension:{ext}")

    # 2. Entropy check
    ent = _file_entropy(path)
    result["entropy"] = ent
    if ext not in COMPRESSED_EXTS:
        if ent > 7.5:
            result["score"] = max(result["score"], 0.75)
            result["reasons"].append(f"very_high_entropy:{ent:.2f}")
        elif ent > 7.0:
            result["score"] = max(result["score"], 0.55)
            result["reasons"].append(f"high_entropy:{ent:.2f}")

    # 3. Suspicious string check
    hits = _scan_strings(path)
    if hits:
        result["score"] = max(result["score"], 0.85)
        result["reasons"].append(f"suspicious_strings:{len(hits)}")
        result["has_suspicious_str"] = True

    # 4. Deep crypto pattern detection
    crypto = detect_encrypted_pattern(path)
    result["encryption_conf"] = crypto["confidence"]
    result["is_encrypted"]    = crypto["is_encrypted"]
    if crypto["is_encrypted"] and ext not in COMPRESSED_EXTS:
        result["score"] = max(result["score"], 0.80)
        result["reasons"].append(f"encrypted_pattern:conf={crypto['confidence']:.2f}")

    result["score"]    = round(min(result["score"], 1.0), 2)
    result["malicious"] = result["score"] >= 0.7

    return result


# ── Quick test ────────────────────────────────────────────────
if __name__ == "__main__":
    import tempfile, random

    tests = [
        ("normal_text.txt",       b"Hello world this is normal content " * 200),
        ("malicious_script.txt",  b"vssadmin delete shadows\nbitcoin wallet.dat\ncmd.exe /c del *"),
        ("encrypted_sim.locked",  bytes([random.randint(0,255) for _ in range(8192)])),
        ("normal_pdf_like.pdf",   b"%PDF-1.4 normal document content " * 100),
    ]

    for name, content in tests:
        with tempfile.NamedTemporaryFile(suffix=os.path.splitext(name)[1], delete=False) as f:
            f.write(content)
            path = f.name

        res = scan_file(path)
        print(f"\nFile     : {name}")
        print(f"Score    : {res['score']}")
        print(f"Entropy  : {res['entropy']:.2f}")
        print(f"Malicious: {res['malicious']}")
        print(f"Encrypted: {res['is_encrypted']} (conf={res['encryption_conf']})")
        print(f"Reasons  : {res['reasons']}")