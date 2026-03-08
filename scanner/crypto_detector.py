import os
import math
import struct
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from config import ENCRYPTED_EXTS, COMPRESSED_EXTS

RANSOMWARE_HEADERS = [
    b"WANACRY!",
    b"LOCKED\x00",
    b"ENCRYPTED",
    b"RANSOM",
]

COMPRESSED_MAGIC = [
    b"PK",               # ZIP / DOCX / XLSX
    b"\x1f\x8b",         # GZIP
    b"Rar!",             # RAR
    b"\xfd7zXZ",         # XZ
    b"7z\xbc\xaf",       # 7ZIP
    b"\xff\xd8\xff",     # JPEG
    b"\x89PNG",          # PNG
    b"%PDF",             # PDF
    b"ID3",              # MP3
    b"fLaC",             # FLAC
    b"RIFF",             # WAV / AVI
]


def byte_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0.0
    n = float(len(data))
    for f in freq:
        if f > 0:
            p = f / n
            ent -= p * math.log2(p)
    return ent


def chi_square_test(data: bytes) -> float:
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    expected = len(data) / 256.0
    if expected == 0:
        return 0.0
    chi2 = sum((f - expected) ** 2 / expected for f in freq)
    return chi2


def byte_uniformity(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    expected = n / 256.0
    uniform = sum(1 for f in freq if 0.1 * expected <= f <= 2.5 * expected)
    return uniform / 256.0


def monte_carlo_pi(data: bytes) -> float:
    if len(data) < 6:
        return 3.0
    inside = 0
    total = 0
    for i in range(0, len(data) - 5, 6):
        x = struct.unpack('<H', data[i:i+2])[0] / 65535.0
        y = struct.unpack('<H', data[i+2:i+4])[0] / 65535.0
        if x * x + y * y <= 1.0:
            inside += 1
        total += 1
    if total == 0:
        return 3.0
    return abs(4.0 * inside / total - math.pi)


def detect_encrypted_pattern(path: str, max_bytes: int = 65536) -> dict:
    result = {
        "path":                  path,
        "entropy":               0.0,
        "chi_square":            0.0,
        "byte_uniformity":       0.0,
        "pi_deviation":          3.0,
        "has_ransomware_header": False,
        "has_encrypted_ext":     False,
        "is_encrypted":          False,
        "confidence":            0.0,
        "reasons":               [],
    }

    if not os.path.isfile(path):
        return result

    _, ext = os.path.splitext(path.lower())
    result["has_encrypted_ext"] = ext in ENCRYPTED_EXTS
    if result["has_encrypted_ext"]:
        result["reasons"].append(f"encrypted_extension:{ext}")

    try:
        with open(path, "rb") as f:
            header = f.read(16)
            f.seek(0)
            data = f.read(max_bytes)
    except Exception as e:
        result["reasons"].append(f"read_error:{e}")
        return result

    for rh in RANSOMWARE_HEADERS:
        if header[:len(rh)] == rh:
            result["has_ransomware_header"] = True
            result["reasons"].append("ransomware_header_match")
            break

    if len(data) < 512:
        return result

    for magic in COMPRESSED_MAGIC:
        if data[:len(magic)] == magic:
            result["reasons"].append("known_compressed_skipped")
            return result

    ent       = byte_entropy(data)
    chi2      = chi_square_test(data)
    uniformity = byte_uniformity(data)
    pi_dev    = monte_carlo_pi(data)

    result["entropy"]         = round(ent, 4)
    result["chi_square"]      = round(chi2, 2)
    result["byte_uniformity"] = round(uniformity, 4)
    result["pi_deviation"]    = round(pi_dev, 4)

    score = 0.0

    if ent > 7.5:
        score += 0.40
        result["reasons"].append(f"very_high_entropy:{ent:.2f}")
    elif ent > 7.0:
        score += 0.25
        result["reasons"].append(f"high_entropy:{ent:.2f}")

    if uniformity > 0.75:
        score += 0.25
        result["reasons"].append(f"uniform_byte_dist:{uniformity:.2f}")

    if chi2 < 300:
        score += 0.20
        result["reasons"].append(f"low_chi_square:{chi2:.0f}")

    if pi_dev < 0.05:
        score += 0.15
        result["reasons"].append("random_pi_estimate")

    if result["has_ransomware_header"]:
        score += 0.50

    if result["has_encrypted_ext"]:
        score += 0.40

    result["confidence"] = round(min(score, 1.0), 3)
    result["is_encrypted"] = result["confidence"] >= 0.55

    return result


# ── Quick test ───────────────────────────────────────────────
if __name__ == "__main__":
    import json, tempfile, random

    # Test 1: random bytes (simulated encrypted file)
    with tempfile.NamedTemporaryFile(suffix=".locked", delete=False) as f:
        f.write(bytes([random.randint(0, 255) for _ in range(8192)]))
        enc_path = f.name

    # Test 2: plain text file
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as f:
        f.write("Hello world this is normal text content " * 200)
        txt_path = f.name

    for label, path in [("ENCRYPTED_SIM", enc_path), ("PLAIN_TEXT", txt_path)]:
        res = detect_encrypted_pattern(path)
        print(f"\n{'='*50}")
        print(f"FILE TYPE  : {label}")
        print(f"Entropy    : {res['entropy']}")
        print(f"Chi-Square : {res['chi_square']}")
        print(f"Uniformity : {res['byte_uniformity']}")
        print(f"Pi dev     : {res['pi_deviation']}")
        print(f"Encrypted? : {res['is_encrypted']}  (conf={res['confidence']})")
        print(f"Reasons    : {res['reasons']}")