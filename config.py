import os

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DATA_DIR   = os.path.join(BASE_DIR, "data")
MODELS_DIR = os.path.join(DATA_DIR, "models")
DB_PATH    = os.path.join(DATA_DIR, "ransomguard.db")
SANDBOX    = os.path.join(DATA_DIR, "sandbox")

os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(SANDBOX,    exist_ok=True)

# Watch Paths
WATCH_PATHS = [
    r"C:\Users\Admin\Desktop",
    r"C:\Users\Admin\Documents",
    r"C:\Users\Admin\Downloads",
    r"C:\Users\Admin\Pictures",
]
PROJECT_DIR      = r"C:\Users\Admin\Desktop\RansomGuard_Advanced"
DEBOUNCE_SECONDS = 3.0

SKIP_SCAN_EXTS = {
    ".tmp", ".crdownload", ".part", ".partial",
    ".download", ".opdownload", ".!ut"
}

FINAL_EXTS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".zip", ".rar", ".exe", ".txt", ".csv",
}

ENCRYPTED_EXTS = {
    ".locked", ".enc", ".encrypted", ".crypt", ".cry",
    ".xxx", ".zepto", ".locky", ".cerber", ".thor",
    ".aaa", ".abc", ".xyz", ".zzz", ".micro",
    ".crypto", ".darkness", ".777", ".xtbl",
    ".wallet", ".wcry", ".wncry",
}

SUSPICIOUS_EXTS = {
    ".exe", ".dll", ".js", ".vbs", ".ps1", ".bat",
    ".cmd", ".scr", ".jar", ".hta", ".docm", ".xlsm",
}

COMPRESSED_EXTS = {
    ".pdf", ".zip", ".rar", ".7z", ".gz", ".png",
    ".jpg", ".jpeg", ".mp3", ".mp4", ".docx", ".xlsx", ".pptx",
}

SUSPICIOUS_STRINGS = [
    "vssadmin delete shadows",
    "wbadmin delete catalog",
    "bcdedit /set",
    "cipher /w:",
    "powershell -enc",
    "cmd.exe /c",
    "schtasks /create",
    "tor.exe",
    "bitcoin",
    "wallet.dat",
]

# Mass Activity
MASS_WINDOW_SECONDS = 10
MASS_THRESHOLD      = 5

# Risk Thresholds
HIGH_RISK_THRESHOLD  = 0.7
SUSPICIOUS_THRESHOLD = 0.5
STATUS_WINDOW_SECS   = 5

# CPU Monitor
CPU_SAMPLE_INTERVAL  = 1.0
CPU_BASELINE_WINDOW  = 60
CPU_SPIKE_THRESHOLD  = 30.0
CPU_SPIKE_MIN_VALUE  = 70.0

# LSTM
SEQUENCE_LENGTH = 30
INPUT_FEATURES  = 20
HIDDEN_SIZE     = 128
NUM_LAYERS      = 2
LSTM_THRESHOLD  = 0.65

MODEL_PATH  = os.path.join(MODELS_DIR, "lstm_ransomware.pth")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.pkl")

# API
API_BASE = "http://127.0.0.1:8000/api"