import os
import sys
import pickle
import numpy as np
from collections import deque

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from config import (
    MODEL_PATH, SCALER_PATH, SEQUENCE_LENGTH,
    INPUT_FEATURES, LSTM_THRESHOLD
)

try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

from ml.lstm_model import RansomwareLSTM


class RansomwarePredictor:
    def __init__(self):
        self._model      = None
        self._scaler     = None
        self._window     = deque(maxlen=SEQUENCE_LENGTH)
        self._last_pred  = {
            "label": 0, "confidence": 0.0,
            "ransomware_prob": 0.0, "ready": False
        }
        self._loaded     = False
        self._try_load()

    def _try_load(self):
        if not TORCH_AVAILABLE:
            print("[predictor] PyTorch not installed. Rule-based only.")
            return
        if not os.path.isfile(MODEL_PATH):
            print(f"[predictor] Model not found at {MODEL_PATH}")
            print("[predictor] Train the model first: python -m scripts.train_model")
            return
        if not os.path.isfile(SCALER_PATH):
            print(f"[predictor] Scaler not found at {SCALER_PATH}")
            return
        try:
            import torch
            self._model = RansomwareLSTM(INPUT_FEATURES, 128, 2)
            self._model.load_state_dict(
                torch.load(MODEL_PATH, map_location="cpu")
            )
            self._model.eval()
            with open(SCALER_PATH, "rb") as f:
                self._scaler = pickle.load(f)
            self._loaded = True
            print("[predictor] ✅ LSTM model loaded successfully.")
            print(f"[predictor]   Model : {MODEL_PATH}")
            print(f"[predictor]   Scaler: {SCALER_PATH}")
        except Exception as e:
            print(f"[predictor] Load failed: {e}")

    def push(self, feature_vector: np.ndarray):
        """Add one feature vector to the sliding window."""
        self._window.append(feature_vector.astype(np.float32))

    def predict(self) -> dict:
        """
        Run LSTM on current window.
        Returns dict with ransomware_prob, label, confidence, ready.
        """
        if not self._loaded:
            return {"label": 0, "confidence": 0.0, "ransomware_prob": 0.0, "ready": False}

        if len(self._window) < SEQUENCE_LENGTH:
            return {
                "label": 0, "confidence": 0.0,
                "ransomware_prob": 0.0, "ready": False,
                "window_fill": f"{len(self._window)}/{SEQUENCE_LENGTH}"
            }

        import torch

        seq      = np.array(list(self._window), dtype=np.float32)          # (30, 20)
        seq_flat = seq.reshape(1, -1)                                        # (1, 600)
        scaled   = self._scaler.transform(seq_flat).reshape(1, SEQUENCE_LENGTH, INPUT_FEATURES)
        tensor   = torch.FloatTensor(scaled)

        with torch.no_grad():
            logits = self._model(tensor)
            probs  = torch.softmax(logits, dim=1)[0]
            r_prob = float(probs[1])
            label  = 1 if r_prob >= LSTM_THRESHOLD else 0
            conf   = float(probs[label])

        self._last_pred = {
            "label":           label,
            "confidence":      round(conf,   4),
            "ransomware_prob": round(r_prob, 4),
            "ready":           True,
        }
        return self._last_pred

    @property
    def last(self) -> dict:
        return self._last_pred

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    @property
    def window_fill(self) -> int:
        return len(self._window)


# Singleton instance used by backend
_predictor: RansomwarePredictor | None = None


def get_predictor() -> RansomwarePredictor:
    global _predictor
    if _predictor is None:
        _predictor = RansomwarePredictor()
    return _predictor


# ── Quick test ────────────────────────────────────────────────
if __name__ == "__main__":
    import numpy as np

    pred = RansomwarePredictor()
    print(f"\nModel loaded: {pred.is_loaded}")

    if not pred.is_loaded:
        print("Simulating predictions with random features (model not trained yet)...")
        print("Push 30 random feature vectors:")
        for i in range(30):
            fv = np.random.rand(INPUT_FEATURES).astype(np.float32)
            pred.push(fv)
        result = pred.predict()
        print(f"\nPrediction result: {result}")
    else:
        print("Model found — running real prediction test...")
        for i in range(SEQUENCE_LENGTH):
            fv = np.random.rand(INPUT_FEATURES).astype(np.float32)
            pred.push(fv)
        result = pred.predict()
        print(f"Prediction: {result}")