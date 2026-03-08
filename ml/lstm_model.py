import torch
import torch.nn as nn
import os, sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from config import INPUT_FEATURES, HIDDEN_SIZE, NUM_LAYERS, SEQUENCE_LENGTH


class RansomwareLSTM(nn.Module):
    """
    Bidirectional LSTM with attention for ransomware detection.

    Input  : (batch, sequence_length=30, features=20)
    Output : (batch, 2)  →  [P(benign), P(ransomware)]
    """

    def __init__(
        self,
        input_size:  int = INPUT_FEATURES,
        hidden_size: int = HIDDEN_SIZE,
        num_layers:  int = NUM_LAYERS,
        dropout:     float = 0.3,
    ):
        super().__init__()

        self.lstm = nn.LSTM(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0,
            bidirectional=True,
        )

        # Attention over time steps
        self.attention = nn.Linear(hidden_size * 2, 1)

        self.classifier = nn.Sequential(
            nn.Linear(hidden_size * 2, 64),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, 2),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (batch, seq_len, features)
        lstm_out, _ = self.lstm(x)
        # lstm_out: (batch, seq_len, hidden*2)

        attn_weights = torch.softmax(self.attention(lstm_out), dim=1)
        context      = (attn_weights * lstm_out).sum(dim=1)
        # context: (batch, hidden*2)

        return self.classifier(context)


def get_model() -> RansomwareLSTM:
    return RansomwareLSTM()


# ── Quick test ────────────────────────────────────────────────
if __name__ == "__main__":
    model = get_model()
    total_params = sum(p.numel() for p in model.parameters())
    print(f"\nModel Architecture:")
    print(model)
    print(f"\nTotal parameters : {total_params:,}")
    print(f"Input shape      : (batch, {SEQUENCE_LENGTH}, {INPUT_FEATURES})")

    dummy = torch.randn(4, SEQUENCE_LENGTH, INPUT_FEATURES)
    out   = model(dummy)
    probs = torch.softmax(out, dim=1)
    print(f"\nDummy forward pass:")
    print(f"  Output shape   : {out.shape}")
    print(f"  Sample probs   : benign={probs[0][0]:.3f}  ransomware={probs[0][1]:.3f}")