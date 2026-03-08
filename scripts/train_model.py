
import os, sys, json, pickle, argparse
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import (MODEL_PATH, SCALER_PATH, SEQUENCE_LENGTH,
                    INPUT_FEATURES, HIDDEN_SIZE, NUM_LAYERS, MODELS_DIR)
from database.db import get_connection

try:
    import torch, torch.nn as nn
    from torch.utils.data import DataLoader, TensorDataset
except ImportError:
    print("ERROR: pip install torch"); sys.exit(1)

from sklearn.model_selection import train_test_split
from sklearn.preprocessing   import StandardScaler
from sklearn.metrics         import classification_report, confusion_matrix
from ml.lstm_model           import RansomwareLSTM


def load_from_db():
    conn = get_connection()
    c    = conn.cursor()
    c.execute("SELECT features, label FROM behavior_sequences WHERE label IN (0,1) ORDER BY timestamp")
    rows = c.fetchall()
    conn.close()
    seqs, labels = [], []
    for row in rows:
        feat = json.loads(row['features'])
        if len(feat) == SEQUENCE_LENGTH and len(feat[0]) == INPUT_FEATURES:
            seqs.append(feat)
            labels.append(int(row['label']))
    if not seqs:
        return None, None
    return np.array(seqs, dtype=np.float32), np.array(labels, dtype=np.int64)


def load_from_npy():
    X_path = os.path.join(MODELS_DIR, "X_train.npy")
    y_path = os.path.join(MODELS_DIR, "y_train.npy")
    if not os.path.isfile(X_path):
        print(f"Not found: {X_path}\nRun: python -m scripts.merge_and_export first")
        return None, None
    return np.load(X_path), np.load(y_path)


def train(epochs=50, batch_size=64, lr=0.001, use_npy=False):
    print(f"\n{'='*55}\n  LSTM TRAINING\n{'='*55}")

    print("\n[1/5] Loading data...")
    X, y = load_from_npy() if use_npy else load_from_db()
    if X is None:
        print("No data found. Collect data first."); return

    N, seq_len, feat_len = X.shape
    n_b, n_r = (y==0).sum(), (y==1).sum()
    print(f"  Total: {N}  benign={n_b}  ransomware={n_r}  shape={X.shape}")

    if n_b < 50 or n_r < 50:
        print(f"  ⚠  Too little data. Min 50 each class needed."); return

    print("\n[2/5] Scaling features...")
    X_flat = X.reshape(N, -1)
    scaler = StandardScaler()
    X_sc   = scaler.fit_transform(X_flat).reshape(N, seq_len, feat_len)
    os.makedirs(MODELS_DIR, exist_ok=True)
    with open(SCALER_PATH, 'wb') as f:
        pickle.dump(scaler, f)
    print(f"  Scaler saved → {SCALER_PATH}")

    print("\n[3/5] Train/test split 80/20...")
    X_tr, X_te, y_tr, y_te = train_test_split(X_sc, y, test_size=0.2, random_state=42, stratify=y)
    print(f"  Train={len(X_tr)}  Test={len(X_te)}")

    tr_dl = DataLoader(TensorDataset(torch.FloatTensor(X_tr), torch.LongTensor(y_tr)),
                       batch_size=batch_size, shuffle=True)
    te_dl = DataLoader(TensorDataset(torch.FloatTensor(X_te), torch.LongTensor(y_te)),
                       batch_size=batch_size)

    print("\n[4/5] Training...")
    device    = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model     = RansomwareLSTM(feat_len, HIDDEN_SIZE, NUM_LAYERS).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    criterion = nn.CrossEntropyLoss()
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=5)
    

    best_acc = 0.0
    for epoch in range(1, epochs+1):
        model.train()
        total_loss = 0.0
        for Xb, yb in tr_dl:
            optimizer.zero_grad()
            loss = criterion(model(Xb.to(device)), yb.to(device))
            loss.backward(); optimizer.step()
            total_loss += loss.item()

        model.eval()
        correct = total = 0
        with torch.no_grad():
            for Xb, yb in te_dl:
                preds = model(Xb.to(device)).argmax(1).cpu()
                correct += (preds == yb).sum().item(); total += len(yb)

        acc = correct / total
        scheduler.step(1 - acc)
        if epoch % 10 == 0 or epoch == 1:
            bar = '█' * int(acc * 20) + '░' * (20 - int(acc * 20))
            print(f"  Epoch {epoch:3d}/{epochs}  loss={total_loss/len(tr_dl):.4f}  "
                  f"acc={acc:.4f}  [{bar}]")
        if acc > best_acc:
            best_acc = acc
            torch.save(model.state_dict(), MODEL_PATH)

    print(f"\n  Best accuracy: {best_acc:.4f}")
    print(f"  Model saved → {MODEL_PATH}")

    print("\n[5/5] Final evaluation...")
    model.load_state_dict(torch.load(MODEL_PATH, map_location=device))
    model.eval()
    all_pred, all_true = [], []
    with torch.no_grad():
        for Xb, yb in te_dl:
            all_pred.extend(model(Xb.to(device)).argmax(1).cpu().tolist())
            all_true.extend(yb.tolist())

    print(classification_report(all_true, all_pred, target_names=["Benign","Ransomware"]))
    cm = confusion_matrix(all_true, all_pred)
    tn, fp, fn, tp = cm.ravel()
    print(f"  TP={tp}  FP={fp}  TN={tn}  FN={fn}")
    print(f"  False alarm rate : {fp/(fp+tn)*100:.1f}%")
    print(f"  Detection rate   : {tp/(tp+fn)*100:.1f}%")
    print(f"\n{'='*55}\n  TRAINING COMPLETE\n{'='*55}")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--epochs",   type=int,   default=50)
    p.add_argument("--batch",    type=int,   default=64)
    p.add_argument("--lr",       type=float, default=0.001)
    p.add_argument("--use-npy",  action='store_true')
    args = p.parse_args()
    train(args.epochs, args.batch, args.lr, args.use_npy)