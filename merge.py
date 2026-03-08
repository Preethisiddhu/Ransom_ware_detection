import os, sys, json, math
import numpy as np
from datetime import datetime, timezone

sys.path.insert(0, r'C:\Users\Admin\Desktop\RansomGuard_Advanced')
os.chdir(r'C:\Users\Admin\Desktop\RansomGuard_Advanced')

from database.db import get_connection
from config import SEQUENCE_LENGTH, INPUT_FEATURES, MODELS_DIR

conn = get_connection()
c = conn.cursor()

# Clear old generated sequences
c.execute("DELETE FROM behavior_sequences WHERE source='generated_from_events'")
conn.commit()
print("Cleared old sequences.")

seqs_saved = 0

for label in [0, 1]:
    c.execute("""
        SELECT timestamp, operation, path, extension,
               file_size, risk_score, session_id
        FROM file_events
        WHERE label=?
        ORDER BY timestamp
    """, (label,))
    events = c.fetchall()
    print(f"\nlabel={label}  events={len(events)}")

    if len(events) < SEQUENCE_LENGTH:
        print(f"  Not enough events, skipping.")
        continue

    count = 0
    for i in range(0, len(events) - SEQUENCE_LENGTH, 3):
        window = events[i:i + SEQUENCE_LENGTH]
        vec = []
        for e in window:
            op   = str(e[1]) if e[1] else 'modify'
            risk = float(e[5]) if e[5] else 0.0
            ext  = str(e[3]) if e[3] else ''
            size = int(e[4]) if e[4] else 0
            fv = [
                1.0 if op == 'create' else 0.0,
                1.0 if op == 'modify' else 0.0,
                1.0 if op == 'delete' else 0.0,
                1.0 if op == 'rename' else 0.0,
                min(risk, 1.0),
                0.5,
                1.0 if ext in ('.locked','.enc','.encrypted','.wcry','.wncry','.crypt') else 0.0,
                0.0, 0.0,
                min(math.log10(size + 1) / 7.0, 1.0),
                0.2, 0.0, 0.0,
                0.0, 0.0, 0.0, 0.0,
                0.1, 0.1, 0.5
            ]
            vec.append(fv)

        c.execute("""
            INSERT INTO behavior_sequences
            (timestamp, session_id, features, label, window_size, source)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            datetime.now(timezone.utc).isoformat(),
            f'generated_{label}',
            json.dumps(vec),
            label,
            SEQUENCE_LENGTH,
            'generated_from_events'
        ))
        count += 1

    conn.commit()
    print(f"  Saved {count} sequences")
    seqs_saved += count

c.execute("SELECT features, label FROM behavior_sequences WHERE label IN (0,1)")
rows = c.fetchall()
conn.close()

seqs, labels = [], []
for row in rows:
    try:
        feat = json.loads(row[0])
        if len(feat) == SEQUENCE_LENGTH and len(feat[0]) == INPUT_FEATURES:
            seqs.append(feat)
            labels.append(int(row[1]))
    except:
        pass

X = np.array(seqs,   dtype='float32')
y = np.array(labels, dtype='int64')

os.makedirs(MODELS_DIR, exist_ok=True)
np.save(os.path.join(MODELS_DIR, 'X_train.npy'), X)
np.save(os.path.join(MODELS_DIR, 'y_train.npy'), y)

print(f"\n{'='*40}")
print(f"Shape      : {X.shape}")
print(f"Benign     : {sum(y==0)}")
print(f"Ransomware : {sum(y==1)}")
print(f"Total      : {len(y)}")
print(f"{'='*40}")
print(f"Ready to train!")