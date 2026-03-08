import time
import threading
import psutil
import sys
import os
from collections import deque
from datetime import datetime, timezone
from typing import Callable, Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from config import (
    CPU_SAMPLE_INTERVAL, CPU_BASELINE_WINDOW,
    CPU_SPIKE_THRESHOLD, CPU_SPIKE_MIN_VALUE
)


class CPUMonitor:
    def __init__(
        self,
        on_spike:  Optional[Callable] = None,
        on_sample: Optional[Callable] = None,
    ):
        self.on_spike  = on_spike
        self.on_sample = on_sample
        self._baseline_samples = deque(maxlen=CPU_BASELINE_WINDOW)
        self._running = False
        self._thread  = None
        self._last    = {"cpu_percent": 0.0, "is_spike": False, "baseline": 0.0}

    @property
    def baseline(self) -> float:
        if not self._baseline_samples:
            return 20.0
        return sum(self._baseline_samples) / len(self._baseline_samples)

    @property
    def last_sample(self) -> dict:
        return self._last

    def _sample_loop(self):
        while self._running:
            try:
                cpu     = psutil.cpu_percent(interval=CPU_SAMPLE_INTERVAL)
                base    = self.baseline
                delta   = cpu - base
                is_spike = (delta >= CPU_SPIKE_THRESHOLD) or (cpu >= CPU_SPIKE_MIN_VALUE)

                sample = {
                    "timestamp":   datetime.now(timezone.utc).isoformat(),
                    "cpu_percent": round(cpu,   2),
                    "baseline":    round(base,  2),
                    "spike_delta": round(delta, 2),
                    "is_spike":    is_spike,
                }

                self._baseline_samples.append(cpu)
                self._last = sample

                if self.on_sample:
                    self.on_sample(sample)

                if is_spike and self.on_spike:
                    self.on_spike(sample)
                    print(f"[cpu] !! SPIKE: {cpu:.1f}%  (baseline={base:.1f}%  delta=+{delta:.1f}%)")

            except Exception as e:
                print(f"[cpu_monitor] Error: {e}")

    def start(self):
        self._running = True
        self._thread  = threading.Thread(target=self._sample_loop, daemon=True)
        self._thread.start()
        print(f"[cpu_monitor] Started.")
        print(f"  Sample interval : {CPU_SAMPLE_INTERVAL}s")
        print(f"  Spike threshold : baseline + {CPU_SPIKE_THRESHOLD}%  OR  raw > {CPU_SPIKE_MIN_VALUE}%")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)
        print("[cpu_monitor] Stopped.")


# ── Quick test ────────────────────────────────────────────────
if __name__ == "__main__":
    def on_spike(s):
        print(f"  → ALERT  cpu={s['cpu_percent']}%  delta={s['spike_delta']}%")

    def on_sample(s):
        bar = "█" * int(s["cpu_percent"] / 5)
        print(f"  CPU {s['cpu_percent']:5.1f}%  [{bar:<20}]  spike={s['is_spike']}")

    mon = CPUMonitor(on_spike=on_spike, on_sample=on_sample)
    mon.start()
    print("Monitoring CPU for 15 seconds...")
    try:
        time.sleep(15)
    except KeyboardInterrupt:
        pass
    mon.stop()