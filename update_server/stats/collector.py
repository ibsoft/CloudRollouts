from __future__ import annotations
import time, socket
from collections import deque
from dataclasses import dataclass, asdict
from typing import Deque, Dict, Any, Optional
import psutil

@dataclass
class Sample:
    ts: float      # epoch seconds
    cpu: float     # %
    ram: float     # %
    netIn: float   # bytes/sec
    netOut: float  # bytes/sec
    rtt: float     # ms, -1 αν αποτύχει

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class StatsStore:
    def __init__(self, maxlen: int = 3600):
        self.buf: Deque[Sample] = deque(maxlen=maxlen)
        self._last_net = None  # (time, bytes_recv, bytes_sent)

    def _measure_rtt(self, host: str, port: int, timeout: float = 0.75) -> float:
        start = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return (time.perf_counter() - start) * 1000.0
        except Exception:
            return -1.0

    def sample_once(self, rtt_host: str = "1.1.1.1", rtt_port: int = 53) -> Sample:
        now = time.time()
        cpu = psutil.cpu_percent(interval=None)
        ram = psutil.virtual_memory().percent

        n = psutil.net_io_counters()
        if self._last_net is None:
            netIn = netOut = 0.0
        else:
            dt = max(1e-6, now - self._last_net[0])
            netIn  = (n.bytes_recv - self._last_net[1]) / dt
            netOut = (n.bytes_sent - self._last_net[2]) / dt
        self._last_net = (now, n.bytes_recv, n.bytes_sent)

        rtt = self._measure_rtt(rtt_host, rtt_port)
        s = Sample(ts=now, cpu=cpu, ram=ram, netIn=netIn, netOut=netOut, rtt=rtt)
        self.buf.append(s)
        return s

    def latest(self) -> Optional[Sample]:
        return self.buf[-1] if self.buf else None

    def window(self, seconds: int) -> list[Dict[str, Any]]:
        if not self.buf:
            return []
        cutoff = time.time() - seconds
        return [s.to_dict() for s in self.buf if s.ts >= cutoff]

store = StatsStore(maxlen=3600)  # ~1h @1Hz
