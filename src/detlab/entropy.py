"""Shannon entropy — used to score subdomain randomness when detecting DNS tunneling."""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())
