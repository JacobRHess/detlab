"""detlab — network detection lab helpers (Shannon entropy, Zeek loader, detector runner)."""

from detlab.entropy import shannon_entropy
from detlab.zeek_loader import load_zeek_dns

__all__ = ["shannon_entropy", "load_zeek_dns"]
__version__ = "0.1.0"
