"""detlab — network detection lab helpers (Shannon entropy, Zeek loader, detector runner)."""

from detlab.entropy import shannon_entropy
from detlab.killchain import detect_attack_chain
from detlab.zeek_loader import load_zeek_dns

__all__ = ["detect_attack_chain", "load_zeek_dns", "shannon_entropy"]
__version__ = "0.1.0"
