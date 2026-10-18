"""
Aegis vault - a portfolio-grade encrypted password manager.

Crypto: Argon2id (RFC 9106) -> HKDF-SHA256 (RFC 5869) -> XChaCha20-Poly1305
AEAD, with an HMAC-SHA-256-authenticated header. See aegis/crypto.py for
the design invariants and README.md for the research.
"""

from .crypto import AegisError, FormatError, UnlockError
from .vault import Vault

__version__ = "0.4.0"
__all__ = ["Vault", "AegisError", "FormatError", "UnlockError", "__version__"]
