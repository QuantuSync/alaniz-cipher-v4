"""
crypto/ — v4r3 scheme implementation.

Reference (galois-free) path:
    from crypto.protocol_v4r3_pq128 import setup_pq128, keygen_pq128, encrypt_pq128
    from crypto.decrypt_v4r3_pq128 import decrypt_pq128

Old galois-based stack (slated for deprecation) is imported lazily so that
importing `crypto` never requires galois:
    SigmaV4, ProtocolV4r3, PublicParamsV4r3, KeyV4r3
"""
from .protocol_v4r3_pq128 import (setup_pq128, keygen_pq128, encrypt_pq128,
                                     ParamsPQ128, KeyPQ128)
from .decrypt_v4r3_pq128 import decrypt_pq128

__all__ = [
    "setup_pq128", "keygen_pq128", "encrypt_pq128", "decrypt_pq128",
    "ParamsPQ128", "KeyPQ128",
    # lazily-loaded old stack (galois):
    "SigmaV4", "ProtocolV4r3", "PublicParamsV4r3", "KeyV4r3",
]

_LAZY_OLD_STACK = {
    "SigmaV4": ("crypto.sigma", "SigmaV4"),
    "ProtocolV4r3": ("crypto.protocol_v4r3", "ProtocolV4r3"),
    "PublicParamsV4r3": ("crypto.protocol_v4r3", "PublicParamsV4r3"),
    "KeyV4r3": ("crypto.protocol_v4r3", "KeyV4r3"),
}


def __getattr__(name):
    # PEP 562 lazy attribute: defer galois-dependent old stack until used.
    if name in _LAZY_OLD_STACK:
        import importlib
        mod_name, attr = _LAZY_OLD_STACK[name]
        return getattr(importlib.import_module(mod_name), attr)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
