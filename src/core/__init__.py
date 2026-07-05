"""core/ — combinatorial substrate.

`Complex2D` is galois-free and part of the reference (pq128) path.
`Sheaf2D` belongs to the old galois-based stack (slated for deprecation);
it is imported lazily so that importing `core` never pulls in galois.
"""
from .complex2d import Complex2D

__all__ = ["Complex2D", "Sheaf2D"]


def __getattr__(name):
    # PEP 562 lazy attribute: defer the galois-dependent old stack until used.
    if name == "Sheaf2D":
        from .sheaf2d import Sheaf2D
        return Sheaf2D
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
