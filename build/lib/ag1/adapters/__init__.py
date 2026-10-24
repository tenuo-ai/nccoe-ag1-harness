from __future__ import annotations

import importlib

from .base import Adapter

ADAPTERS = {
    "tenuo": "ag1.adapters.tenuo_adapter:TenuoAdapter",
}


def load(spec: str = "tenuo") -> Adapter:
    """Load an adapter by registered name or by `module:Class` path."""
    target = ADAPTERS.get(spec, spec)
    module, _, cls = target.partition(":")
    return getattr(importlib.import_module(module), cls)()
