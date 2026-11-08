from __future__ import annotations

import importlib
from importlib.metadata import entry_points

from .base import Adapter

ENTRY_POINT_GROUP = "ag1.adapters"
DEFAULT = "reference"

# Modules are imported only when an adapter is loaded, so the package imports without any
# implementation's dependencies installed.
ADAPTERS = {
    "reference": "ag1.adapters.reference:ReferenceAdapter",
    "tenuo": "ag1.adapters.tenuo_adapter:TenuoAdapter",
}
# Registered adapters whose dependencies come from an extra of the same name.
EXTRAS = {"tenuo": ("tenuo", "cbor2")}


def available() -> list[str]:
    """Registered names, then names from installed packages' `ag1.adapters` entry points."""
    return list(ADAPTERS) + sorted({ep.name for ep in entry_points(group=ENTRY_POINT_GROUP)} - set(ADAPTERS))


def load(spec: str = DEFAULT) -> Adapter:
    """Load an adapter by registered name, `ag1.adapters` entry point name, or `module:Class` path."""
    if spec in ADAPTERS:
        target = ADAPTERS[spec]
    elif ":" in spec:
        target = spec
    else:
        found = [ep for ep in entry_points(group=ENTRY_POINT_GROUP) if ep.name == spec]
        if not found:
            raise LookupError(f"no adapter {spec!r}: use one of {', '.join(available())}, or module:Class")
        return found[0].load()()
    module, _, cls = target.partition(":")
    try:
        loaded = importlib.import_module(module)
    except ModuleNotFoundError as e:
        if (e.name or "").split(".")[0] in EXTRAS.get(spec, ()):
            raise ModuleNotFoundError(f"the {spec} adapter needs: pip install 'nccoe-ag1-harness[{spec}]'",
                                      name=e.name) from e
        raise
    return getattr(loaded, cls)()
