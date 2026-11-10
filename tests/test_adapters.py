"""Adapter loading: registered names, module:Class paths, and `ag1.adapters` entry points."""

from importlib.metadata import EntryPoint

import pytest

import ag1.adapters as adapters
from ag1.adapters.reference import ReferenceAdapter


def test_registered_name_and_path_load_the_same_adapter():
    assert isinstance(adapters.load("reference"), ReferenceAdapter)
    assert isinstance(adapters.load("ag1.adapters.reference:ReferenceAdapter"), ReferenceAdapter)
    assert adapters.DEFAULT == "reference"


def test_entry_point_loads_a_third_party_adapter(monkeypatch):
    ep = EntryPoint("thirdparty", "ag1.adapters.reference:ReferenceAdapter", adapters.ENTRY_POINT_GROUP)
    monkeypatch.setattr(adapters, "entry_points", lambda group: [ep] if group == adapters.ENTRY_POINT_GROUP else [])
    assert isinstance(adapters.load("thirdparty"), ReferenceAdapter)
    assert adapters.available()[-1] == "thirdparty"


def test_unknown_name_lists_the_choices(monkeypatch):
    monkeypatch.setattr(adapters, "entry_points", lambda group: [])
    with pytest.raises(LookupError, match="reference, tenuo"):
        adapters.load("no-such-adapter")


class NotAnAdapter:
    name = "incomplete"
    version = "0"


def test_object_missing_contract_members_is_refused(monkeypatch):
    import sys
    import types
    module = types.ModuleType("incomplete_adapter")
    module.NotAnAdapter = NotAnAdapter
    monkeypatch.setitem(sys.modules, "incomplete_adapter", module)
    with pytest.raises(TypeError, match="missing: .*capabilities.*issue"):
        adapters.load("incomplete_adapter:NotAnAdapter")


def test_duplicate_entry_point_names_are_refused(monkeypatch):
    eps = [EntryPoint("dup", "ag1.adapters.reference:ReferenceAdapter", adapters.ENTRY_POINT_GROUP),
           EntryPoint("dup", "other_pkg.adapter:Other", adapters.ENTRY_POINT_GROUP)]
    monkeypatch.setattr(adapters, "entry_points", lambda group: eps)
    with pytest.raises(LookupError, match="several packages register adapter 'dup'.*other_pkg"):
        adapters.load("dup")


@pytest.mark.parametrize("missing", ["tenuo", "cbor2"])
def test_loopback_collection_skips_missing_declared_extra(monkeypatch, missing):
    import runpy
    from pathlib import Path

    def unavailable(_):
        raise ModuleNotFoundError("missing optional dependency", name=missing)

    monkeypatch.setenv("AG1_ADAPTER", "tenuo")
    monkeypatch.setattr(adapters, "load", unavailable)
    with pytest.raises(pytest.skip.Exception, match="optional tenuo extra not installed"):
        runpy.run_path(str(Path(__file__).with_name("test_compose_loopback.py")))


@pytest.mark.parametrize("error", [ModuleNotFoundError("adapter bug", name="unexpected_dependency"),
                                   LookupError("unknown adapter"), TypeError("invalid adapter contract")])
def test_loopback_collection_preserves_configuration_and_adapter_errors(monkeypatch, error):
    import runpy
    from pathlib import Path

    def broken(_):
        raise error

    monkeypatch.setenv("AG1_ADAPTER", "tenuo")
    monkeypatch.setattr(adapters, "load", broken)
    with pytest.raises(type(error)) as caught:
        runpy.run_path(str(Path(__file__).with_name("test_compose_loopback.py")))
    assert caught.value is error
