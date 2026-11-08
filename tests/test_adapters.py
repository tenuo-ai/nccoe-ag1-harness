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


def test_unknown_name_lists_the_choices():
    with pytest.raises(LookupError, match="reference, tenuo"):
        adapters.load("no-such-adapter")
