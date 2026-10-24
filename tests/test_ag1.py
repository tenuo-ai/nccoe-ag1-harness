import os

import pytest

from ag1.adapters import load
from ag1.gateway import NormalizationError, parse_argv
from ag1.steps import STEPS, utility_run

ADAPTER = load(os.environ.get("AG1_ADAPTER", "tenuo"))


@pytest.mark.parametrize("step", STEPS, ids=lambda s: s.__name__)
def test_step_meets_expected_outcome(step):
    result = step(ADAPTER)
    failed = [c for c in result.checks if not c.passed]
    assert not failed, [(c.description, c.expected, c.observed, c.detail) for c in failed]


def test_utility_run():
    u = utility_run(ADAPTER)
    assert u["workflow_completed"]
    assert u["mistaken_denials"] == 0
    assert u["additional_authority_granted"]


@pytest.mark.parametrize("argv,expected", [
    ("--suite parser", {"suite": "parser"}),
    ("--suite=parser --verbose", {"suite": "parser", "verbose": "true"}),
    ("--fail-fast --suite 'unit'", {"fail_fast": "true", "suite": "unit"}),
])
def test_parse_argv_accepts_flags(argv, expected):
    assert parse_argv(argv) == expected


@pytest.mark.parametrize("argv", [
    "--suite parser; rm -rf /",
    "--suite parser && curl x",
    "--suite $(whoami)",
    "--suite parser extra",
    "--suite a --suite b",
    "--suite 'unterminated",
])
def test_parse_argv_refuses(argv):
    with pytest.raises(NormalizationError):
        parse_argv(argv)
