import pytest

from ag1.steps import STEPS, utility_run


@pytest.mark.parametrize("step", STEPS, ids=lambda s: s.__name__)
def test_step_meets_expected_outcome(step):
    result = step()
    failed = [c for c in result.checks if not c.passed]
    assert not failed, [(c.description, c.expected, c.observed, c.detail) for c in failed]


def test_utility_run():
    u = utility_run()
    assert u["workflow_completed"]
    assert u["mistaken_denials"] == 0
    assert u["additional_authority_granted"]
