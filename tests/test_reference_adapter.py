"""The steps run against an implementation that is not Tenuo, and catch a weak one."""

import pytest
from reference_adapter import ReferenceAdapter, Verifier

from ag1 import spec, steps
from ag1.steps import STEPS, ag1_04, ag1_08, ag1_09, utility_run


@pytest.mark.parametrize("step", STEPS, ids=lambda s: s.__name__)
def test_reference_adapter_meets_each_step(step):
    result = step(ReferenceAdapter())
    failed = [c for c in result.checks if c.applicable and not c.passed]
    assert not failed, [(c.description, c.expected, c.observed, c.detail) for c in failed]
    assert result.not_applicable == 0


def test_reference_adapter_completes_the_workflow():
    utility = utility_run(ReferenceAdapter())
    assert utility["workflow_completed"] and utility["mistaken_denials"] == 0


class NoLinkChecks(Verifier):
    """Checks signatures, parent hashes, expiry and revocation, but nothing about what a link grants."""

    def check_link(self, parent, link):
        return None


class NoLinkChecksAdapter(ReferenceAdapter):
    verifier_class = NoLinkChecks


@pytest.mark.parametrize("step", [ag1_04, ag1_09], ids=lambda s: s.__name__)
def test_verifier_without_delegation_checks_is_caught(step):
    result = step(NoLinkChecksAdapter())
    assert not result.passed
    failed = [c.description for c in result.checks if c.applicable and not c.passed]
    assert any("presented to the enforcement point" in d or "forged link" in d for d in failed), failed


class TokenExchangeShaped(ReferenceAdapter):
    """Reports an authorization server as the signer of every link, as token exchange would."""

    capabilities = spec.AdapterCapabilities("authorization_server", "online_introspection", "opaque")

    def info(self, grant):
        info = super().info(grant)
        if grant.payload["parent"] is not None:
            info.issuer = "authorization-server"
        return info


def test_audit_path_does_not_assume_holder_signed_links():
    result = ag1_08(TokenExchangeShaped())
    failed = [c for c in result.checks if c.applicable and not c.passed]
    assert not failed, [(c.description, c.expected, c.observed) for c in failed]


def test_adapter_without_forge_link_reports_not_applicable():
    class NoForge(ReferenceAdapter):
        forge_link = property(lambda self: (_ for _ in ()).throw(AttributeError()))

    result = ag1_09(NoForge())
    assert result.not_applicable == 1
    assert any(c.observed == "not applicable" and "enforcement point" in c.description for c in result.checks)


def test_step_comments_do_not_name_another_implementation():
    for step in (steps.ag1_03, steps.ag1_06):
        assert "Tenuo" not in step(ReferenceAdapter()).comments
