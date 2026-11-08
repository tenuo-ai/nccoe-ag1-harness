"""Adversarial tests beyond the ten AG-1 steps, and mutation tests of the harness itself.

The first part attacks the enforcement point directly. The second part
sabotages one defense at a time and checks that the harness notices: a
harness that still reports "met" with a defense switched off would be
measuring nothing.
"""

import time

import pytest

pytest.importorskip("tenuo")

from ag1 import steps  # noqa: E402
from ag1.adapters.tenuo_adapter import TenuoAdapter, TenuoVerifier  # noqa: E402
from ag1.gateway import GENESIS, Decision, EnforcementPoint, Request, chain_head, checkpoint_covers  # noqa: E402
from ag1.scenario import ARTIFACT, FIX_BRANCH, REPO, build_world, write_caps  # noqa: E402
from ag1.scm import ServiceError  # noqa: E402
from ag1.spec import AnyValue, Denied, DelegationRejected  # noqa: E402

WRITE = {"repo": REPO, "branch": FIX_BRANCH, "path": "/src/parser/lexer.c", "content": "x"}


@pytest.fixture
def world():
    return build_world("tenuo")


# Attacks on the enforcement point ---------------------------------------------------------------

PATH_ATTACKS = {
    "traversal": "/src/parser/../../.github/workflows/release.yml",
    "encoded traversal": "/src/parser/%2e%2e/%2e%2e/.github/workflows/release.yml",
    "double-encoded traversal": "/src/parser/%252e%252e/%252e%252e/.github/workflows/release.yml",
    "triple-encoded traversal": "/src/parser/%25252e%25252e/%25252e%25252e/.github/x",
    "fullwidth solidus": "/src/parser/..／..／.github/workflows/release.yml",
    "division slash": "/src/parser/..∕..∕.github/x",
    "fraction slash": "/src/parser/..⁄..⁄.github/x",
    "fullwidth reverse solidus": "/src/parser/..＼..＼.github/x",
    "one-dot leader as dot": "/src/parser/․․/․․/.github/x",
    "overlong utf-8 slash": "/src/parser/..%c0%af..%c0%af.github/x",
    "invalid utf-8": "/src/parser/%ff%fe",
    "backslash": "/src/parser/..\\..\\.github\\x",
    "null byte": "/src/parser/lexer.c%00../../.github/x",
    "newline": "/src/parser/lexer.c\n/../../.github/x",
    "sibling prefix": "/src/parser-evil/x.c",
    "relative traversal": "../../etc/passwd",
    "symlink": "/src/parser/ci/release.yml",
    "symlink directory itself": "/src/parser/ci",
    "symlink behind doubled slash": "//src/parser/ci/release.yml",
    "symlink behind tripled slash": "///src/parser/ci/release.yml",
    "case change": "/SRC/parser/lexer.c",
    "too long": "/src/parser/" + "a/" * 2100 + "x.c",
}


@pytest.mark.parametrize("name", PATH_ATTACKS)
def test_path_attacks_are_denied(world, name):
    d = world.call(world.patch_agent, "repo.write", {**WRITE, "path": PATH_ATTACKS[name]}, intent="attack")
    assert not d.allowed, (name, d.reason, d.canonical_args)
    assert world.scm.file(REPO, "main", "/.github/workflows/release.yml") == "name: release"


@pytest.mark.parametrize("path", ["/src/parser//lexer.c", "src/parser/lexer.c", "/src/parser/./lexer.c",
                                  "/src/parser/sub/../lexer.c", "/src/parser/lex%65r.c",
                                  "//src/parser/lexer.c"])
def test_equivalent_paths_inside_scope_are_allowed(world, path):
    d = world.call(world.patch_agent, "repo.write", {**WRITE, "path": path, "content": path})
    assert d.allowed, (path, d.reason)
    assert d.canonical_args["path"] == "/src/parser/lexer.c"


@pytest.mark.parametrize("field,value", [
    ("path", ["/src/parser/x", "/etc/passwd"]), ("path", 5), ("path", None), ("path", {"a": 1}),
    ("repo", ["acme/repo-a"]), ("branch", None), ("content", {"a": 1}), ("content", 5),
])
def test_non_string_values_are_refused(world, field, value):
    d = world.call(world.patch_agent, "repo.write", {**WRITE, field: value}, intent="attack")
    assert not d.allowed and "must be a string" in d.reason


@pytest.mark.parametrize("field,value", [
    ("branch", FIX_BRANCH + " "), ("branch", "Fix/cve-2026-1234"), ("branch", "refs/heads/../main"),
    ("branch", FIX_BRANCH + "/../../main"), ("repo", "acme/repo-a/"), ("repo", "acme/repo-a.git"),
    ("repo", "acme/repо-a"),  # Cyrillic o
])
def test_lookalike_identifiers_are_denied(world, field, value):
    assert not world.call(world.patch_agent, "repo.write", {**WRITE, field: value}, intent="attack").allowed


@pytest.mark.parametrize("args", [
    {"suite": "parser", "argv": "--suite integration"},
    {"argv": "--suite parser --repo acme/repo-b"},
    {"argv": "--suite parser\n--suite integration"},
    {"argv": "--suite parser\t--upload-to=x"},
    {"argv": "--suite=parser --suite=parser"},
])
def test_command_line_smuggling_is_refused(world, args):
    base = {"repo": REPO, "branch": FIX_BRANCH}
    assert not world.call(world.test_runner, "test.run", {**base, **args}, intent="attack").allowed


def test_chain_manipulation_is_denied(world):
    a, task, patch = world.adapter, *world.patch_agent.chain
    pk = world.patch_agent.principal
    for chain in ([patch, task], [patch], [task, task, patch], [task, patch, patch], []):
        proof = a.prove(chain, pk, "repo.write", WRITE) if chain else None
        assert not world.gateway.handle(Request("pa", chain, "repo.write", WRITE, proof)).allowed, chain
    # A parent holder cannot act with its child's chain, nor a child with a truncated one.
    for who, chain in ((world.orchestrator.principal, [task, patch]),
                       (world.test_runner.principal, [task, patch])):
        proof = a.prove(chain, who, "repo.write", WRITE)
        assert not world.gateway.handle(Request("x", chain, "repo.write", WRITE, proof)).allowed


def test_proof_with_shifted_timestamp_is_denied(world):
    task, patch = world.patch_agent.chain
    key = world.patch_agent.principal.key
    for shift in (3600, -3600):
        proof = bytes(patch.sign(key, "repo.write", WRITE, int(time.time()) + shift))
        assert not world.gateway.handle(Request("pa", [task, patch], "repo.write", WRITE, proof)).allowed


def test_exact_replay_is_denied_but_original_succeeds_once(world):
    req = world.patch_agent.request("repo.write", WRITE)
    assert world.gateway.handle(req).allowed
    assert not world.gateway.handle(Request("thief", req.chain, req.tool, dict(req.args), req.proof)).allowed


def test_failed_attempt_does_not_burn_a_legitimate_request(world):
    req = world.patch_agent.request("repo.write", WRITE)
    world.gateway.verifier.install_revocation(world.issuer, [])  # no-op list, verifier stays usable
    bad = Request("thief", req.chain, req.tool, {**WRITE, "path": "/etc/x"}, req.proof)
    assert not world.gateway.handle(bad).allowed
    assert world.gateway.handle(req).allowed


def test_approval_cannot_be_reused_with_a_fresh_proof(world):
    """Reuse must be caught by the approval itself, not only by replay of an identical proof."""
    ra, a = world.release_agent, world.adapter
    grant = ra.chain[-1]
    args = {"artifact": ARTIFACT}
    approval = a.approve(world.release_approver, grant, ra.principal, "deploy.staging", args)
    assert world.call(ra, "deploy.staging", args, approvals=[approval]).allowed
    # A proof from the previous 30s window is still accepted by Tenuo but has different bytes.
    older = bytes(grant.sign(ra.principal.key, "deploy.staging", args, int(time.time()) - 30))
    d = world.gateway.handle(Request("release-agent", ra.chain, "deploy.staging", args, older, [approval]))
    assert not d.allowed and "ApprovalReuse" in d.reason, d.reason


def test_approval_for_another_holder_is_refused(world):
    ra, a = world.release_agent, world.adapter
    args = {"artifact": ARTIFACT}
    wrong_holder = a.approve(world.release_approver, ra.chain[-1], world.patch_agent.principal,
                             "deploy.staging", args)
    assert not world.call(ra, "deploy.staging", args, approvals=[wrong_holder]).allowed


def test_reissued_grant_works_after_revocation(world):
    patch = world.patch_agent.chain[-1]
    world.gateway.verifier.install_revocation(world.issuer, [patch])
    assert not world.call(world.patch_agent, "repo.write", WRITE).allowed
    fresh = world.delegate_patch(world.task_grant, world.patch_agent.principal)
    agent = world.agent(world.patch_agent.principal, [world.task_grant, fresh])
    assert world.gateway.handle(agent.request("repo.write", WRITE)).allowed


def test_revocation_list_from_untrusted_issuer_is_rejected(world):
    with pytest.raises(Exception):
        world.gateway.verifier.install_revocation(world.adapter.new_principal("intruder"),
                                                  [world.patch_agent.chain[-1]])
    assert world.call(world.patch_agent, "repo.write", WRITE).allowed


def test_successive_revocations_preserve_previous_grants_and_descendants(world):
    world.revoke([world.patch_agent.chain[-1]])
    request = world.patch_agent.request("repo.write", WRITE)
    assert not world.gateway.handle(request).allowed
    world.revoke([world.release_agent.chain[-1]])
    world.revoke([])
    for gateway in (world.gateway, world.receiving, world.other_service):
        verifier = gateway.verifier
        for agent, tool, args in (
            (world.patch_agent, "repo.write", WRITE),
            (world.test_runner, "test.run", {"repo": REPO, "branch": FIX_BRANCH, "suite": "unit"}),
            (world.release_agent, "deploy.staging", {"artifact": ARTIFACT}),
        ):
            req = agent.request(tool, args)
            with pytest.raises(Denied, match="Revoked"):
                verifier.authorize(req.chain, tool, args, args, req.proof, None)
    assert world.call(world.orchestrator, "repo.read", {"repo": REPO}).allowed


def test_rejected_revocation_does_not_poison_local_state(world):
    verifier = world.gateway.verifier
    with pytest.raises(Exception):
        verifier.install_revocation(world.adapter.new_principal("intruder"), [world.task_grant])
    verifier.install_revocation(world.issuer, [world.patch_agent.chain[-1]])
    assert world.call(world.orchestrator, "repo.read", {"repo": REPO}).allowed
    assert not world.call(world.patch_agent, "repo.write", WRITE).allowed


def test_checkpoint_detects_truncation_of_its_own_log(world):
    world.call(world.patch_agent, "repo.write", WRITE)
    world.call(world.orchestrator, "repo.read", {"repo": REPO})
    gateway = world.gateway
    latest = gateway.checkpoint()
    assert checkpoint_covers(latest, gateway.evidence_public_key, gateway.evidence)
    assert not checkpoint_covers(latest, gateway.evidence_public_key, gateway.evidence[:-1])


def test_rollback_to_an_earlier_checkpoint_needs_an_anchored_head(world):
    """An earlier export is self-consistent, so only a head anchored elsewhere reveals what came after it."""
    gateway = world.gateway
    world.call(world.patch_agent, "repo.write", WRITE)
    earlier, earlier_records = gateway.checkpoint(), list(gateway.evidence)
    world.call(world.orchestrator, "repo.read", {"repo": REPO})
    anchored_head = chain_head(gateway.evidence)
    assert checkpoint_covers(earlier, gateway.evidence_public_key, earlier_records)
    assert chain_head(earlier_records) != anchored_head


@pytest.mark.parametrize("enforce", [True, False], ids=["enforced", "baseline"])
def test_failed_execution_still_leaves_a_record(world, monkeypatch, enforce):
    gateway = world.gateway if enforce else world.baseline

    def fails(tool, args):
        raise ServiceError("stored the write, then lost the connection")

    monkeypatch.setattr(gateway.scm, "execute", fails)
    with pytest.raises(ServiceError):
        world.call(world.patch_agent, "repo.write", WRITE, gateway=gateway)
    record = gateway.evidence[-1]["record"]
    assert record["decision"] == "allowed" and record["outcome"] == "execution failed: ServiceError"


def test_a_service_failure_does_not_count_as_a_refusal(world, monkeypatch):
    def fails(repo):
        raise ServiceError("forge unavailable")

    monkeypatch.setattr(world.gateway.scm, "canonical_repo", fails)
    decision = world.call(world.patch_agent, "repo.write", WRITE, intent="attack")
    assert not decision.allowed and decision.reason.startswith("ServiceError")
    result = steps.StepResult("X", "t", "e")
    result.decision("denied because the service failed", decision, False)
    assert not result.passed


def test_denial_for_the_wrong_reason_fails_the_row():
    result = steps.StepResult("X", "t", "e", reasons={"revoked": ("RevokedError",)})
    result.decision("revoked grant", Decision(False, "ExpiredError: too late", {}), False, "revoked")
    assert not result.passed and result.checks[0].expected == "denied (RevokedError)"


def test_forged_widened_link_is_refused_without_changing_main(world):
    a, patch, pk = world.adapter, world.patch_agent.chain[-1], world.patch_agent.principal
    other = a.new_principal("other-agent")
    link = a.forge_link(patch, pk, other, {"repo.write": write_caps(branch="main", root="/")}, ttl=60)
    agent = world.agent(other, [world.task_grant, patch, link])
    args = {"repo": REPO, "branch": "main", "path": "/.github/workflows/release.yml", "content": "x"}
    assert not world.gateway.handle(agent.request("repo.write", args)).allowed
    assert world.scm.file(REPO, "main", "/.github/workflows/release.yml") == "name: release"


# Mutation tests: switch off one defense and check the harness reports it ------------------------

class AllowAll(TenuoVerifier):
    def authorize(self, *a, **k):
        return None


class IgnoreProofFailures(TenuoVerifier):
    def authorize(self, chain, tool, signed_args, constraint_args, proof, approvals):
        try:
            super().authorize(chain, tool, signed_args, constraint_args, proof, approvals)
        except Denied as exc:
            if "Signature" in str(exc) or "Replay" in str(exc):
                return None
            raise


class NoReplayCache(TenuoVerifier):
    def __init__(self, root):
        super().__init__(root)
        self._nonces.is_replay = lambda proof: False


class NoApprovalSingleUse(TenuoVerifier):
    def __init__(self, root):
        super().__init__(root)
        self._used_approvals = type("Forgetful", (set,), {"update": lambda self, *a: None})()


class NoRevocation(TenuoVerifier):
    def install_revocation(self, issuer, grants):
        return None


class NoChainCheck(TenuoVerifier):
    def verify_chain(self, chain, *, as_of=None):
        return None


def adapter_with(verifier_cls=TenuoVerifier, **overrides):
    adapter = TenuoAdapter()
    adapter.verifier = lambda root: verifier_cls(root)
    for name, fn in overrides.items():
        setattr(adapter, name, fn.__get__(adapter))
    return adapter


def _delegate_without_checks(self, parent, parent_holder, child, caps, ttl, terminal=False):
    try:
        return TenuoAdapter.delegate(self, parent, parent_holder, child, caps, ttl, terminal)
    except DelegationRejected:
        return self.issue(parent_holder, child, caps, ttl)  # a fresh, unanchored grant instead of a refusal


def _issue_without_gate(self, issuer, holder, caps, ttl, task=None, gate=None):
    return TenuoAdapter.issue(self, issuer, holder, caps, ttl, task=task, gate=None)


def _without_audience(caps):
    return {tool: {k: (AnyValue() if k == "audience" else v) for k, v in constraints.items()}
            for tool, constraints in caps.items()}


def _issue_without_audience(self, issuer, holder, caps, ttl, task=None, gate=None):
    return TenuoAdapter.issue(self, issuer, holder, _without_audience(caps), ttl, task=task, gate=gate)


def _delegate_without_audience(self, parent, parent_holder, child, caps, ttl, terminal=False):
    return TenuoAdapter.delegate(self, parent, parent_holder, child, _without_audience(caps), ttl, terminal)


SABOTAGE = {
    "verifier allows everything": (lambda: adapter_with(AllowAll), ["ag1_01", "ag1_02", "ag1_03", "ag1_04", "ag1_05",
                                                                    "ag1_06", "ag1_07", "ag1_09", "ag1_10"]),
    "approval single use off": (lambda: adapter_with(NoApprovalSingleUse), ["ag1_06"]),
    "proof failures ignored": (lambda: adapter_with(IgnoreProofFailures), ["ag1_03"]),
    "no replay cache": (lambda: adapter_with(NoReplayCache), ["ag1_03"]),
    "revocation ignored": (lambda: adapter_with(NoRevocation), ["ag1_07"]),
    "chain verification skipped": (lambda: adapter_with(NoChainCheck), ["ag1_09"]),
    "delegation not checked": (lambda: adapter_with(delegate=_delegate_without_checks), ["ag1_04", "ag1_09"]),
    "approval gate dropped": (lambda: adapter_with(issue=_issue_without_gate), ["ag1_06"]),
    "grant audience not enforced": (lambda: adapter_with(issue=_issue_without_audience,
                                                         delegate=_delegate_without_audience), ["ag1_04"]),
}


@pytest.mark.parametrize("name", SABOTAGE)
def test_harness_detects_sabotaged_defense(name):
    make, targets = SABOTAGE[name]
    for step_name in targets:
        result = getattr(steps, step_name)(make())
        assert not result.passed, f"{name}: {step_name} still reports met"


def test_harness_detects_disabled_normalization(monkeypatch):
    monkeypatch.setattr(EnforcementPoint, "normalize", lambda self, tool, args: dict(args))
    assert not steps.ag1_02(TenuoAdapter()).passed


def test_harness_detects_unlinked_evidence(monkeypatch):
    original = EnforcementPoint._record

    def unlinked(self, req, decision, checked_at):
        original(self, req, decision, checked_at)
        self._head = GENESIS

    monkeypatch.setattr(EnforcementPoint, "_record", unlinked)
    assert not steps.ag1_08(TenuoAdapter()).passed


def test_harness_detects_a_baseline_that_refuses(monkeypatch):
    """AG-1.10's comparison must come from the baseline actually rewriting the workflow."""
    from ag1.scm import MockSCM

    real = MockSCM.execute

    def refuses_workflow(self, tool, args):
        if tool == "repo.write" and args["branch"] == "main":
            return "did nothing"
        return real(self, tool, args)

    monkeypatch.setattr(MockSCM, "execute", refuses_workflow)
    assert not steps.ag1_10(TenuoAdapter()).passed


def test_harness_detects_revocation_missing_at_a_receiving_point(monkeypatch):
    from ag1 import scenario

    real = scenario.local_deployment

    def main_only(adapter):
        d = real(adapter)

        def revoke(grants):
            d["gateway"].verifier.install_revocation(d["issuer"], grants)
            return {"ms": 0.0, "enforcement_points": 1}

        return {**d, "revoke": revoke}

    scenario.use_deployment(main_only)
    try:
        assert not steps.ag1_07(TenuoAdapter()).passed
    finally:
        scenario.use_deployment(None)


def test_targeted_request_cannot_be_replayed_at_main(world):
    from ag1.scenario import TEST_AUDIENCE, cross_domain_test_caps

    a = world.adapter
    grant = a.issue(world.issuer, world.orchestrator.principal,
                    {"test.run": cross_domain_test_caps()}, ttl=60)
    agent = world.agent(world.orchestrator.principal, [grant])
    req = agent.request("test.run", {"repo": REPO, "branch": FIX_BRANCH,
                                     "suite": "unit", "audience": TEST_AUDIENCE})
    assert world.receiving.handle(req).allowed
    runs = len(world.scm.test_runs)
    denied = world.gateway.handle(req)
    assert not denied.allowed
    assert "AudienceMismatch" in denied.reason
    assert len(world.scm.test_runs) == runs
    # Ordinary local requests remain usable.
    assert world.call(world.test_runner, "test.run",
                      {"repo": REPO, "branch": FIX_BRANCH, "suite": "unit"}).allowed
