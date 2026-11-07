"""Compose mode over real HTTP on localhost, without containers.

Every key holder and enforcement point is a separate server, as in compose. The SCM is
the in-memory mock and the test service is a stub that records runs; the container
deployment replaces both with Forgejo and real pytest runs.
"""

import pytest

from ag1 import report, scenario
from ag1.adapters import load
from ag1.compose import keyholder, pep, sink
from ag1.compose.driver import ComposeConfig, RemotePrincipal, deployment
from ag1.compose.http import serve_in_thread
from ag1.gateway import EnforcementPoint
from ag1.scenario import CONTROL_DOMAIN, DEVELOPMENT_DOMAIN, TEST_AUDIENCE, TEST_DOMAIN, SCM_AUDIENCE, build_world
from ag1.scm import MockSCM
from ag1.steps import STEPS, evidence_run, utility_run

HOLDERS = {
    "issuer": [("task-authorization-system", CONTROL_DOMAIN)],
    "approver": [],
    "orchestrator": [("orchestrator", DEVELOPMENT_DOMAIN)],
    "patch-agent": [],
    "test-runner": [],
    "release-agent": [],
    "thief": [],
}


def _stub_tests(state):
    runs = []

    def run(body):
        record = {**body, "passed": state["passed"], "summary": "stub"}
        runs.append(record)
        return record
    return {"GET /runs": lambda _: {"runs": list(runs)}, "POST /run": run}


@pytest.fixture(scope="module")
def topology():
    servers = []
    test_state = {"passed": True}

    def start(routes):
        server, url = serve_in_thread(routes)
        servers.append(server)
        return url

    peps: dict[str, str] = {}
    keyholders = {name: start(keyholder.routes(load("tenuo"), ids, peps)) for name, ids in HOLDERS.items()}
    sink_url, test_url = start(sink.routes()), start(_stub_tests(test_state))
    mock = MockSCM()
    issuer = scenario_identity(keyholders["issuer"], "task-authorization-system")
    origin = scenario_identity(keyholders["orchestrator"], "orchestrator")
    configs = {
        "main": {},
        "receiving": {"audience": TEST_AUDIENCE, "trust_domain": TEST_DOMAIN, "trusted_origin_principals": {origin}},
        "other-service": {"audience": SCM_AUDIENCE, "trust_domain": DEVELOPMENT_DOMAIN,
                          "trusted_origin_principals": {origin}},
        "baseline": {"enforce": False},
    }
    for name, extra in configs.items():
        gateway = EnforcementPoint(adapter=load("tenuo"), trusted_root=issuer, name=name,
                                   scm=pep.ComposeService(mock, test_url, sink_url), **extra)
        peps[name] = start(pep.routes(gateway, issuer))

    def fresh():
        mock.__init__()
        return mock

    scenario.use_deployment(deployment(ComposeConfig(keyholders, dict(peps), test_url, sink_url, fresh)))
    yield {"peps": peps, "issuer": issuer, "tests": test_state}
    scenario.use_deployment(None)
    for server in servers:
        server.shutdown()


def scenario_identity(url, name):
    from ag1.compose.http import call
    return next(i["public_id"] for i in call(f"{url}/identities")["identities"] if i["name"] == name)


@pytest.mark.parametrize("step", STEPS, ids=lambda s: s.__name__)
def test_step_meets_expected_outcome_across_services(topology, step):
    result = step()
    failed = [c for c in result.checks if c.applicable and not c.passed]
    assert not failed, [(c.description, c.expected, c.observed, c.detail) for c in failed]


def test_utility_run_across_services(topology):
    u = utility_run()
    assert u["workflow_completed"] and u["tests_passed"] and u["mistaken_denials"] == 0


def test_failed_tests_do_not_count_as_a_completed_workflow(topology):
    topology["tests"]["passed"] = False
    try:
        u = utility_run()
    finally:
        topology["tests"]["passed"] = True
    assert not u["tests_passed"] and not u["workflow_completed"]
    assert u["mistaken_denials"] == 0  # authorization still allowed every run


def test_driver_holds_no_private_keys(topology):
    w = build_world()
    for p in (w.issuer, w.release_approver, w.orchestrator.principal, w.patch_agent.principal):
        assert isinstance(p, RemotePrincipal) and not hasattr(p, "key")


def test_stable_identities_survive_across_worlds(topology):
    a, b = build_world(), build_world()
    assert a.issuer.public_id == b.issuer.public_id == topology["issuer"]
    assert a.patch_agent.principal.public_id != b.patch_agent.principal.public_id


def test_revocation_reaches_every_enforcement_point(topology):
    w = build_world()
    args = {"repo": scenario.REPO, "branch": scenario.FIX_BRANCH, "path": "/src/parser/x.c", "content": "x"}
    assert w.call(w.patch_agent, "repo.write", args).allowed
    reach = w.revoke([w.patch_agent.chain[-1]])
    assert reach["enforcement_points"] == 4  # each acknowledged the signed list
    assert "Revoked" in w.call(w.patch_agent, "repo.write", {**args, "content": "y"}).reason


def test_every_bundle_verifies_against_its_own_key(topology, tmp_path):
    w = evidence_run()
    bundles = {g.name: g.bundle() for g in w.gateways}
    report.write_bundles(tmp_path, bundles)
    keys = {g.name: g.evidence_public_key_hex for g in w.gateways}
    result = report.verify_bundles(tmp_path, load("tenuo"), topology["issuer"], keys)
    assert result["valid"], result
    swapped = {**keys, "main": keys["receiving"]}
    assert not report.verify_bundles(tmp_path, load("tenuo"), topology["issuer"], swapped)["valid"]
    del keys["baseline"]
    assert not report.verify_bundles(tmp_path, load("tenuo"), topology["issuer"], keys)["valid"]
