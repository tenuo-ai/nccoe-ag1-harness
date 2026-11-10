"""Checks at the actual service-call boundary, independent of evidence labels."""
import time
from dataclasses import replace

import pytest

from ag1 import scenario, steps
from ag1.adapters import EXTRAS, load
from ag1.gateway import EnforcementPoint
from ag1.spec import ApprovalGate, Exact


@pytest.fixture(params=['reference', 'tenuo'])
def adapter(request):
    try:
        return load(request.param)
    except ModuleNotFoundError as exc:
        if exc.name and exc.name.split('.')[0] in EXTRAS.get(request.param, ()):
            pytest.skip(f'optional {request.param} extra not installed')
        raise


def quorum_world(adapter):
    world = scenario.build_world(adapter)
    holder = world.release_agent.principal
    approvers = [adapter.new_principal('approver-a'), adapter.new_principal('approver-b')]
    args = {'artifact': scenario.ARTIFACT}
    grant = adapter.issue(world.issuer, holder, {'deploy.staging': {'artifact': Exact(scenario.ARTIFACT)}},
                          ttl=60, gate=ApprovalGate(('deploy.staging',), approvers, threshold=2))
    # The signed serialization must retain the threshold.
    grant = adapter.from_bytes(adapter.to_bytes(grant))
    agent = world.agent(holder, [grant])
    votes = [adapter.approve(p, grant, holder, 'deploy.staging', args) for p in approvers]
    return world, agent, approvers, votes, args


def test_quorum_requires_distinct_keys_and_preserves_votes_after_denial(adapter):
    world, agent, approvers, votes, args = quorum_world(adapter)
    second_from_same = adapter.approve(approvers[0], agent.chain[-1], agent.principal, 'deploy.staging', args)
    for approvals in ([votes[0]], [votes[0], votes[0]], [votes[0], second_from_same]):
        assert not world.call(agent, 'deploy.staging', args, approvals=approvals).allowed
        assert world.scm.deployments == []
    assert world.call(agent, 'deploy.staging', args, approvals=votes).allowed
    assert len(world.scm.deployments) == 1
    fresh = adapter.prove(agent.chain, agent.principal, 'deploy.staging', args, at=int(time.time()) - 10)
    req = replace(agent.request('deploy.staging', args, approvals=votes), proof=fresh)
    assert not world.gateway.handle(req).allowed
    assert len(world.scm.deployments) == 1


@pytest.mark.parametrize('threshold', [0, -1, 2, 3, True])
def test_reference_rejects_invalid_quorum(threshold):
    a = load('reference')
    root, holder, approver = [a.new_principal(n) for n in ('root', 'holder', 'approver')]
    with pytest.raises(ValueError, match='threshold'):
        a.issue(root, holder, {'deploy.staging': {'artifact': Exact('x')}}, ttl=60,
                gate=ApprovalGate(('deploy.staging',), [approver, approver], threshold=threshold))


@pytest.mark.parametrize('encoding', ['upper', 'whitespace'])
def test_reference_proof_encoding_cannot_bypass_replay(encoding):
    w = scenario.build_world('reference')
    req = w.test_runner.request('test.run', {'repo': scenario.REPO, 'branch': scenario.FIX_BRANCH, 'suite': 'unit'})
    assert w.gateway.handle(req).allowed
    sig = req.proof[10:]
    alias = sig.upper() if encoding == 'upper' else b' '.join(sig[i:i+2] for i in range(0, len(sig), 2))
    assert not w.gateway.handle(replace(req, proof=req.proof[:10] + alias)).allowed
    assert len(w.scm.test_runs) == 1


@pytest.mark.parametrize('step', steps.STEPS, ids=lambda s: s.__name__)
def test_every_step_checks_before_calling_the_service(adapter, monkeypatch, step):
    """Observe execute itself: no denied request may reach it, even for reads/tests.

    Both positive and negative calls are required, so deny-all or no-op execution
    cannot satisfy the observer. Canonical arguments must be those executed.
    """
    handle = EnforcementPoint.handle
    counts = {'allowed': 0, 'denied': 0}

    def observed(gateway, req):
        calls = []
        execute = gateway.scm.execute

        def capture(tool, args):
            calls.append((tool, dict(args)))
            return execute(tool, args)

        with monkeypatch.context() as patch:
            patch.setattr(gateway.scm, 'execute', capture)
            decision = handle(gateway, req)
        if decision.allowed:
            counts['allowed'] += 1
            assert calls == [(req.tool, decision.canonical_args)]
        else:
            counts['denied'] += 1
            assert calls == [], (step.__name__, req.tool, req.args, calls)
        return decision

    monkeypatch.setattr(EnforcementPoint, 'handle', observed)
    result = step(adapter)
    assert result.passed, [(c.description, c.detail) for c in result.checks if c.applicable and not c.passed]
    assert counts['allowed'] > 0 and counts['denied'] > 0


@pytest.mark.parametrize("replay", ["proof", "approval"])
def test_concurrent_replay_executes_once(monkeypatch, replay):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    w = scenario.build_world('reference')
    req = w.test_runner.request('test.run', {'repo': scenario.REPO, 'branch': scenario.FIX_BRANCH, 'suite': 'unit'})
    requests = [req] * 8
    if replay == "approval":
        w, agent, _, votes, args = quorum_world(load("reference"))
        requests = [
            replace(agent.request("deploy.staging", args, approvals=votes),
                    proof=w.adapter.prove(agent.chain, agent.principal, "deploy.staging", args,
                                          at=int(time.time()) - 10 - i))
            for i in range(8)
        ]
    check = w.gateway.verifier._check_approvals

    def slow_check(*args):
        # Release the GIL between checking replay state and consuming the proof.
        result = check(*args)
        time.sleep(0.05)
        return result

    monkeypatch.setattr(w.gateway.verifier, '_check_approvals', slow_check)
    barrier = Barrier(8)

    def send(request):
        barrier.wait(timeout=5)
        return w.gateway.handle(request)

    with ThreadPoolExecutor(max_workers=8) as pool:
        decisions = list(pool.map(send, requests))
    assert sum(d.allowed for d in decisions) == 1
    assert len(w.scm.test_runs if replay == "proof" else w.scm.deployments) == 1
    assert [e['record']['seq'] for e in w.gateway.evidence] == list(range(1, 9))


def test_utility_rejects_success_without_patch(monkeypatch):
    from ag1.scm import MockSCM
    execute = MockSCM.execute

    def no_write(self, tool, args):
        return 'pretended to write' if tool == 'repo.write' else execute(self, tool, args)

    monkeypatch.setattr(MockSCM, 'execute', no_write)
    result = steps.utility_run('reference')
    assert not result['patch_present']
    assert not result['workflow_completed']


def test_quorum_scenario_detects_downgraded_threshold():
    from ag1.adapters.reference import ReferenceAdapter

    class OneVote(ReferenceAdapter):
        def issue(self, *args, gate=None, **kwargs):
            if gate:
                gate = replace(gate, threshold=1)
            return super().issue(*args, gate=gate, **kwargs)

    assert not steps.ag1_06(OneVote()).passed


@pytest.mark.parametrize("enforce", [True, False, "missing", None, 0])
@pytest.mark.parametrize("chain_kind", ["absent", "valid", "untrusted"])
@pytest.mark.parametrize("allowed", [True, False])
def test_signed_record_chain_requirements(tmp_path, enforce, chain_kind, allowed):
    from ag1 import report
    from ag1.gateway import Decision, chain_head, record_payload

    w = scenario.build_world('reference')
    chain = {"absent": [], "valid": w.test_runner.chain,
             "untrusted": scenario.build_world('reference').test_runner.chain}[chain_kind]
    req = w.test_runner.request('test.run', {'repo': scenario.REPO, 'branch': scenario.FIX_BRANCH, 'suite': 'unit'})
    w.gateway._record(replace(req, chain=chain), Decision(allowed, 'fixture', req.args), int(time.time()))
    item = w.gateway.evidence[0]
    if enforce == "missing":
        del item["record"]["enforced"]
    else:
        item["record"]["enforced"] = enforce
    # Sign the incomplete/malformed record with the actual evidence key, so
    # rejection tests chain obligations rather than signature tampering.
    item["signature"] = w.gateway._signer.sign(record_payload(item["record"])).hex()
    w.gateway._head = chain_head(w.gateway.evidence)
    report.write([], {}, tmp_path, w.adapter, w.scm, evidence_world=w)
    result = report.verify_bundle(tmp_path, w.adapter, w.issuer.public_id, w.gateway.evidence_public_key_hex)
    assert result["signatures_valid"] == 1 and result["checkpoint_valid"]
    required = allowed and (enforce is not False or chain_kind != "absent")
    assert result["allowed_chains_required"] == int(required)
    assert result["allowed_chains_valid"] == int(allowed and chain_kind == "valid")
    assert result["valid"] is (not required or chain_kind == "valid")


def test_reference_rejects_unknown_constraint():
    a = load('reference')
    with pytest.raises(TypeError, match='unsupported constraint'):
        a.issue(a.new_principal('root'), a.new_principal('holder'),
                {'repo.read': {'repo': object()}}, ttl=60)


def test_reference_zero_ttl_approval_is_expired():
    w = scenario.build_world('reference')
    agent = w.release_agent
    args = {'artifact': scenario.ARTIFACT}
    vote = w.adapter.approve(w.release_approver, agent.chain[-1], agent.principal,
                             'deploy.staging', args, ttl=0)
    assert not w.call(agent, 'deploy.staging', args, approvals=[vote]).allowed
    assert not w.scm.deployments


def test_all_accepted_approvals_are_consumed(adapter):
    w, agent, approvers, votes, args = quorum_world(adapter)
    extra = adapter.approve(approvers[0], agent.chain[-1], agent.principal, 'deploy.staging', args)
    assert w.call(agent, 'deploy.staging', args, approvals=[votes[0], extra, votes[1]]).allowed
    fresh_vote = adapter.approve(approvers[1], agent.chain[-1], agent.principal, 'deploy.staging', args)
    fresh_proof = adapter.prove(agent.chain, agent.principal, 'deploy.staging', args, at=int(time.time()) - 10)
    req = replace(agent.request('deploy.staging', args, approvals=[votes[0], fresh_vote]), proof=fresh_proof)
    assert not w.gateway.handle(req).allowed
    assert len(w.scm.deployments) == 1
