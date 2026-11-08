"""The AG-1 scenario: an orchestrator remediates a CVE in one repository.

The developer's request becomes a task grant issued by the task
authorization system (the trusted root) to the orchestrator. The
orchestrator delegates a narrower grant to a patch agent, and the patch agent
delegates a test-only grant to a test runner, which cannot delegate further.
Deployment is a separate task with its own approval-gated grant.

Grants are written in the neutral vocabulary of `spec`, so the same scenario
runs against any adapter.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .adapters import DEFAULT, load
from .adapters.base import Adapter, Principal
from .gateway import Decision, EnforcementPoint, Request
from .scm import MockSCM, Service
from .spec import AnyValue, ApprovalGate, Exact, OneOf, Under

REPO = "acme/repo-a"
OTHER_REPO = "acme/repo-b"
FIX_BRANCH = "fix/cve-2026-1234"
TASK_ID = "remediate-CVE-2026-1234"
RELEASE_TASK_ID = "release-app-1.4.2"
ARTIFACT = "app:1.4.2"
ARTIFACT_NEXT = "app:1.4.3"  # also deployable under the release grant, but not approved
SUITES = ("unit", "parser")
CONTROL_DOMAIN = "control.example"
DEVELOPMENT_DOMAIN = "dev.example"
TEST_DOMAIN = "test.example"
TEST_AUDIENCE = "test-gateway.test.example"
SCM_AUDIENCE = "scm-gateway.dev.example"


def write_caps(branch: str = FIX_BRANCH, root: str = "/src/parser") -> dict:
    return {"repo": Exact(REPO), "branch": Exact(branch), "path": Under(root), "content": AnyValue()}


def test_caps(suites=SUITES) -> dict:
    return {"repo": Exact(REPO), "branch": Exact(FIX_BRANCH), "suite": OneOf(tuple(suites))}


def cross_domain_test_caps(suites=SUITES, audience: str = TEST_AUDIENCE) -> dict:
    return {**test_caps(suites), "audience": Exact(audience)}


def task_caps(suites=SUITES) -> dict:
    return {
        "repo.read": {"repo": Exact(REPO)},
        "repo.write": write_caps(),
        "pr.create": {"repo": Exact(REPO), "head": Exact(FIX_BRANCH), "base": Exact("main")},
        "test.run": test_caps(suites),
    }


@dataclass
class Agent:
    principal: Principal
    chain: list
    adapter: Adapter

    @property
    def name(self) -> str:
        return self.principal.name

    def request(self, tool: str, args: dict, *, approvals=None, intent: str = "legit") -> Request:
        proof = self.adapter.prove(self.chain, self.principal, tool, args)
        return Request(self.name, self.chain, tool, args, proof, approvals, intent)


class Gateway(Protocol):
    """An enforcement point as the steps see it: in this process, or a separate service."""

    name: str

    def handle(self, req: Request) -> Decision: ...

    @property
    def evidence(self) -> list[dict]: ...

    @property
    def evidence_public_key(self) -> Ed25519PublicKey: ...

    @property
    def evidence_public_key_hex(self) -> str: ...

    def signed_checkpoint(self) -> dict: ...


@dataclass
class World:
    adapter: Adapter
    issuer: Principal
    release_approver: Principal
    scm: Service
    gateway: Gateway  # in front of the SCM, CI/CD and deployment services
    receiving: Gateway  # test service in the test domain: audience and origin allowlist (AG-1.4)
    other_service: Gateway  # another service in the development domain, with its own audience (AG-1.4)
    baseline: Gateway  # unenforced: the service acts on its own credential (AG-1.10)
    task_grant: Any
    orchestrator: Agent
    patch_agent: Agent
    test_runner: Agent
    release_agent: Agent
    revoke_at: Callable[[list], dict]
    deployment: str = "in-process"
    # Evidence records each gateway held when this world was built; a separately
    # deployed enforcement point keeps one log for the whole run.
    evidence_start: dict = field(default_factory=dict)
    remote_runner: Principal | None = None  # set by the evidence run, for AG-1.8

    @property
    def gateways(self) -> list[Gateway]:
        return [self.gateway, self.receiving, self.other_service, self.baseline]

    def call(self, agent: Agent, tool: str, args: dict, gateway: Gateway | None = None, **kw):
        return (gateway or self.gateway).handle(agent.request(tool, args, **kw))

    def agent(self, principal: Principal, chain: list) -> Agent:
        return Agent(principal, chain, self.adapter)

    def records(self, gateway: Gateway | None = None) -> list[dict]:
        """Evidence records `gateway` wrote since this world was built."""
        gateway = gateway or self.gateway
        return gateway.evidence[self.evidence_start.get(gateway.name, 0):]

    def revoke(self, grants: list) -> dict:
        """Revoke `grants` at every enforcing point; returns delivery time and reach."""
        return self.revoke_at(grants)

    def issue_task(self, holder: Principal, suites=SUITES):
        return self.adapter.issue(self.issuer, holder, task_caps(suites), ttl=7200, task=TASK_ID)

    def delegate_patch(self, task_grant, patch: Principal, suites=SUITES):
        return self.adapter.delegate(task_grant, self.orchestrator.principal, patch, task_caps(suites), ttl=1800)

    def delegate_runner(self, patch_grant, runner: Principal, suites=SUITES, ttl: int = 600):
        return self.adapter.delegate(patch_grant, self.patch_agent.principal, runner,
                                     {"test.run": test_caps(suites)}, ttl=ttl, terminal=True)


_service_factory: Callable[[], Service] = MockSCM


def use_service(factory: Callable[[], Service]) -> None:
    """Choose the SCM service every new in-process world starts from (default: the in-memory mock)."""
    global _service_factory
    _service_factory = factory


def local_deployment(adapter: Adapter) -> dict:
    """Every party and enforcement point in this process, as objects."""
    p = adapter.new_principal
    parties = {
        "issuer": p("task-authorization-system", CONTROL_DOMAIN),
        "approver": p("release-manager", CONTROL_DOMAIN),
        "orchestrator": p("orchestrator", DEVELOPMENT_DOMAIN),
        "patch": p("patch-agent", DEVELOPMENT_DOMAIN),
        "runner": p("test-runner", TEST_DOMAIN),
        "release": p("release-agent", DEVELOPMENT_DOMAIN),
    }
    scm = _service_factory()
    issuer = parties["issuer"]
    origins = {parties["orchestrator"].public_id}
    gateways = {
        "gateway": EnforcementPoint(adapter=adapter, trusted_root=issuer, scm=scm, name="main"),
        "receiving": EnforcementPoint(adapter=adapter, trusted_root=issuer, scm=scm, name="receiving",
                                      audience=TEST_AUDIENCE, trust_domain=TEST_DOMAIN,
                                      trusted_origin_principals=origins),
        "other_service": EnforcementPoint(adapter=adapter, trusted_root=issuer, scm=scm, name="other-service",
                                          audience=SCM_AUDIENCE, trust_domain=DEVELOPMENT_DOMAIN,
                                          trusted_origin_principals=origins),
        "baseline": EnforcementPoint(adapter=adapter, trusted_root=issuer, scm=scm, name="baseline",
                                     enforce=False),
    }

    def revoke(grants: list) -> dict:
        t0 = time.perf_counter()
        enforcing = [g for g in gateways.values() if g.enforce]
        for g in enforcing:
            g.verifier.install_revocation(issuer, grants)
        return {"ms": (time.perf_counter() - t0) * 1000, "enforcement_points": len(enforcing)}

    return {**parties, "scm": scm, **gateways, "revoke": revoke, "deployment": "in-process"}


_deployment: Callable[[Adapter], dict] = local_deployment


def use_deployment(factory: Callable[[Adapter], dict] | None) -> None:
    """Choose where parties and enforcement points live (default: this process)."""
    global _deployment
    _deployment = factory or local_deployment


def build_world(adapter: Adapter | str | None = None) -> World:
    if adapter is None or isinstance(adapter, str):
        adapter = load(adapter or DEFAULT)
    d = _deployment(adapter)
    adapter = d.get("adapter", adapter)
    issuer, orch, patch, runner, release = d["issuer"], d["orchestrator"], d["patch"], d["runner"], d["release"]

    task = adapter.issue(issuer, orch, task_caps(), ttl=7200, task=TASK_ID)
    patch_grant = adapter.delegate(task, orch, patch, task_caps(), ttl=1800)
    runner_grant = adapter.delegate(patch_grant, patch, runner, {"test.run": test_caps()}, ttl=600, terminal=True)
    release_grant = adapter.issue(
        issuer, release, {"deploy.staging": {"artifact": OneOf((ARTIFACT, ARTIFACT_NEXT))}}, ttl=900,
        task=RELEASE_TASK_ID, gate=ApprovalGate(tools=("deploy.staging",), approvers=[d["approver"]]),
    )

    gateways = [d["gateway"], d["receiving"], d["other_service"], d["baseline"]]
    return World(
        adapter=adapter,
        issuer=issuer,
        release_approver=d["approver"],
        scm=d["scm"],
        gateway=d["gateway"],
        receiving=d["receiving"],
        other_service=d["other_service"],
        baseline=d["baseline"],
        task_grant=task,
        orchestrator=Agent(orch, [task], adapter),
        patch_agent=Agent(patch, [task, patch_grant], adapter),
        test_runner=Agent(runner, [task, patch_grant, runner_grant], adapter),
        release_agent=Agent(release, [release_grant], adapter),
        revoke_at=d["revoke"],
        deployment=d["deployment"],
        evidence_start={g.name: len(g.evidence) for g in gateways},
    )
