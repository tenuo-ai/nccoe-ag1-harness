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

from dataclasses import dataclass
from typing import Any

from .adapters import load
from .adapters.base import Adapter, Principal
from .gateway import EnforcementPoint, Request
from .scm import MockSCM
from .spec import AnyValue, ApprovalGate, Exact, OneOf, Under

REPO = "org/repo-a"
FIX_BRANCH = "fix/cve-2026-1234"
TASK_ID = "remediate-CVE-2026-1234"
RELEASE_TASK_ID = "release-app-1.4.2"
ARTIFACT = "app:1.4.2"
ARTIFACT_NEXT = "app:1.4.3"  # also deployable under the release grant, but not approved
SUITES = ("unit", "parser")


def write_caps(branch: str = FIX_BRANCH, root: str = "/src/parser") -> dict:
    return {"repo": Exact(REPO), "branch": Exact(branch), "path": Under(root), "content": AnyValue()}


def test_caps(suites=SUITES) -> dict:
    return {"repo": Exact(REPO), "branch": Exact(FIX_BRANCH), "suite": OneOf(tuple(suites))}


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


@dataclass
class World:
    adapter: Adapter
    issuer: Principal
    release_approver: Principal
    scm: MockSCM
    gateway: EnforcementPoint
    task_grant: Any
    orchestrator: Agent
    patch_agent: Agent
    test_runner: Agent
    release_agent: Agent

    def call(self, agent: Agent, tool: str, args: dict, **kw):
        return self.gateway.handle(agent.request(tool, args, **kw))

    def agent(self, principal: Principal, chain: list) -> Agent:
        return Agent(principal, chain, self.adapter)

    def issue_task(self, holder: Principal, suites=SUITES):
        return self.adapter.issue(self.issuer, holder, task_caps(suites), ttl=7200, task=TASK_ID)

    def delegate_patch(self, task_grant, patch: Principal, suites=SUITES):
        return self.adapter.delegate(task_grant, self.orchestrator.principal, patch, task_caps(suites), ttl=1800)

    def delegate_runner(self, patch_grant, runner: Principal, suites=SUITES, ttl: int = 600):
        return self.adapter.delegate(patch_grant, self.patch_agent.principal, runner,
                                     {"test.run": test_caps(suites)}, ttl=ttl, terminal=True)


def build_world(adapter: Adapter | str | None = None) -> World:
    if adapter is None or isinstance(adapter, str):
        adapter = load(adapter or "tenuo")
    p = adapter.new_principal
    issuer, approver = p("task-authorization-system"), p("release-manager")
    orch, patch, runner, release = p("orchestrator"), p("patch-agent"), p("test-runner"), p("release-agent")

    scm = MockSCM()
    gateway = EnforcementPoint(adapter=adapter, trusted_root=issuer, scm=scm)

    task = adapter.issue(issuer, orch, task_caps(), ttl=7200, task=TASK_ID)
    patch_grant = adapter.delegate(task, orch, patch, task_caps(), ttl=1800)
    runner_grant = adapter.delegate(patch_grant, patch, runner, {"test.run": test_caps()}, ttl=600, terminal=True)
    release_grant = adapter.issue(
        issuer, release, {"deploy.staging": {"artifact": OneOf((ARTIFACT, ARTIFACT_NEXT))}}, ttl=900,
        task=RELEASE_TASK_ID, gate=ApprovalGate(tools=("deploy.staging",), approvers=[approver]),
    )

    return World(
        adapter=adapter,
        issuer=issuer,
        release_approver=approver,
        scm=scm,
        gateway=gateway,
        task_grant=task,
        orchestrator=Agent(orch, [task], adapter),
        patch_agent=Agent(patch, [task, patch_grant], adapter),
        test_runner=Agent(runner, [task, patch_grant, runner_grant], adapter),
        release_agent=Agent(release, [release_grant], adapter),
    )
