"""The AG-1 scenario: an orchestrator remediates a CVE in one repository.

The developer's request becomes a task grant issued by the task
authorization service (the trusted root) to the orchestrator. The
orchestrator delegates a narrower grant to a patch agent, and the patch agent
delegates a test-only grant to a test runner, which cannot delegate further.
Deployment is a separate task with its own approval-gated grant.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from tenuo import Exact, OneOf, SigningKey, Subpath, Warrant, Wildcard

from .gateway import EnforcementPoint, Request
from .scm import MockSCM

REPO = "org/repo-a"
FIX_BRANCH = "fix/cve-2026-1234"
TASK_ID = "remediate-CVE-2026-1234"
RELEASE_TASK_ID = "release-app-1.4.2"
ARTIFACT = "app:1.4.2"
ARTIFACT_NEXT = "app:1.4.3"  # also deployable under the release grant, but not approved


@dataclass
class Agent:
    name: str
    key: SigningKey
    chain: list[Warrant]

    def request(self, tool: str, args: dict, *, approvals=None, intent: str = "legit") -> Request:
        signature = bytes(self.chain[-1].sign(self.key, tool, args, int(time.time())))
        return Request(self.name, self.chain, tool, args, signature, approvals, intent)


@dataclass
class World:
    issuer: SigningKey
    release_approver: SigningKey
    scm: MockSCM
    gateway: EnforcementPoint
    task_grant: Warrant
    orchestrator: Agent
    patch_agent: Agent
    test_runner: Agent
    release_agent: Agent

    def call(self, agent: Agent, tool: str, args: dict, **kw):
        return self.gateway.handle(agent.request(tool, args, **kw))


SUITES = ("unit", "parser")


def any_text():
    return Wildcard()


def write_constraints(branch: str = FIX_BRANCH, root: str = "/src/parser") -> dict:
    return {"repo": Exact(REPO), "branch": Exact(branch), "path": Subpath(root), "content": any_text()}


def test_constraints(suites=SUITES) -> dict:
    return {"repo": Exact(REPO), "branch": Exact(FIX_BRANCH), "suite": OneOf(list(suites))}


def task_grant_builder(holder: SigningKey, ttl: int = 7200, suites=SUITES):
    return (
        Warrant.mint_builder()
        .capability("repo.read", repo=Exact(REPO))
        .capability("repo.write", **write_constraints())
        .capability("pr.create", repo=Exact(REPO), head=Exact(FIX_BRANCH), base=Exact("main"))
        .capability("test.run", **test_constraints(suites))
        .holder(holder.public_key)
        .session_id(TASK_ID)
        .ttl(ttl)
    )


def patch_grant(task_grant: Warrant, orchestrator: SigningKey, patch_key: SigningKey, suites=SUITES) -> Warrant:
    return (
        task_grant.grant_builder()
        .capability("repo.read", repo=Exact(REPO))
        .capability("repo.write", **write_constraints())
        .capability("pr.create", repo=Exact(REPO), head=Exact(FIX_BRANCH), base=Exact("main"))
        .capability("test.run", **test_constraints(suites))
        .holder(patch_key.public_key)
        .ttl(1800)
        .grant(orchestrator)
    )


def test_runner_grant(patch: Warrant, patch_key: SigningKey, runner_key: SigningKey,
                      suites=SUITES, ttl: int = 600) -> Warrant:
    return (
        patch.grant_builder()
        .capability("test.run", **test_constraints(suites))
        .holder(runner_key.public_key)
        .ttl(ttl)
        .terminal()
        .grant(patch_key)
    )


def build_world() -> World:
    issuer = SigningKey.generate()
    approver = SigningKey.generate()
    orch_key, patch_key, runner_key, release_key = (SigningKey.generate() for _ in range(4))

    scm = MockSCM()
    gateway = EnforcementPoint(trusted_root=issuer.public_key, scm=scm)

    task = task_grant_builder(orch_key).mint(issuer)
    patch = patch_grant(task, orch_key, patch_key)
    runner = test_runner_grant(patch, patch_key, runner_key)

    release = (
        Warrant.mint_builder()
        .capability("deploy.staging", artifact=OneOf([ARTIFACT, ARTIFACT_NEXT]))
        .approval_gates({"deploy.staging": None})
        .required_approvers([approver.public_key])
        .min_approvals(1)
        .holder(release_key.public_key)
        .session_id(RELEASE_TASK_ID)
        .ttl(900)
        .mint(issuer)
    )

    return World(
        issuer=issuer,
        release_approver=approver,
        scm=scm,
        gateway=gateway,
        task_grant=task,
        orchestrator=Agent("orchestrator", orch_key, [task]),
        patch_agent=Agent("patch-agent", patch_key, [task, patch]),
        test_runner=Agent("test-runner", runner_key, [task, patch, runner]),
        release_agent=Agent("release-agent", release_key, [release]),
    )
