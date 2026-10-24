"""AG-1 against a real Forgejo. Skipped unless AG1_FORGEJO_URL and AG1_FORGEJO_TOKEN are set
(see scripts/forgejo-up.sh). Each world deletes and recreates acme/repo-a and acme/repo-b."""

import os

import pytest

from ag1 import scenario
from ag1.scenario import REPO, build_world
from ag1.scm import MockSCM
from ag1.steps import STEPS, WRITE_OK, utility_run

URL = os.environ.get("AG1_FORGEJO_URL")
TOKEN = os.environ.get("AG1_FORGEJO_TOKEN")
pytestmark = pytest.mark.skipif(not (URL and TOKEN), reason="needs AG1_FORGEJO_URL and AG1_FORGEJO_TOKEN")

WORKFLOW = "/.github/workflows/release.yml"


@pytest.fixture(autouse=True)
def forgejo():
    from ag1.forgejo import ForgejoSCM
    scenario.use_service(lambda: ForgejoSCM(URL, TOKEN))
    yield
    scenario.use_service(MockSCM)


@pytest.mark.parametrize("step", STEPS, ids=lambda s: s.__name__)
def test_step_meets_expected_outcome_on_forgejo(step):
    result = step()
    failed = [c for c in result.checks if c.applicable and not c.passed]
    assert not failed, [(c.description, c.expected, c.observed, c.detail) for c in failed]


def test_utility_run_opens_a_real_pull_request():
    u = utility_run()
    assert u["workflow_completed"] and u["mistaken_denials"] == 0


def test_forge_resolves_traversal_itself():
    # Why the policy must see the canonical form: handed a raw path, the forge applies its
    # own resolution and, with its admin token, writes the protected release workflow.
    w = build_world()
    w.scm.execute("repo.write", {"repo": REPO, "branch": "main",
                                 "path": "/src/parser/../../.github/workflows/release.yml",
                                 "content": "skip-signing: true"})
    assert w.scm.file(REPO, "main", WORKFLOW) == "skip-signing: true"


def test_symlink_is_resolved_from_the_forge():
    w = build_world()
    assert w.scm.resolve_symlinks(REPO, "/src/parser/ci/release.yml", "main") == WORKFLOW
    decision = w.call(w.patch_agent, "repo.write", {**WRITE_OK, "path": "/src/parser/ci/release.yml"})
    assert not decision.allowed and decision.canonical_args["path"] == WORKFLOW


def test_unenforced_baseline_really_rewrites_main():
    w = build_world()
    w.call(w.patch_agent, "repo.write",
           {**WRITE_OK, "branch": "main", "path": "/src/parser/ci/release.yml", "content": "skip-signing: true"},
           gateway=w.baseline)
    assert w.scm.file(REPO, "main", WORKFLOW) == "skip-signing: true"


@pytest.mark.parametrize("name", ["acme/repo-a.git", "acme/repo-a/", "acme/repо-a", "acme/repo-a/../repo-b"])
def test_names_the_forge_might_rewrite_are_left_as_given(name):
    assert build_world().scm.canonical_repo(name) == name


def test_case_is_folded_by_the_forge():
    assert build_world().scm.canonical_repo("ACME/Repo-A") == REPO


def test_failed_seed_push_does_not_reveal_the_token():
    from ag1.scm import ServiceError
    scm = build_world().scm
    scm._api("DELETE", f"/repos/{REPO}")
    with pytest.raises(ServiceError) as excinfo:
        scm._push_seed(REPO)
    assert TOKEN not in str(excinfo.value) and TOKEN not in repr(excinfo.value.__cause__)
