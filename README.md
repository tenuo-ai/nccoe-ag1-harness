# AG-1 agent authorization harness

A reproducible run of the AG-1 scenario that Tenuo proposed in its comments on the NIST NCCoE
*Secure Software Development, Security, and Operations (DevSecOps) Practices* live document, for
Example Implementation 3 (agentic AI developing, building, and testing code).

The harness tests the requirements, not a product. Tenuo is the implementation under test here;
the same steps can be run against any implementation that provides task-scoped, delegable,
sender-constrained authorization.

## Scenario

A developer asks an orchestrator agent to remediate `CVE-2026-1234` in `org/repo-a`.

- The task authorization service (the trusted root) issues the orchestrator a task grant: read
  `org/repo-a`, write only to branch `fix/cve-2026-1234` under `/src/parser`, run the `unit` and
  `parser` test suites, and open a pull request into `main`. Nothing else.
- The orchestrator delegates a grant to a patch agent. The patch agent delegates a test-only,
  terminal grant to a test runner.
- Deployment is a separate task with its own grant, gated on a release manager's signed approval.
- Every call goes through an enforcement point in front of a mock SCM and CI/CD service. The service
  holds a broad admin credential of its own, so a pass shows that the service acted on the authority
  presented, not on its own.

No model is involved: a scripted agent makes each call, including the calls an injected agent would
make. The harness assumes prompt injection succeeds and checks what the enforcement point allows.

## Steps

| ID | Step | What is exercised |
| :- | :- | :- |
| AG-1.1 | Task scoping | Allowed repository action vs. the same action on another repository or branch |
| AG-1.2 | Action constraints | Path, branch and repository constraints after normalization: `../`, URL and double encoding, symbolic links, `refs/heads/`, `HEAD`, case, extra arguments |
| AG-1.3 | Sender constraint | Copied chain without the bound key, no proof, proof replayed with other arguments |
| AG-1.4 | Delegation | Narrower child accepted; added tool, relaxed path or branch, added suite, depth past a terminal grant rejected; longer lifetime clamped |
| AG-1.5 | Prompt injection | Instructions in an issue that ask for a workflow edit, a push to `main`, and a production deploy |
| AG-1.6 | Human approval | No approval, wrong approver, approval reused for another artifact, valid approval |
| AG-1.7 | Expiry and revocation | Expired grant; signed revocation list; a concurrent task keeps working |
| AG-1.8 | Audit reconstruction | Signed evidence records, offline chain re-verification, tamper detection |
| AG-1.9 | Forged or spliced chain | Bit flips over the whole grant, a link spliced from another chain, an untrusted root |
| AG-1.10 | Confused deputy | Requests a service could satisfy with its own credential, with an unenforced baseline for comparison |

The run also reports utility measures: tasks completed within the initial grant, requests for
additional authority and their latency, and denials of in-scope requests.

## Run

```bash
python -m venv .venv && .venv/bin/pip install -e '.[test]'
.venv/bin/pytest -q
.venv/bin/python -m ag1 --out results
```

`results/results.md` uses the column layout of NCCoE's functional demonstration results
(Demo ID, Expected Outcome, Observed Outcome, Comments). `results/results.json` has the same data.

## Findings from the current run (tenuo 0.3.3)

- **AG-1.4, lifetime.** A child that requests a longer lifetime than its parent is not rejected;
  its expiry is clamped to the parent's, so it never outlives it. The expected-outcome wording in
  the AG-1 profile says "rejected", and should allow for either behavior.
- **AG-1.9, encoding.** A bit flip in the outer envelope that leaves the signed payload unchanged
  still verifies. Authority is unaffected (the payload and warrant ID are identical), but the byte
  encoding of a warrant is not unique.

## Not covered yet

- Parsing command-line flags as structured arguments (Comment 3) is not exercised.
- Revocation is installed locally at one enforcement point; distribution to remote enforcement
  points is not.
- Approvals appear in evidence records by count only.
- A live-model variant that runs inside a CI job.
