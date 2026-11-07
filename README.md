# AG-1: a test harness for AI agent authorization

**An agent is told to fix a bug. An injected instruction tells it to rewrite the release workflow.
Does the tool gateway let it?**

AG-1 is an open-source harness for testing task-scoped authorization in a software factory.
Scripted agents attempt both legitimate work and deliberate violations of their grants. Ten
steps check the decisions and produce a report with signed authorization evidence.

> **Independent proposal.** AG-1 is the scenario Tenuo proposed in
> [its comments](docs/tenuo-nccoe-devsecops-comments.pdf) on the NIST NCCoE *DevSecOps Practices* live
> document, for Example Implementation 3. It has not been adopted or endorsed by NIST or the NCCoE.

## One task, a concrete boundary

The task is to fix a vulnerability in `acme/repo-a`. The orchestrator delegates patching to one
agent and testing to another. Their authority is limited to the repository, patch branch,
source directory, and test suites needed for the job.

| Attempt | Expected result |
| :- | :- |
| Write a patch under `/src/parser` on `fix/cve-2026-1234` | Allowed |
| Run the `unit` and `parser` suites | Allowed |
| Open a pull request from the patch branch into `main` | Allowed |
| Write the same patch directly to `main` | Denied |
| Escape into `.github/workflows` through traversal or a symlink | Denied |
| Use a copied grant without its holder's key, or replay an accepted request | Denied |
| Deploy using the development task's grant | Denied |

The unenforced baseline makes the consequence visible: the service's admin credential can rewrite
the release workflow on `main`. With task authorization enforced, that same request is refused.
The legitimate patch-and-test workflow is evaluated separately to check that useful work still
completes.

**The checked-in [Compose sample run](docs/sample-results.md) met all ten steps, completed the
authorized workflow, and recorded zero denials of in-scope requests.** It used Forgejo for
repositories and pull requests, a service running real pytest suites, and a recording sink for
deployment.

## Quick start

Requires Python 3.10 or newer. This run uses an in-memory service and needs no Docker or model
credentials.

```bash
git clone https://github.com/tenuo-ai/nccoe-ag1-harness.git && cd nccoe-ag1-harness
python -m venv .venv
.venv/bin/pip install --require-hashes -r requirements-lock.txt
.venv/bin/pip install --no-deps --no-build-isolation -e .
.venv/bin/python -m ag1 --out results
```

Open `results/results.md` for the findings. The command exits nonzero if a step fails, an in-scope
request is denied, or the authorized workflow does not complete.

## Three ways to run

| Mode | What runs |
| :- | :- |
| In-memory (default) | Agents, enforcement points, and a mock source control service in one process |
| Forgejo | Real repository and pull-request operations; tests and deployment are recorded by the harness |
| Compose | Separate key holders and enforcement points, Forgejo, a pytest service, and a deployment sink |

See [Running AG-1](docs/running.md) for all three, and for how to verify the evidence.

## The ten steps

| ID | Step | What it checks |
| :- | :- | :- |
| AG-1.1 | Task scoping | Allowed on the task's repository and branch, denied elsewhere |
| AG-1.2 | Action constraints | Constraints hold on the real target, despite traversal, encodings, and symlinks |
| AG-1.3 | Sender constraint | A copied chain, a missing proof, and a replay are refused |
| AG-1.4 | Delegation across a simulated trust boundary | A narrower child is accepted only for the trusted origin and audience; widening is refused |
| AG-1.5 | Prompt injection | Injected requests are denied, and the real task still proceeds |
| AG-1.6 | Human approval | Only a valid approval deploys, and only once |
| AG-1.7 | Expiry and revocation | Expired and revoked grants fail, and a concurrent task keeps working |
| AG-1.8 | Audit reconstruction | Records are signed and hash-linked; edits and deletions are detected |
| AG-1.9 | Forged or spliced chain | Tampered, spliced, and untrusted chains are rejected |
| AG-1.10 | Confused deputy | A service with its own admin credential still refuses out-of-scope requests |

## Limits

- The agents are scripted, so this tests the authorization layer, not model behavior.
- Only Compose runs real test suites, and deployment is a recording sink in every mode.
- Compose does not authenticate callers on its internal networks, so it isn't a deployment template.
- Misuse inside the granted scope is bounded, not prevented. Code review and testing still matter.
- Tenuo is the only adapter so far. [Add yours](ADAPTERS.md).

The [full list of limits](docs/how-it-works.md#limits) has the details.

## Learn more

- [How it works](docs/how-it-works.md): the flow, Compose mode, who supplies each control, and the
  detailed steps
- [Running AG-1](docs/running.md): every mode, the outputs, and evidence verification
- [Findings](docs/findings.md): pressure testing, what it found, and Tenuo version notes
- [Sample results](docs/sample-results.md): a Compose run

## License

Apache-2.0. See [LICENSE](LICENSE).
