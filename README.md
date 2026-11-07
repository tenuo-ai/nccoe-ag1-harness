# AG-1 agent authorization harness

A reproducible test of task-scoped authorization for AI agents in a software factory. It runs the
AG-1 scenario that Tenuo proposed in [its comments](docs/tenuo-nccoe-devsecops-comments.pdf) on the NIST NCCoE *Secure Software Development,
Security, and Operations (DevSecOps) Practices* live document, for Example Implementation 3
(agentic AI developing, building, and testing code).

The harness tests requirements, not a product. Implementations plug in through an adapter
([ADAPTERS.md](ADAPTERS.md)); a Tenuo adapter is included.

> **Independent proposal.** This repository is a Tenuo contribution and implementation aid. AG-1
> has not been adopted or endorsed by NIST or the NCCoE.

## The problem

A coding agent today usually acts with a standing credential: a role, a service account, a CI job
token, or a developer's own session. That credential is sized for everything the agent might ever
do, so it typically covers reading many repositories, writing any branch, running pipelines, and
sometimes reading secrets or deploying.

That is tolerable when a person decides each action. It is not when the agent's next action can be
decided by text it reads. An issue, a pull request description, a dependency's README, or a tool
response can instruct the agent, and whatever the agent is told to do is carried out with the full
credential. Public incidents in 2026 followed exactly this pattern in
[GitHub Agentic Workflows](https://www.securityweek.com/critical-vulnerability-exposes-github-agentic-workflows-to-prompt-injection/),
[Cline's triage workflow](https://snyk.io/blog/cline-supply-chain-attack-prompt-injection-github-actions/),
[Google's Gemini CLI triage workflow](https://www.pillar.security/blog/my-agentic-trust-issues-from-prompt-injection-to-supply-chain-compromise-on-gemini-cli),
and the [Claude Code GitHub Action](https://www.microsoft.com/en-us/security/blog/2026/06/05/securing-ci-cd-in-agentic-world-claude-code-github-action-case/).

Identity does not fix this. Knowing reliably *which* agent is acting says nothing about *what it
should be able to do right now*.

## What task-scoped authorization changes

Task-scoped authorization gives each task its own grant, sized for that task and nothing else, and
checks every tool call against it.

| | Standing credential (role, session, job token) | Task grant |
| :- | :- | :- |
| Scope | Everything the role might need | What this task needs: these tools, these repositories, this branch, these paths, these test suites |
| Lifetime | Hours to indefinite, shared across tasks | Minutes, tied to one task; nothing exists between tasks |
| Granularity | Usually resource or permission level | Tool and argument level, checked on the normalized arguments |
| Delegation | A sub-agent inherits the credential, or a new one is minted out of band | A child grant is derived from the parent and can only narrow it; the chain is verifiable |
| Theft | A copied token works for whoever holds it | Bound to the holder's key; a copy without the key is useless, and an exact replay is refused |
| Prompt injection | Redirects the agent and its full authority | Redirects the agent, but the enforcement point refuses anything outside the grant |
| Needing more | Use what you already have | Ask for a new grant; an existing grant cannot widen |
| Audit | Logs say what happened | Each decision is recorded with the chain that authorized it, verifiable from the root key |

The rest of the stack stays: agents keep managed identities, the CI job token remains the outer
bound, branch protection and code review remain the last gate. The task grant narrows what an agent
can do inside those bounds.

## What the harness does

```
 developer request
        │
        ▼
 task authorization system ── issues task grant ──▶ orchestrator
   (trusted root)                                     │ delegates (narrower)
                                                      ▼
                                                 patch agent ── delegates (test only, terminal) ──▶ test runner
                                                      │                                                 │
                         every tool call, with the chain and a proof of possession                      │
                                                      ▼                                                 ▼
                     ┌──────────────────────── enforcement point ─────────────────────────┐
                     │ 1. normalize arguments (paths, refs, encodings, command lines)       │
                     │ 2. verify the chain to the trusted root, proof, constraints,         │
                     │    expiry, revocation, approvals, replay   (no call to the issuer)   │
                     │ 3. execute only if authorized                                        │
                     │ 4. append a signed, hash-linked evidence record                      │
                     └───────────────────────────────────┬──────────────────────────────────┘
                                                         ▼
                    SCM and CI/CD service (holds an admin credential): a real Forgejo, or an in-memory mock
```

A developer asks an orchestrator agent to fix `CVE-2026-1234` in `acme/repo-a`. The task grant allows
reading that repository, writing only to branch `fix/cve-2026-1234` under `/src/parser`, running the
`unit` and `parser` test suites, and opening a pull request into `main`. Deployment is a separate
task with its own grant that also needs a release manager's signed approval.

AG-1.4 also simulates a trust boundary: a second enforcement point, configured with its own audience
and a list of trusted originating principals, receives a grant delegated to a test runner labelled
as belonging to another domain. It checks the complete delegation chain against the trusted issuer
(the adapter's job), and compares the requested audience with its own and the root holder with its
allowlist (the reference enforcement point's job). The same authority presented to another service,
rooted at an untrusted issuer, or originating from an unrecognized principal is refused. In-process,
both enforcement points are objects in one process; in compose mode (below) each is its own service.
Domain labels are not carried in the grants in either mode, and a deployment across real
organizational boundaries is not tested.

The agents are scripted; no model is involved. Each step assumes prompt injection succeeds and the
agent does what it is told, and then checks what the enforcement point allows. That is the property
that matters: an authorization control has to hold even when the agent is fully compromised.

The service holds a broad admin credential of its own. If a step passes, the service acted on the
authority the agent presented, not on its own.

The service is either an in-memory mock or a real [Forgejo](https://forgejo.org/) instance
(`--service forgejo`). With Forgejo, the enforcement point calls the forge's API with an admin token,
and that service account is on the push allowlist of the protected `main` branch, as bot accounts
usually are. Normalization asks the forge: repository names, the default branch behind `HEAD`, and
symbolic links are resolved from the repository itself. After every write the file is read back at
the canonical path. Every world deletes and recreates the seed repositories, so steps start from
the same state. Test runs and deployments are still recorded by the harness in this mode.

### Compose mode

`compose.yaml` runs the same steps with every party and enforcement point as a separate container:

```
 key holders (issuer, approver, orchestrator, patch agent, test runner, release agent, thief)
   │ each signs only with the keys it holds; requests leave from the presenting agent's container
   ▼
 enforcement points: main · receiving (test domain) · other service · baseline (unenforced)
   │ each with its own evidence key, audience and allowed origins
   ▼
 Forgejo (admin token) · test service (read-only token, runs the repository's pytest suites) · staging sink
```

- Private keys never leave their key holder. The driver that runs the steps holds only grants,
  proofs and approvals, which is what an observer of the traffic could hold.
- A copied chain in AG-1.3 is presented from the thief's container, which does not hold the key.
- Revocation in AG-1.7 is signed by the issuer and pushed to all four enforcement points.
- The test service checks out the branch and runs real `unit`, `parser` and `integration` suites.
  The seed repository's lexer has the CVE: the parser suite fails until the patch is written.
- Each enforcement point exports its own evidence bundle, verified against its own key. AG-1.8 also
  traces a cross-domain test run through the receiving enforcement point's log.
- Networks are internal. Agents reach enforcement points but not Forgejo or the internet. The test
  service reaches Forgejo and the enforcement points that call it, but not the agents.

### What the implementation supplies

The report does not attribute controls supplied by the harness to the adapter under test.

| Control | Provider |
| :- | :- |
| Grant issuance, attenuation, proof, and authorization verification | Adapter / implementation under test |
| Argument normalization | AG-1 reference enforcement point |
| Receiver audience comparison and originating-principal allowlist (AG-1.4) | AG-1 reference enforcement point |
| Trust-domain labels (AG-1.4) | AG-1 scenario, or deployment configuration in compose mode; not carried in grants |
| Enforcement immediately before execution | AG-1 reference enforcement point |
| Evidence signing and hash linking | AG-1 reference enforcement point |
| SCM, CI/CD, and deployment behavior | AG-1 mock service; Forgejo for repositories and pull requests; in compose mode, also a test service running pytest and a staging sink |

Each adapter declares its delegation, verification, and artifact modes. This allows an
authorization-server-mediated OAuth design to describe itself differently from a holder-signed,
offline-verifiable capability chain without treating either architecture as the definition of
conformance. See [ADAPTERS.md](ADAPTERS.md).

## The ten steps

| ID | Step | What it shows |
| :- | :- | :- |
| AG-1.1 | Task scoping | The allowed action works; the same action on another repository or branch is denied before it runs |
| AG-1.2 | Action constraints | Constraints hold on the canonical form: `../`, URL, double and overlong encoding, look-alike slashes, backslashes, symbolic links, `refs/heads/`, `HEAD`, case, extra arguments, non-string values, and command lines parsed into flags |
| AG-1.3 | Sender constraint | A copied chain without the key, no proof, a proof replayed with other arguments, and an exact replay are all refused |
| AG-1.4 | Delegation across a simulated trust boundary | A receiving enforcement point accepts a narrower child only for the trusted origin, intended audience, valid chain, and trusted issuer; widening and excess lifetime are rejected or bounded |
| AG-1.5 | Prompt injection | An issue that asks for a workflow edit, a push to `main` and a production deploy gets none of them, and the real task still proceeds |
| AG-1.6 | Human approval | No approval, the wrong approver, an approval for a different artifact, an expired approval and a reused approval are refused; one valid approval deploys once |
| AG-1.7 | Expiry and revocation | Expired and revoked grants fail, revocation reaches everything delegated below, and a concurrent task keeps working |
| AG-1.8 | Audit reconstruction | Every record is signed, hash-linked and re-verifiable from the root key; the delegation path, approver and denials are reconstructed; edited and deleted records are detected |
| AG-1.9 | Forged or spliced chain | Single-bit changes, links spliced from another chain, reordered or truncated chains, untrusted roots, and links signed by the wrong key are rejected without contacting the issuer |
| AG-1.10 | Confused deputy | A service that could act on its own admin credential refuses out-of-scope requests; an unenforced baseline shows what would have happened |

The run also reports utility, because a control nobody can live with gets widened until it means
nothing: tasks completed within the initial grant, requests for additional authority and their
latency, and denials of in-scope requests.

## Pressure testing

`tests/test_adversarial.py` goes beyond the ten steps in two ways.

- **Attacks on the enforcement point:** path and identifier tricks, command-line smuggling, chain
  manipulation, shifted proof timestamps, replay, approval reuse with a fresh proof, approvals for
  another holder, revocation from an untrusted issuer, and evidence truncation.
- **Mutation tests of the harness itself:** each test switches off one defense (the verifier, proof
  checking, the replay cache, revocation, chain verification, delegation checks, the approval gate,
  normalization, evidence linking) and asserts that the harness then reports a failure. A harness
  that still says "met" with a defense switched off would be measuring nothing.

## Run

```bash
python -m venv .venv
.venv/bin/pip install --require-hashes -r requirements-lock.txt
.venv/bin/pip install --no-deps --no-build-isolation -e .
.venv/bin/pytest -q
.venv/bin/python -m ag1 --out results    # prints the two verification anchors
.venv/bin/python -m ag1 --verify results --trusted-root <hex> --evidence-key <hex>
.venv/bin/python -m ag1 --adapter mypackage.my_adapter:MyAdapter --out results-myimpl
```

To run against a real Forgejo (needs Docker and git):

```bash
eval "$(scripts/forgejo-up.sh)"    # starts Forgejo 16.0.6, sets AG1_FORGEJO_URL and AG1_FORGEJO_TOKEN
.venv/bin/pytest -q tests/test_forgejo.py
.venv/bin/python -m ag1 --service forgejo --out results-forgejo
```

The run deletes and recreates `acme/repo-a` and `acme/repo-b` on that instance, so point it only at
a throwaway forge.

To run in compose mode (needs Docker Compose):

```bash
scripts/compose-up.sh            # Forgejo, its two tokens as Docker secrets, then every service
docker compose run --rm driver   # writes results-compose/ and prints the anchors
docker compose down -v
```

A compose run prints one evidence key per enforcement point, and each enforcement point also logs
its key when it starts. Verify with one `--evidence-key NAME=HEX` per bundle in
`results-compose/evidence/`:

```bash
.venv/bin/python -m ag1 --verify results-compose --trusted-root <hex> \
  --evidence-key main=<hex> --evidence-key receiving=<hex> \
  --evidence-key other-service=<hex> --evidence-key baseline=<hex>
```

`tests/test_compose_loopback.py` runs the same topology over HTTP on localhost, without Docker.

`results/results.md` uses the column layout of NCCoE's functional demonstration results (Demo ID,
Expected Outcome, Observed Outcome, Comments) and adds an explicit result column.
`results/results.json` has the same data. A run also exports:

- `evidence.json` (compose mode: `evidence/<enforcement point>.json`): the raw signed, hash-linked
  evidence records, authorization chains, trusted root, evidence public key, and terminal hash. Every
  allowed record's chain must re-verify; a denied record may carry an invalid chain, since that is
  why it was denied;
- `manifest.json`: the harness commit, platform, Python version, and installed package versions.

The evidence bundle can be checked after the original process has exited, against two anchors
the run prints: the trusted root and the evidence signing key. Take them from somewhere the
bundle's author cannot rewrite later, such as the CI log of the run or a key published by the
operator. `--verify` will not read them from the bundle: anyone able to edit the bundle could
re-sign every record with keys of their own and it would still be internally consistent. The
check shows the bundle was not altered after the run; it cannot show that the run itself was
honest.

`requirements-lock.txt` pins every package with its hashes, so pip refuses any file that differs
from the one tested. Regenerate it with
`uv pip compile requirements.in --generate-hashes --universal --python-version 3.10 -o requirements-lock.txt`.

Or run the packaged harness in a container:

```bash
docker build -t nccoe-ag1-harness .
docker run --rm -v "$PWD/results:/results" nccoe-ag1-harness    # prints the anchors
docker run --rm -v "$PWD/results:/results" nccoe-ag1-harness --verify /results \
  --trusted-root <hex> --evidence-key <hex>
```

## What pressure testing found, and how it is handled

These came from attacking the harness, not from the ten steps as first written.

- **Exact replay.** Proof of possession binds a request to the holder's key, the tool and the
  arguments, but an identical request resent inside the proof's validity window still verifies.
  Stopping it needs the enforcement point to remember proofs it has accepted. Tenuo provides this as
  a separate component (`NonceStore`), which the Tenuo adapter enables. As a consequence, two
  identical requests in the same proof window count as one.
- **Approval reuse.** An approval is bound to one exact request, but nothing stops it being presented
  again with a fresh proof. The enforcement point records approvals it has accepted and refuses
  reuse.
- **Clock tolerance.** Timestamps are whole seconds and verifiers allow some clock skew for
  approvals dated slightly in the future; expiry itself is strict. The harness sets a 2-second
  tolerance; production deployments usually allow more and should say how much.
- **Ambiguous paths.** Look-alike separators (for example U+FF0F, U+2215), overlong UTF-8 and
  backslashes were initially accepted as ordinary file names. They are harmless on this mock and on
  POSIX, but some platforms and normalizations turn them into separators. The enforcement point now
  refuses them instead of guessing how a downstream tool will read them.
- **The forge resolves paths itself.** Given `src/parser/../../.github/workflows/release.yml`, Forgejo
  writes `.github/workflows/release.yml`, and with the admin token it does so on protected `main`.
  Its API refuses reads and writes through the `src/parser/ci` symbolic link, but a git checkout of
  the branch, as a build or test runner makes, follows it. A policy checked on the string the agent sent would therefore approve a different file from the
  one the forge changes. The enforcement point checks and forwards the canonical form, and repository
  names the forge might rewrite (a `.git` suffix, look-alike characters) are refused rather than
  resolved.
- **Evidence deletion.** Signed records alone do not reveal a missing record. Records are now
  hash-linked, so a deletion or reordering breaks the chain, and a signed checkpoint over the record
  count and latest hash, checked against the evidence key held outside the bundle, catches deleted
  trailing records.

## Tenuo version

The harness pins Tenuo 0.3.5, which includes
[tenuo-ai/tenuo#997](https://github.com/tenuo-ai/tenuo/pull/997). Three behaviours in the results
come from that change:

- **AG-1.4, lifetime.** A child that requests a longer lifetime than its parent is rejected. AG-1
  also allows an implementation to limit the child to the parent's expiry.
- **AG-1.9, encoding.** Only the canonical encoding decodes, so no change to the outer envelope is
  accepted.
- **Approval expiry.** Approval expiry is strict. Clock tolerance covers only approvals dated
  slightly in the future.

## Limits

- The agents are scripted; the harness tests the authorization layer, not model behavior.
- Repositories, pull requests and test runs are real only with Forgejo; in-process with
  `--service forgejo`, test runs and deployments are still recorded by the harness. Deployment is a
  sink in every mode.
- In compose mode, containers share the host's clock and talk plain HTTP inside internal Docker
  networks, without mutual TLS or workload identity. An enforcement point knows the domain labels of
  the issuer and the orchestrator from its configuration; other parties are recorded as `unknown`.
- Normalization, the reference enforcement point, and evidence signing are harness components, not
  claims about the adapter. Every report identifies this responsibility split.
- Revocation is pushed to every enforcement point in the deployment, synchronously; delayed or
  failed propagation is not tested.
- Misuse inside the granted scope is not prevented, only bounded. Code review, testing and branch
  protection remain necessary.
- Only the Tenuo adapter exists so far.
- Utility timing is local, automated harness processing. It does not represent network propagation,
  policy review, or human approval latency.

## License

Apache-2.0. See [LICENSE](LICENSE).
