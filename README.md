# AG-1 agent authorization harness

A reproducible test of task-scoped authorization for AI agents in a software factory. It runs the
AG-1 scenario that Tenuo proposed in its comments on the NIST NCCoE *Secure Software Development,
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
                                   mock SCM and CI/CD service (holds an admin credential)
```

A developer asks an orchestrator agent to fix `CVE-2026-1234` in `org/repo-a`. The task grant allows
reading that repository, writing only to branch `fix/cve-2026-1234` under `/src/parser`, running the
`unit` and `parser` test suites, and opening a pull request into `main`. Deployment is a separate
task with its own grant that also needs a release manager's signed approval.

AG-1.4 additionally places the test runner and its receiving enforcement point in a separate trust
domain. The receiver independently checks the originating principal, its own intended audience,
the complete delegation chain, and the trusted issuer. The same authority presented to another
service, rooted at an untrusted issuer, or originating from an unrecognized principal is refused.

The agents are scripted; no model is involved. Each step assumes prompt injection succeeds and the
agent does what it is told, and then checks what the enforcement point allows. That is the property
that matters: an authorization control has to hold even when the agent is fully compromised.

The mock service holds a broad admin credential of its own. If a step passes, the service acted on
the authority the agent presented, not on its own.

### What the implementation supplies

The report does not attribute controls supplied by the harness to the adapter under test.

| Control | Provider |
| :- | :- |
| Grant issuance, attenuation, proof, and authorization verification | Adapter / implementation under test |
| Argument normalization | AG-1 reference enforcement point |
| Enforcement immediately before execution | AG-1 reference enforcement point |
| Evidence signing and hash linking | AG-1 reference enforcement point |
| SCM, CI/CD, and deployment behavior | AG-1 mock service |

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
| AG-1.4 | Delegation across a trust boundary | A receiving enforcement point accepts a narrower child only for the trusted origin, intended audience, valid chain, and trusted issuer; widening and excess lifetime are rejected or bounded |
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
.venv/bin/pip install -r requirements-lock.txt
.venv/bin/pip install --no-deps --no-build-isolation -e .
.venv/bin/pytest -q
.venv/bin/python -m ag1 --out results
.venv/bin/python -m ag1 --verify results
.venv/bin/python -m ag1 --adapter mypackage.my_adapter:MyAdapter --out results-myimpl
```

`results/results.md` uses the column layout of NCCoE's functional demonstration results (Demo ID,
Expected Outcome, Observed Outcome, Comments) and adds an explicit result column.
`results/results.json` has the same data. A run also exports:

- `evidence.json`: the raw signed, hash-linked evidence records, authorization chains, trusted root,
  evidence public key, and terminal hash;
- `manifest.json`: the harness commit, platform, Python version, and installed package versions.

The evidence bundle can be checked after the original process has exited.

Or run the packaged harness in a container:

```bash
docker build -t nccoe-ag1-harness .
docker run --rm -v "$PWD/results:/results" nccoe-ag1-harness
docker run --rm -v "$PWD/results:/results" nccoe-ag1-harness --verify /results
```

## What pressure testing found, and how it is handled

These came from attacking the harness, not from the ten steps as first written.

- **Exact replay.** Proof of possession binds a request to the holder's key, the tool and the
  arguments, but an identical request resent inside the proof's validity window still verifies.
  Stopping it needs the enforcement point to remember proofs it has accepted. Tenuo provides this
  (`NonceStore`) but does not apply it in its low-level `Authorizer`; the Tenuo adapter enables it.
  As a consequence, two identical requests in the same proof window count as one.
- **Approval reuse.** An approval is bound to one exact request, but nothing stops it being presented
  again with a fresh proof. The enforcement point records approvals it has accepted and refuses
  reuse.
- **Approval clock tolerance.** Approvals are checked with a clock tolerance, and timestamps are whole
  seconds, so an approval can be accepted up to tolerance plus one second after it expires. The
  harness sets a 2-second tolerance; production deployments usually allow more and should say how
  much.
- **Ambiguous paths.** Look-alike separators (for example U+FF0F, U+2215), overlong UTF-8 and
  backslashes were initially accepted as ordinary file names. They are harmless on this mock and on
  POSIX, but some platforms and normalizations turn them into separators. The enforcement point now
  refuses them instead of guessing how a downstream tool will read them.
- **Evidence deletion.** Signed records alone do not reveal a missing record. Records are now
  hash-linked, so a deletion or reordering breaks the chain. Deleting the newest records is still
  only detectable if the latest hash is anchored elsewhere, such as a transparency log.

## Observations about Tenuo 0.3.3

- **AG-1.4, lifetime.** A child that requests a longer lifetime than its parent is not rejected; its
  expiry is clamped to the parent's, so it never outlives it.
- **AG-1.9, encoding.** A bit flip in the outer envelope that leaves the signed payload unchanged
  still verifies. Authority is unaffected (the payload and warrant ID are identical), but the byte
  encoding of a grant is not unique.

## Limits

- The agents are scripted and the services are mocks; the harness tests the authorization layer, not
  model behavior or a real SCM.
- The mock service executes the normalized arguments. A real gateway must forward the normalized
  form too, or the tool and the policy can disagree about what was requested.
- Normalization, the reference enforcement point, and evidence signing are harness components, not
  claims about the adapter. Every report identifies this responsibility split.
- Revocation is installed at one enforcement point; distribution to many is not tested.
- Misuse inside the granted scope is not prevented, only bounded. Code review, testing and branch
  protection remain necessary.
- Only the Tenuo adapter exists so far.
- Utility timing is local, automated harness processing. It does not represent network propagation,
  policy review, or human approval latency.

## License

Apache-2.0. See [LICENSE](LICENSE).
