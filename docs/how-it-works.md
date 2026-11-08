# How AG-1 works

## Why task-scoped authorization?

A CI job token or service account may allow more than a particular agent task needs. If untrusted
issue text or a tool response redirects the agent, that excess authority can become available to
the attack. A task grant restricts the tools and arguments the agent may use for this job, and the
enforcement point checks it before execution.

In a deployment, task grants work alongside managed identity, service credentials, branch
protection, testing, and code review. They add a boundary around what the agent may request now.

Public disclosures in 2026 illustrate the risk in
[GitHub Agentic Workflows](https://www.securityweek.com/critical-vulnerability-exposes-github-agentic-workflows-to-prompt-injection/),
[Cline's triage workflow](https://snyk.io/blog/cline-supply-chain-attack-prompt-injection-github-actions/),
[Google's Gemini CLI triage workflow](https://www.pillar.security/blog/my-agentic-trust-issues-from-prompt-injection-to-supply-chain-compromise-on-gemini-cli),
and the [Claude Code GitHub Action](https://www.microsoft.com/en-us/security/blog/2026/06/05/securing-ci-cd-in-agentic-world-claude-code-github-action-case/).

## The flow

```text
Task authorization system
  └─ task grant → orchestrator
       └─ narrower grant → patch agent
            └─ test-only, terminal grant → test runner

Each tool request + grant chain + holder proof
  ↓
Enforcement point
  1. Normalize the arguments the tool will execute
  2. Verify authority, proof, expiry, revocation, and approvals
  3. Execute only if authorized; record the decision and outcome
  ↓
SCM / test service / deployment sink
```

The included Tenuo adapter verifies the chain locally. `tests/test_compose_loopback.py` checks that
authorization decisions make no call to the issuer. Other adapters declare their verification mode in
the report.

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
both enforcement points are objects in one process; in compose mode each is its own service.
Domain labels are not carried in the grants in either mode, and a deployment across real
organizational boundaries is not tested.

The service is either an in-memory mock or a real [Forgejo](https://forgejo.org/) instance
(`--service forgejo`). With Forgejo, the enforcement point calls the forge's API with an admin token,
and that service account is on the push allowlist of the protected `main` branch, as bot accounts
usually are. Normalization asks the forge: repository names, the default branch behind `HEAD`, and
symbolic links are resolved from the repository itself. After every write the file is read back at
the canonical path. Every world deletes and recreates the seed repositories, so steps start from
the same state. Test runs and deployments are still recorded by the harness in this mode.

## Compose mode

`compose.yaml` runs the same steps with every party and enforcement point as a separate container:

```
 key holders (issuer, approver, orchestrator, patch agent, test runner, release agent, thief)
   │ each signs only with the keys it holds; requests leave from the presenting agent's container
   ▼
 enforcement points: main · receiving (test domain) · other service
   │ each with its own evidence key, audience and allowed origins
   │ baseline (enforcement off) is a separate service only the driver can reach
   ▼
 Forgejo (admin token) · test service (read-only token, runs the repository's pytest suites) · staging sink
```

- Private keys never leave their key holder. The driver that runs the steps holds grants, proofs and
  approvals, which is what an observer of the traffic could hold, plus a Forgejo admin token it uses
  to reset and inspect repositories.
- A copied chain in AG-1.3 is presented from the thief's container, which does not hold the key.
- Revocation in AG-1.7 is signed by the issuer and pushed to the three enforcing points. AG-1.7
  checks that each one then refuses the revoked chain.
- The test service checks out the branch and runs real `unit`, `parser` and `integration` suites.
  The seed repository's lexer has the synthetic vulnerability: the parser suite fails until the
  patch is written.
- Each enforcement point exports its own evidence bundle, verified against its own key. AG-1.8 also
  traces a cross-domain test run through the receiving enforcement point's log.
- Networks are internal. Agents reach enforcing points but not Forgejo, the baseline, or the internet.
  The test service reaches Forgejo and the enforcing points that call it, but not the agents or the
  baseline.

## What the implementation supplies

The report does not attribute controls supplied by the harness to the adapter under test.

| Control | Provider |
| :- | :- |
| Grant issuance, attenuation, proof, and authorization verification | Adapter / implementation under test |
| Argument normalization | AG-1 reference enforcement point |
| Receiver audience comparison and originating-principal allowlist (AG-1.4) | AG-1 reference enforcement point |
| Trust-domain labels (AG-1.4) | AG-1 scenario, or deployment configuration in compose mode; not carried in grants |
| Enforcement immediately before execution | AG-1 reference enforcement point |
| Evidence signing and hash linking | AG-1 reference enforcement point |
| Refusing a replayed request or a reused approval | Adapter / implementation under test |
| SCM, CI/CD, and deployment behavior | AG-1 mock service; Forgejo for repositories and pull requests; in compose mode, also a test service running pytest and a staging sink |

Each adapter declares its delegation, verification, and artifact modes. This allows an
authorization-server-mediated OAuth design to describe itself differently from a holder-signed,
offline-verifiable capability chain without treating either architecture as the definition of
conformance. See [ADAPTERS.md](../ADAPTERS.md).

## The ten steps

| ID | Step | What it shows |
| :- | :- | :- |
| AG-1.1 | Task scoping | The allowed action works; the same action on another repository or branch is denied before it runs |
| AG-1.2 | Action constraints | Constraints hold on the canonical form: `../`, URL, double and overlong encoding, look-alike slashes, backslashes, symbolic links, `refs/heads/`, `HEAD`, case, extra arguments, non-string values, and command lines parsed into flags |
| AG-1.3 | Sender constraint | A copied chain without the key, no proof, a proof replayed with other arguments, and an exact replay are all refused |
| AG-1.4 | Delegation across a simulated trust boundary | A receiving enforcement point accepts a narrower child only for the trusted origin, intended audience, valid chain, and trusted issuer; widening and excess lifetime are rejected by the delegation API, and links a holder signs itself are refused at the enforcement point |
| AG-1.5 | Prompt injection | An issue that asks for a workflow edit, a push to `main` and a production deploy gets none of them, and the real task still proceeds |
| AG-1.6 | Human approval | No approval, the wrong approver, an approval for a different artifact, an expired approval and a reused approval are refused; one valid approval deploys once |
| AG-1.7 | Expiry and revocation | Grants that worked before expiry or revocation then fail at every enforcing point, revocation reaches everything delegated below, and a concurrent task keeps working |
| AG-1.8 | Audit reconstruction | Every record is signed, hash-linked and re-verifiable from the root key; the delegation path, approver and denials are reconstructed; edited records, records deleted from the middle, and records removed from an export are detected |
| AG-1.9 | Forged or spliced chain | Every single-bit change to each link, links spliced from another chain, reordered or truncated chains, untrusted roots, and links signed by the wrong key are rejected |
| AG-1.10 | Confused deputy | A service that could act on its own admin credential refuses out-of-scope requests; with enforcement off, the same request rewrites the workflow, read back from the service |

The run also reports utility: tasks completed within the initial grant, requests for additional
authority and their latency, and denials of in-scope requests.

## Limits

- The harness evaluates a bounded scenario. It does not establish production readiness.
- The agents are scripted; the harness tests the authorization layer, not model behavior. In AG-1.5
  the agent obeys the injected text, so the step shows what is refused, not whether a model would
  follow the instruction.
- Forgejo modes use real repositories and pull requests. Only Compose runs repository test suites;
  in-process modes record test requests. Deployment is a recording sink in every mode.
- In compose mode, containers share the host's clock and talk plain HTTP inside internal Docker
  networks, without mutual TLS or workload identity. At startup, an enforcement point reads its trust
  root and the domain labels of the issuer and the orchestrator from their key holders; other parties
  are recorded as `unknown`.
- Compose mode separates keys and traffic, but does not authenticate callers on its internal networks.
  A key holder signs for any caller that can reach it, and any caller on the network can read an
  enforcement point's evidence.
- Test suites run code the patch agent wrote. That code runs in the test service, where it can read
  the read-only Forgejo token and reach the enforcing points, which still require a valid grant. A
  deployment with live agents needs authenticated control interfaces and a separate test sandbox.
- `actor` and `intent` in evidence records are labels the caller supplies. Enforcement ignores them.
- A signed checkpoint detects records removed from an export by anyone without the evidence key.
  Rolling back to an earlier checkpoint, or re-signing with the evidence key, is detected only against
  a head anchored elsewhere, such as a transparency log. The harness does not anchor heads.
- Normalization, the reference enforcement point, and evidence signing are harness components, not
  claims about the adapter. Every report identifies this responsibility split.
- Revocation is pushed to every enforcing point in the deployment, synchronously; delayed or failed
  propagation is not tested, and the harness sets no propagation objective.
- Misuse inside the granted scope is not prevented, only bounded. Code review, testing and branch
  protection remain necessary.
- Two adapters are included: Tenuo, and `src/ag1/adapters/reference.py`, a small example used as
  the default and to test the harness. The reference adapter is not meant for deployment.
- Utility timing is local, automated harness processing. It does not represent network propagation,
  policy review, or human approval latency.
