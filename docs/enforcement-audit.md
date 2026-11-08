# Enforcement audit

This review covers the request path, both adapters, scenario assertions, evidence verification,
Compose control services, Forgejo integration, dependency installation and CI configuration.
It is a source review with targeted regression and negative-control tests, not an independent
security certification or a proof that every possible bypass has been excluded.

## What is enforced

For requests submitted through the AG-1 enforcement point, authorization occurs before
`Service.execute`. The gateway normalizes arguments and forwards those same canonical arguments.
The adapters check signed authority, holder possession, attenuation, expiry, revocation, replay
and required approvals. Audience and originating-principal comparisons are gateway controls.
Reports distinguish these responsibilities from controls supplied by Tenuo.

`tests/test_enforcement_contract.py` observes actual service invocations across all ten scenarios
for both included adapters. It requires each allowed request to execute exactly once with the
checked arguments, and each denied request to make zero execution calls. Positive controls
also prevent a gateway that denies everything from passing. Normalization can make metadata
reads before authorization; the zero-call assertion concerns the requested tool operation.

Existing adversarial tests disable individual defenses and require scenario failures. Added
negative controls downgrade a two-person gate to one person and replace patch writes with
successful no-ops. Neither can produce a passing result.

## Defects corrected in this review

| Finding | Correction and regression check |
| --- | --- |
| Reference grants discarded the approval threshold | Sign and preserve the threshold; require distinct authorized keys; reject impossible thresholds; exercise two-person approval in AG-1.6, including duplicate votes |
| Alternate hex encodings bypassed reference proof replay detection | Accept only canonical proof encoding; uppercase and whitespace aliases cannot execute again |
| Concurrent calls could pass replay checks before either consumed the proof | Serialize authorization, consumption, execution and evidence append per gateway; eight concurrent copies must cause exactly one execution |
| A reference approval with zero TTL received the default lifetime | Distinguish zero from an omitted TTL; zero-TTL approvals cannot authorize deployment |
| Unknown reference constraint objects silently became unrestricted | Reject unsupported constraint types instead of issuing broader authority |
| A signed enforced allow without an authorization chain passed bundle verification | Require a verifiable chain for every enforced allowed record; explicitly unenforced baseline records remain valid |
| Utility completion trusted a successful write response | Read back the expected patch; a service that claims success without writing fails workflow completion |
| AG-1.9 had no positive execution control | Execute an in-scope request through the gateway before evaluating forged chains |

The concurrency regression was also run with gateway serialization deliberately disabled:
all eight requests executed and the test failed, establishing that this check detects the race.

## Boundaries that remain trusted

- **Compose control plane:** key-holder endpoints sign for reachable callers. Internal networks
  and separate key containers do not provide caller authentication. A compromised workload
  that can reach an issuer or approver can request signatures. Live hostile workloads require
  authenticated, authorized control interfaces before this topology is a security boundary.
- **Test execution:** patch-controlled Python runs in the test service, with access to its
  read-only Forgejo token and internal network. The harness is not an arbitrary-code sandbox.
  A hostile test can falsify its own process result; a passing pytest result is not a security
  attestation. Deployment is only a recording sink.
- **Service and state:** the gateway, adapter, service credentials and scenario driver are trusted.
  Per-gateway serialization does not provide a distributed replay cache, durable state across
  restarts, or atomicity with independent repository writers. Forgejo refs can change between
  normalization and execution; the scenarios assume controlled writers.
- **Evidence:** offline verification checks signatures, hash links, checkpoints and historical
  grant chains. It does not independently replay the complete authorization decision: original
  possession proofs and verifiable approval artifacts are not retained for that purpose.
  Service effects are tested separately. The evidence signer remains trusted, and rollback
  needs an externally anchored head.
- **Coverage:** the attacks are scripted and bounded. AG-1.5 assumes an injection succeeds;
  it measures refusal of the resulting out-of-scope requests, not model attack-success rates.
  Approvers are scripted key holders: approval tests establish signature binding and quorum,
  not real human consent. In-scope misuse, availability attacks, delayed revocation propagation and host compromise
  are not established as prevented.

## Reproduce

Install the locked test dependencies as described in the README, then run:

```sh
pytest -q
AG1_ADAPTER=tenuo pytest -q
pytest -q tests/test_enforcement_contract.py
```

The Tenuo extra is required for the second command. The contract tests skip Tenuo when it is
absent. The first command uses the default reference adapter for the configurable suites.
Forgejo integration tests skip without a configured instance; HTTP loopback tests use stub
services and do not establish Docker network isolation. CI separately runs real Forgejo and
Compose jobs. Inspect their results for the exact commit being evaluated before merging.
