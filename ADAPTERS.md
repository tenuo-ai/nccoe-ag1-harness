# Writing an adapter

The AG-1 steps test requirements, not a product. An adapter lets any authorization implementation
run the same ten steps: OAuth token exchange with an authorization server, a capability token
format such as Biscuit or macaroons, a policy engine with delegation support, or Tenuo.

The harness keeps the parts that must be identical across implementations: the scenario, the SCM/CI
service (an in-memory mock or a real Forgejo), argument normalization, and the signed evidence
records. Every result contains a responsibility table so those reference controls are not
attributed to the adapter. The adapter supplies everything about the authorization artifact.

## Architecture declaration

An adapter declares three properties with `AdapterCapabilities`:

| Property | Values | Meaning |
| :- | :- | :- |
| `delegation_mode` | `holder_signed`, `authorization_server` | Whether a holder derives the child directly or exchanges parent authority at a server |
| `verification_mode` | `offline_chain`, `online_introspection`, `hybrid` | Where authorization artifacts are verified |
| `artifact_mode` | `structured_signed`, `opaque` | Whether the artifact exposes portable signed content |

These declarations are reported, not ranked. A conforming adapter can use OAuth Token Exchange and
introspection without imitating a holder-signed capability chain. Checks that inherently require a
structured offline artifact should report that architectural alternative instead of claiming that
opaque bytes form a locally verifiable chain.

A check skipped because of a declared mode is reported as *not applicable* and is never counted as
met. The report counts these checks, and a step with no other checks is not met. The declared values
are validated against the lists above.

## Interface

`src/ag1/adapters/base.py` defines the protocol. Grants are described with the neutral types in
`src/ag1/spec.py`:

| Type | Meaning |
| :- | :- |
| `Exact(value)` | The argument must equal `value` |
| `OneOf(values)` | The argument must be one of `values` |
| `Under(root)` | A path equal to `root` or below it (the harness normalizes paths first) |
| `AnyValue()` | The argument must be present and may take any value |

Arguments not listed for a tool must be refused.

| Method | Used by | Must |
| :- | :- | :- |
| `new_principal(name, trust_domain)` | all | Create a party with a public identifier (`public_id`) and declared trust domain |
| `issue(issuer, holder, caps, ttl, task, gate)` | all | Issue a root grant; with `gate`, require a signed approval from one of `gate.approvers` for the listed tools |
| `delegate(parent, parent_holder, child, caps, ttl, terminal)` | AG-1.4, 1.9 | Obtain a child authorized by the parent holder, either locally or through an authorization server; raise `DelegationRejected` if it widens authority or exceeds depth. A longer lifetime may be rejected or clamped |
| `prove(chain, holder, tool, args, at=None)` | AG-1.3, 1.6 | Proof bound to the holder's key, the tool, and the exact arguments, made at time `at` (default now) |
| `approve(approver, grant, holder, tool, args, ttl=None)` | AG-1.6 | Approval bound to this exact request, valid for `ttl` seconds |
| `verifier(trusted_root).authorize(...)` | all | Raise `Denied` unless authorized; check proof over the signed arguments and constraints over the normalized ones; use only the trusted root; refuse an identical request already authorized and an approval already used |
| `verifier(...).verify_chain(chain, as_of=None)` | AG-1.8, 1.9 | Verify every link back to the root without a tool check; must accept `as_of`, and use that signed authorization time when it is supplied, otherwise the current time |
| `verifier(...).install_revocation(issuer, grants)` | AG-1.7 | Make the grants, and everything delegated from them, fail |
| `info(grant)` | AG-1.8 | Issuer, holder, tools, expiry, and task for evidence records |
| `approval_info(approval)` | AG-1.8 | Approver, approver identity, and validity for evidence records |
| `expires_at(grant)` | AG-1.4 | Expiry as a Unix timestamp |
| `encode_chain` / `decode_chain` | AG-1.8 | Portable chain encoding carried in evidence records |
| `to_bytes` / `from_bytes` / `signed_content` | AG-1.9 | Serialization, and the bytes a signature covers |

A chain is a list of links, root first. An authorization-server adapter returns one link per exchange.
`GrantInfo.issuer` is whoever signed the link, so it may be the server on every link.

These are optional:

| Member | Used by | Effect |
| :- | :- | :- |
| `forge_link(parent, signer, child, caps, ttl, terminal=False)` | AG-1.4, 1.9 | Build a link claiming to extend `parent`, signed by `signer`, without any delegation check, so the step can present it to the enforcement point. Without it, those checks are reported as not applicable |
| `denial_reasons` | all | Maps each kind of denial the steps name (`constraint`, `tool`, `proof`, `replay`, `root`, `chain`, `approval_missing`, `approval`, `approval_reuse`, `expired`, `revoked`) to the reasons this implementation gives. A row then fails if a request is denied for a different reason |
| `notes` | all | Maps a step ID to a sentence about this implementation, added to that step's comments |

An implementation that verifies online (for example, by introspection) can still be evaluated: its
verifier calls the authorization server inside `authorize`. Its evidence should identify the
introspection decision and trusted server, and checks that require offline chain reconstruction
should be reported as an architectural alternative rather than silently simulated.

## Remote operation (compose mode)

In compose mode each party's key stays in its own key holder service, and enforcement points
are separate services. The harness then also needs:

| Method | Must |
| :- | :- |
| `public_principal(name, public_id, trust_domain)` | A party known only by its public identifier, usable as a holder, a delegation child, an approval holder, or an approver in a gate |
| `proof_to_bytes` / `proof_from_bytes` | Carry a proof of possession across the network unchanged |
| `approval_to_bytes` / `approval_from_bytes` | Carry a signed approval across the network unchanged |
| `revocation(issuer, grants, version)` | A revocation list signed by `issuer`, cumulative, with an increasing version |
| `verifier(...).apply_revocation(data)` | Install a list produced by `revocation`, refusing one not signed by the trusted root |

An adapter without them still runs in-process. With them, `AG1_ADAPTER=... pytest tests/test_compose_loopback.py`
runs every step across separate HTTP services on localhost, without Docker.

## Running

Register the adapter in `src/ag1/adapters/__init__.py`, or pass its path directly:

```bash
python -m ag1 --adapter mypackage.my_adapter:MyAdapter --out results-myimpl
AG1_ADAPTER=mypackage.my_adapter:MyAdapter pytest -q
```

`tests/test_ag1.py` and `tests/test_compose_loopback.py` use `AG1_ADAPTER`. `tests/test_adversarial.py`
is specific to Tenuo.

`src/ag1/adapters/tenuo_adapter.py` is a complete example in about 300 lines. `tests/reference_adapter.py`
is a smaller one with no Tenuo code.
