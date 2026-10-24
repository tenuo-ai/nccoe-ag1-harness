# Writing an adapter

The AG-1 steps test requirements, not a product. An adapter lets any authorization implementation
run the same ten steps: OAuth token exchange with an authorization server, a capability token
format such as Biscuit or macaroons, a policy engine with delegation support, or Tenuo.

The harness keeps the parts that must be identical across implementations: the scenario, the mock
SCM/CI service, argument normalization, and the signed evidence records. The adapter supplies
everything about the authorization artifact.

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
| `new_principal(name)` | all | Create a party with a public identifier (`public_id`) |
| `issue(issuer, holder, caps, ttl, task, gate)` | all | Issue a root grant; with `gate`, require a signed approval from one of `gate.approvers` for the listed tools |
| `delegate(parent, parent_holder, child, caps, ttl, terminal)` | AG-1.4, 1.9 | Derive a child signed by `parent_holder`; raise `DelegationRejected` if it adds a tool, relaxes a constraint, exceeds depth, or is signed by someone who does not hold `parent`. A longer lifetime may be rejected or clamped |
| `prove(chain, holder, tool, args)` | AG-1.3 | Proof bound to the holder's key, the tool, and the exact arguments |
| `approve(approver, grant, holder, tool, args)` | AG-1.6 | Approval bound to this exact request |
| `verifier(trusted_root).authorize(...)` | all | Raise `Denied` unless authorized; check proof over the signed arguments and constraints over the normalized ones; use only the trusted root |
| `verifier(...).verify_chain(chain)` | AG-1.8, 1.9 | Verify every link back to the root without a tool check |
| `verifier(...).install_revocation(issuer, grants)` | AG-1.7 | Make the grants, and everything delegated from them, fail |
| `info(grant)` | AG-1.8 | Issuer, holder, tools, expiry, and task for evidence records |
| `approval_info(approval)` | AG-1.8 | Approver, approver identity, and validity for evidence records |
| `expires_at(grant)` | AG-1.4 | Expiry as a Unix timestamp |
| `encode_chain` / `decode_chain` | AG-1.8 | Portable chain encoding carried in evidence records |
| `to_bytes` / `from_bytes` / `signed_content` | AG-1.9 | Serialization, and the bytes a signature covers |

An implementation that verifies online (for example, by introspection) can still be evaluated: its
verifier calls the authorization server inside `authorize`. AG-1.9 then reports whether it rejects
forged chains, and the comments column should say that verification was online.

## Running

Register the adapter in `src/ag1/adapters/__init__.py`, or pass its path directly:

```bash
python -m ag1 --adapter mypackage.my_adapter:MyAdapter --out results-myimpl
AG1_ADAPTER=mypackage.my_adapter:MyAdapter pytest -q
```

`src/ag1/adapters/tenuo_adapter.py` is a complete example in about 150 lines.
