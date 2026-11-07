# Pressure testing and findings

## How the harness is tested

`tests/test_adversarial.py` goes beyond the ten steps in two ways.

- **Attacks on the enforcement point:** path and identifier tricks, command-line smuggling, chain
  manipulation, shifted proof timestamps, replay, approval reuse with a fresh proof, approvals for
  another holder, revocation from an untrusted issuer, and evidence truncation.
- **Mutation tests of the harness itself:** each test switches off one defense (the verifier, proof
  checking, the replay cache, revocation, chain verification, delegation checks, the approval gate,
  normalization, evidence linking) and asserts that the harness then reports a failure. A harness
  that still says "met" with a defense switched off would be measuring nothing.

`tests/test_reference_adapter.py` runs the steps against a small adapter with no Tenuo code. The same
adapter with its delegation checks removed fails AG-1.4 and AG-1.9.

## What pressure testing found, and how it is handled

These came from attacking the harness, not from the ten steps as first written.

- **Exact replay.** Proof of possession binds a request to the holder's key, the tool and the
  arguments, but an identical request resent inside the proof's validity window still verifies.
  Stopping it needs the verifier to remember proofs it has accepted. Tenuo provides this as a
  separate component (`NonceStore`), which the Tenuo adapter enables. As a consequence, two
  identical requests in the same proof window count as one.
- **Approval reuse.** An approval is bound to one exact request, but nothing in the approval stops it
  being presented again with a fresh proof. The Tenuo adapter records approvals it has accepted and
  refuses reuse. AG-1.6 presents a reused approval with a new proof to check this.
- **Forged links.** A delegation API refuses to widen a grant, but a compromised holder can skip that
  API and sign the link itself. AG-1.4 and AG-1.9 present such links to the enforcement point. The
  `forge_link` adapter method builds them.
- **Clock tolerance.** Timestamps are whole seconds and verifiers allow some clock skew for
  approvals dated slightly in the future; expiry itself is strict. The Tenuo adapter sets a 2-second
  tolerance; production deployments usually allow more and should say how much.
- **Ambiguous paths.** Look-alike separators (for example U+FF0F, U+2215), overlong UTF-8 and
  backslashes were initially accepted as ordinary file names. They are harmless on this mock and on
  POSIX, but some platforms and normalizations turn them into separators. The enforcement point now
  refuses them instead of guessing how a downstream tool will read them.
- **The forge resolves paths itself.** Given `src/parser/../../.github/workflows/release.yml`, Forgejo
  writes `.github/workflows/release.yml`, and with the admin token it does so on protected `main`.
  Its API refuses reads and writes through the `src/parser/ci` symbolic link, but a git checkout of
  the branch, as a build or test runner makes, follows it. A policy checked on the string the agent
  sent would therefore approve a different file from the one the forge changes. The enforcement point
  checks and forwards the canonical form, and repository names the forge might rewrite (a `.git`
  suffix, look-alike characters) are refused rather than resolved.
- **Evidence deletion.** Signed records alone do not reveal a missing record. Records are now
  hash-linked, so a deletion or reordering breaks the chain. A signed checkpoint over the record count
  and latest hash detects records removed from an export by anyone without the evidence key. Rolling
  back to an earlier checkpoint, or re-signing with that key, is detected only against a head anchored
  elsewhere.

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
