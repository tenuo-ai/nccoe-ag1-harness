"""Compose mode: each party and enforcement point as a separate service.

One image runs every role, chosen on the command line (`python -m ag1.compose ROLE`):

- `keyholder`: holds the private keys of one deployment's parties (the issuer, the
  approver, an agent, or the thief) and signs only inside its own container.
- `pep`: an AG-1 reference enforcement point in front of the services.
- `test-service`: checks out a branch with a read-only token and runs its pytest suite.
- `sink`: the staging deployment target, which records what it is asked to deploy.

The driver (`ag1 --mode compose`) runs the same steps against them over HTTP.
"""
