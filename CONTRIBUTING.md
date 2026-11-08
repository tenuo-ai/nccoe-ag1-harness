# Contributing

Issues and pull requests are welcome: new adapters, results for an implementation, bugs in a step,
and clearer documentation. For a security issue, follow [SECURITY.md](SECURITY.md) instead of
opening an issue.

## Add your implementation

An implementation joins through an adapter: a Python class that issues, delegates, proves, and
verifies grants in that implementation's own format. The harness supplies everything else.

### 1. Write the adapter

[ADAPTERS.md](ADAPTERS.md) lists every method, what each step uses it for, and the architecture
declaration (`delegation_mode`, `verification_mode`, `artifact_mode`). The interface is defined in
`src/ag1/adapters/base.py`. Two adapters are included to read from:

- `src/ag1/adapters/reference.py`: short, with no dependency beyond `cryptography`. It is an example
  of the contract, not an implementation to deploy.
- `src/ag1/adapters/tenuo_adapter.py`: a complete adapter, including remote operation for Compose.

The adapter can live in its own package. Register it under the `ag1.adapters` entry point group:

```toml
[project.entry-points."ag1.adapters"]
myimpl = "mypackage.my_adapter:MyAdapter"
```

Then `--adapter myimpl` (or `AG1_ADAPTER=myimpl`) loads it. A `module:Class` path also works without
packaging.

### 2. Run it

In-memory, with the mock SCM:

```bash
python -m ag1 --adapter myimpl --out results-myimpl
AG1_ADAPTER=myimpl pytest -q
```

Against a real Forgejo (needs Docker):

```bash
eval "$(scripts/forgejo-up.sh)"
AG1_ADAPTER=myimpl pytest -q tests/test_forgejo.py
python -m ag1 --adapter myimpl --service forgejo --out results-myimpl-forgejo
```

As separate services. Compose needs the remote-operation methods in
[ADAPTERS.md](ADAPTERS.md#remote-operation-compose-mode). Check them over HTTP on localhost first,
then set `AG1_ADAPTER` in `compose.yaml`, add your package to the image, and run:

```bash
AG1_ADAPTER=myimpl pytest -q tests/test_compose_loopback.py
scripts/compose-up.sh
docker compose run --rm driver
```

[docs/running.md](docs/running.md) covers outputs and how to verify the evidence bundle.

### 3. Not-applicable checks

Some checks depend on a capability an architecture may not have. They are reported as
*not applicable*, with the reason, and are never counted as met:

- Without `forge_link`, the checks that present a self-signed or spliced link to the enforcement
  point (AG-1.4, AG-1.9) are not applicable.
- A `verification_mode` other than `offline_chain` makes the offline-verification checks not
  applicable.
- An `opaque` `artifact_mode` makes the checks that mutate signed content not applicable.

The report counts these checks. A step whose checks are all not applicable is not met.

### 4. Steps are not changed to fit a design

The steps test requirements, and they are the same for every implementation. A pull request that
loosens a check so that one implementation passes will not be merged. If a check assumes one
architecture where the requirement does not, open an issue that shows the requirement and how
another design meets it. The fix is then a neutral check that every adapter runs, or a declared
mode reported as not applicable.

### 5. Add your results

Open a pull request that adds a row to the results table in the README with the implementation,
its version, the harness commit, and a link to a CI run or a results directory. Note which mode it
ran in.

## Changes to the harness

- Keep `pytest -q` passing, both with and without the `tenuo` extra installed.
- A new check should fail against a weakened adapter. `tests/test_adversarial.py` and
  `tests/test_reference_adapter.py` show how: switch one defense off and assert the step notices.
- Dependencies are pinned with hashes. After changing `pyproject.toml`, regenerate the lock files
  as described in [docs/running.md](docs/running.md#dependencies).
