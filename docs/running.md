# Running AG-1

## Modes

| Mode | What runs | Use it to |
| :- | :- | :- |
| In-memory (default) | Agents, enforcement points, and a mock SCM in one process | Explore the scenario and develop an adapter |
| Forgejo (`--service forgejo`) | Real repository and pull-request operations; tests and deployment are recorded by the harness | Exercise normalization and enforcement against a forge API |
| Compose | Separate key holders and enforcement points, Forgejo, a pytest service, and a deployment sink | Exercise the HTTP boundaries and real test execution |

## Local run

```bash
python -m venv .venv
.venv/bin/pip install --require-hashes -r requirements-lock.txt
.venv/bin/pip install --no-deps --no-build-isolation -e .
.venv/bin/pytest -q
.venv/bin/python -m ag1 --out results    # prints the two verification anchors
.venv/bin/python -m ag1 --verify results --trusted-root <hex> --evidence-key <hex>
.venv/bin/python -m ag1 --adapter mypackage.my_adapter:MyAdapter --out results-myimpl
```

## Forgejo

Needs Docker and git:

```bash
eval "$(scripts/forgejo-up.sh)"    # starts Forgejo 16.0.6, sets AG1_FORGEJO_URL and AG1_FORGEJO_TOKEN
.venv/bin/pytest -q tests/test_forgejo.py
.venv/bin/python -m ag1 --service forgejo --out results-forgejo
```

The run deletes and recreates `acme/repo-a` and `acme/repo-b` on that instance, so point it only at
a throwaway forge.

## Compose

Needs Docker Compose:

```bash
scripts/compose-up.sh            # Forgejo, its two tokens as Docker secrets, then every service
GITHUB_SHA=$(git rev-parse HEAD) docker compose run --rm driver   # writes results-compose/ and prints the anchors
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

## Outputs

`results/results.md` uses the column layout of NCCoE's functional demonstration results (Demo ID,
Expected Outcome, Observed Outcome, Comments) and adds an explicit result column.
`results/results.json` has the same data. A run also exports:

- `evidence.json` (compose mode: `evidence/<enforcement point>.json`): the raw signed, hash-linked
  evidence records, authorization chains, trusted root, evidence public key, and terminal hash. Every
  allowed record's chain must re-verify; a denied record may carry an invalid chain, since that is
  why it was denied;
- `manifest.json`: the harness commit, the CI workflow run if there is one, platform, Python version,
  and installed package versions. The commit and run also appear at the top of `results.md`.

Evidence chains are checked at the signed time each record's authorization was checked, so later
grant expiry does not invalidate an authentic record. This audit check does not authorize new
execution.

## Verifying evidence

The evidence bundle can be checked after the original process has exited, against two anchors
the run prints: the trusted root and the evidence signing key. Take them from somewhere the
bundle's author cannot rewrite later, such as the CI log of the run or a key published by the
operator. `--verify` will not read them from the bundle: anyone able to edit the bundle could
re-sign every record with keys of their own and it would still be internally consistent. The
check shows the bundle matches its signed checkpoint. It does not show that the run itself was
honest, and it does not detect a rollback to an earlier checkpoint or re-signing with the evidence
key. Those need a head anchored elsewhere.

## Dependencies

`requirements-lock.txt` pins every package with its hashes, so pip refuses any file that differs
from the one tested. Regenerate it with
`uv pip compile requirements.in --generate-hashes --universal --python-version 3.10 -o requirements-lock.txt`.

## Container

```bash
docker build -t nccoe-ag1-harness .
docker run --rm -v "$PWD/results:/results" nccoe-ag1-harness    # prints the anchors
docker run --rm -v "$PWD/results:/results" nccoe-ag1-harness --verify /results \
  --trusted-root <hex> --evidence-key <hex>
```
