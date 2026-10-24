FROM python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70

# git for the compose test service, which checks out the branch it tests.
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

WORKDIR /ag1
COPY requirements-lock.txt pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir --require-hashes -r requirements-lock.txt \
    && pip install --no-cache-dir --no-deps --no-build-isolation .

ENTRYPOINT ["ag1"]
CMD ["--out", "/results"]
