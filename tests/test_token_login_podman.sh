#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PODMAN_CONNECTION="${PODMAN_CONNECTION:-podman-machine-default}"
TEST_IMAGE="${TEST_IMAGE:-localhost/nordility-token-login-test:local}"
CONTEXT="${REPO_ROOT}/tests/containers/token-login"

podman --connection "${PODMAN_CONNECTION}" build \
  --tag "${TEST_IMAGE}" \
  --file "${CONTEXT}/Containerfile" \
  "${REPO_ROOT}"

podman --connection "${PODMAN_CONNECTION}" run --rm --network none "${TEST_IMAGE}"
