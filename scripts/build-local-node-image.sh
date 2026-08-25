#!/usr/bin/env bash
# Build the go-qrl execution client image for the QuantaStark Kurtosis
# composition from the go-qrl-stark worktree. Adapted from the QNS builder.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
node_dir="${GO_QRL_DIR:-${repo_root}/../go-qrl-stark}"
image="qrl2-stark/go-qrl:stark"

command -v docker >/dev/null
command -v git >/dev/null

if [[ ! -f "${node_dir}/Dockerfile" ]]; then
    echo "go-qrl checkout not found at ${node_dir} (expected the go-qrl-stark worktree)" >&2
    exit 1
fi

if ! grep -q "type shake256hash struct" "${node_dir}/core/vm/contracts.go"; then
    echo "go-qrl checkout does not contain the SHAKE256 precompile" >&2
    exit 1
fi

if ! grep -q "type mldsa87Verify struct" "${node_dir}/core/vm/contracts.go"; then
    echo "go-qrl checkout does not contain the ML-DSA-87 precompile" >&2
    exit 1
fi

node_revision="$(git -C "${node_dir}" rev-parse HEAD)"
node_source_state="clean"
node_fingerprint="${node_revision}"
if [[ -n "$(git -C "${node_dir}" status --porcelain=v1 --untracked-files=all)" ]]; then
    node_source_state="dirty"
    node_fingerprint="${node_revision}-dirty"
fi

build_args=(
    --tag "${image}"
    --build-arg "COMMIT=${node_fingerprint}"
    --label "org.opencontainers.image.revision=${node_revision}"
    --label "org.opencontainers.image.source-state=${node_source_state}"
)
if [[ -n "${STARK_DOCKER_CGROUP_PARENT:-}" ]]; then
    build_args+=(--cgroup-parent "${STARK_DOCKER_CGROUP_PARENT}")
fi

docker build "${build_args[@]}" "${node_dir}"
echo "Built ${image} from go-qrl ${node_fingerprint}"
