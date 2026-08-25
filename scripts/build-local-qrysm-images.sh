#!/usr/bin/env bash
# Build the pinned Qrysm beacon, validator and genesis-generator images for
# the QuantaStark Kurtosis composition (qrl2-stark namespace). Adapted from
# the QNS builder; same source pins.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
dockerfile="${repo_root}/docker/qrysm/Dockerfile"

qrysm_repository="${QRYSM_REPOSITORY:-https://github.com/cyyber/qrysm.git}"
qrysm_commit="${QRYSM_COMMIT:-b53fd7c488f3f0d1d4163b270afac1749eed954b}"
generator_repository="${QRL_GENESIS_GENERATOR_REPOSITORY:-https://github.com/theQRL/qrl-genesis-generator.git}"
generator_commit="${QRL_GENESIS_GENERATOR_COMMIT:-6a11fbcee762af14d188507f071d08ac5782fa69}"

beacon_image="qrl2-stark/qrysm:beacon-chain-64"
validator_image="qrl2-stark/qrysm:validator-64"
generator_image="qrl2-stark/qrysm:qrl-genesis-generator-64"

command -v docker >/dev/null

common_args=(
    --file "${dockerfile}"
    --build-arg "QRYSM_REPOSITORY=${qrysm_repository}"
    --build-arg "QRYSM_COMMIT=${qrysm_commit}"
    --label "org.opencontainers.image.source=${qrysm_repository}"
    --label "org.opencontainers.image.revision=${qrysm_commit}"
)

if [[ -n "${STARK_DOCKER_CGROUP_PARENT:-}" ]]; then
    common_args+=(--cgroup-parent "${STARK_DOCKER_CGROUP_PARENT}")
fi

docker build \
    "${common_args[@]}" \
    --target beacon-chain \
    --tag "${beacon_image}" \
    "${repo_root}"

docker build \
    "${common_args[@]}" \
    --target validator \
    --tag "${validator_image}" \
    "${repo_root}"

generator_args=(
    --build-arg "QRYSM_GIT_REPO=${qrysm_repository}"
    --build-arg "QRYSM_GIT_REF=${qrysm_commit}"
    --label "org.opencontainers.image.source=${generator_repository}"
    --label "org.opencontainers.image.revision=${generator_commit}"
    --tag "${generator_image}"
)

if [[ -n "${STARK_DOCKER_CGROUP_PARENT:-}" ]]; then
    generator_args+=(--cgroup-parent "${STARK_DOCKER_CGROUP_PARENT}")
fi

docker build \
    "${generator_args[@]}" \
    "${generator_repository}#${generator_commit}"

docker run --rm "${beacon_image}" --version
docker run --rm "${validator_image}" --version
docker run --rm --entrypoint /usr/local/bin/qrysmctl "${generator_image}" --help >/dev/null
docker run --rm --entrypoint /usr/local/bin/deposit "${generator_image}" --help >/dev/null

echo "Built ${beacon_image}"
echo "Built ${validator_image}"
echo "Built ${generator_image}"
