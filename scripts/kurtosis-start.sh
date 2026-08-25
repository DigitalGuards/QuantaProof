#!/usr/bin/env bash
# Start (or reuse) the QuantaProof Kurtosis composition: enclave qrl2-stark,
# chain 3151909, execution RPC on http://127.0.0.1:32102, images in the
# qrl2-stark namespace. Coexists with the QNS composition (qrl2-qns, chain
# 3151908, ports 32000+). Adapted from the QNS driver (GPL-3.0).
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
package_dir="${QRL_PACKAGE_DIR:-${repo_root}/../qrl-package}"
package_manifest="${package_dir}/kurtosis.yml"
node_dir="${GO_QRL_DIR:-${repo_root}/../go-qrl-stark}"
enclave="${KURTOSIS_ENCLAVE:-qrl2-stark}"
args_file="${repo_root}/config/kurtosis-stark.yaml"
local_config="${repo_root}/config/local-stark.json"
example_config="${repo_root}/config/local-stark.example.json"
rpc_url="http://127.0.0.1:32102"
chain_id="3151909"
node_image="qrl2-stark/go-qrl:stark"
qrysm_commit="${QRYSM_COMMIT:-b53fd7c488f3f0d1d4163b270afac1749eed954b}"
generator_commit="${QRL_GENESIS_GENERATOR_COMMIT:-6a11fbcee762af14d188507f071d08ac5782fa69}"
beacon_image="qrl2-stark/qrysm:beacon-chain-64"
validator_image="qrl2-stark/qrysm:validator-64"
generator_image="qrl2-stark/qrysm:qrl-genesis-generator-64"
force_rebuild="${STARK_FORCE_REBUILD:-0}"
allow_wildcard_bind="${STARK_ALLOW_WILDCARD_BIND:-0}"

command -v docker >/dev/null
command -v git >/dev/null
command -v kurtosis >/dev/null

case "${force_rebuild}" in
    0|1) ;;
    *)
        echo "STARK_FORCE_REBUILD must be 0 or 1" >&2
        exit 1
        ;;
esac

case "${allow_wildcard_bind}" in
    0|1) ;;
    *)
        echo "STARK_ALLOW_WILDCARD_BIND must be 0 or 1" >&2
        exit 1
        ;;
esac

if ! docker info >/dev/null 2>&1; then
    echo "Docker is not running. Start the Docker daemon and retry." >&2
    exit 1
fi

if [[ ! -f "${package_manifest}" ]]; then
    echo "QRL Kurtosis package not found at ${package_dir}" >&2
    exit 1
fi

if [[ ! -f "${node_dir}/Dockerfile" ]]; then
    echo "go-qrl checkout not found at ${node_dir} (expected the go-qrl-stark worktree)" >&2
    exit 1
fi

node_revision="$(git -C "${node_dir}" rev-parse HEAD)"
node_source_state="clean"
if [[ -n "$(git -C "${node_dir}" status --porcelain=v1 --untracked-files=all)" ]]; then
    node_source_state="dirty"
fi

image_label() {
    local image="$1"
    local label="$2"
    docker image inspect "${image}" \
        --format "{{ index .Config.Labels \"${label}\" }}" 2>/dev/null || true
}

image_id() {
    docker image inspect "$1" --format '{{.Id}}' 2>/dev/null || true
}

node_image_is_current() {
    [[ "$(image_label "${node_image}" org.opencontainers.image.revision)" == "${node_revision}" ]] &&
        [[ "$(image_label "${node_image}" org.opencontainers.image.source-state)" == "clean" ]] &&
        [[ "${node_source_state}" == "clean" ]]
}

qrysm_image_is_current() {
    local image="$1"
    local revision="$2"
    [[ "$(image_label "${image}" org.opencontainers.image.revision)" == "${revision}" ]]
}

ensure_node_image() {
    if [[ "${node_source_state}" == "dirty" ]]; then
        echo "go-qrl-stark has local changes. Commit or clean the intended source before starting a reusable enclave." >&2
        exit 1
    fi
    if [[ "${force_rebuild}" == "1" ]] || ! node_image_is_current; then
        echo "Building go-qrl image for ${node_revision}." >&2
        "${repo_root}/scripts/build-local-node-image.sh"
    fi
}

ensure_qrysm_images() {
    if [[ "${force_rebuild}" == "1" ]] ||
        ! qrysm_image_is_current "${beacon_image}" "${qrysm_commit}" ||
        ! qrysm_image_is_current "${validator_image}" "${qrysm_commit}" ||
        ! qrysm_image_is_current "${generator_image}" "${generator_commit}"; then
        "${repo_root}/scripts/build-local-qrysm-images.sh"
    fi
}

is_wildcard_ip() {
    [[ -z "$1" || "$1" == "0.0.0.0" || "$1" == "::" ]]
}

probe_default_bind_ips() {
    local probe_name="stark-bind-probe-$$"
    local probe_network="stark-bind-probe-net-$$"
    local probe_container
    local bind_ips

    if ! docker network create --driver bridge "${probe_network}" >/dev/null; then
        return 1
    fi

    if ! probe_container="$(docker run --detach --rm \
        --name "${probe_name}" \
        --network "${probe_network}" \
        --entrypoint /bin/sh \
        --publish 8545/tcp \
        "${node_image}" \
        -c 'sleep 30')"; then
        docker network rm "${probe_network}" >/dev/null 2>&1 || true
        return 1
    fi

    if ! bind_ips="$(docker inspect "${probe_container}" \
        --format '{{range $port, $bindings := .NetworkSettings.Ports}}{{range $bindings}}{{println .HostIp}}{{end}}{{end}}')"; then
        docker rm --force "${probe_container}" >/dev/null 2>&1 || true
        docker network rm "${probe_network}" >/dev/null 2>&1 || true
        return 1
    fi

    docker rm --force "${probe_container}" >/dev/null
    docker network rm "${probe_network}" >/dev/null
    printf '%s\n' "${bind_ips}"
}

require_safe_default_bind() {
    local bind_ips
    local bind_ip

    if [[ "${allow_wildcard_bind}" == "1" ]]; then
        echo "WARNING: STARK_ALLOW_WILDCARD_BIND=1 permits Docker to publish QRL service ports on non-loopback interfaces." >&2
        return
    fi

    if ! bind_ips="$(probe_default_bind_ips)" || [[ -z "${bind_ips}" ]]; then
        echo "Could not prove Docker's default published-port bind address. Refusing to start." >&2
        echo "Configure Docker for loopback publication or set STARK_ALLOW_WILDCARD_BIND=1 after applying host-level access controls." >&2
        exit 1
    fi

    while IFS= read -r bind_ip; do
        if is_wildcard_ip "${bind_ip}"; then
            echo "Docker publishes unspecified ports on all host interfaces (${bind_ip:-unspecified}). Refusing to start." >&2
            echo "The qrl-package nat_exit_ip value controls P2P advertisement and does not bind host ports." >&2
            echo "Configure Docker for loopback publication or set STARK_ALLOW_WILDCARD_BIND=1 after applying host-level access controls." >&2
            exit 1
        fi
    done <<< "${bind_ips}"
}

service_container_id() {
    local service="$1"
    docker ps \
        --filter "label=kurtosis_enclave_name=${enclave}" \
        --filter "label=kurtosis_service_name=${service}" \
        --format '{{.ID}}' | head -n 1
}

verify_running_service_image() {
    local service="$1"
    local expected_image="$2"
    local container_id
    local running_image_id
    local expected_image_id

    container_id="$(service_container_id "${service}")"
    if [[ -z "${container_id}" ]]; then
        echo "Running container not found for Kurtosis service ${service}" >&2
        return 1
    fi

    running_image_id="$(docker inspect "${container_id}" --format '{{.Image}}')"
    expected_image_id="$(image_id "${expected_image}")"
    if [[ -z "${expected_image_id}" || "${running_image_id}" != "${expected_image_id}" ]]; then
        echo "Kurtosis service ${service} is not using the current local image ${expected_image}" >&2
        return 1
    fi
}

verify_running_enclave_provenance() {
    if [[ "${node_source_state}" != "clean" ]]; then
        echo "go-qrl-stark has local changes, so a running enclave cannot be matched to the current source." >&2
        return 1
    fi
    if ! node_image_is_current; then
        echo "Local go-qrl image does not match clean source commit ${node_revision}." >&2
        return 1
    fi
    if ! qrysm_image_is_current "${beacon_image}" "${qrysm_commit}" ||
        ! qrysm_image_is_current "${validator_image}" "${qrysm_commit}" ||
        ! qrysm_image_is_current "${generator_image}" "${generator_commit}"; then
        echo "Local Qrysm images do not match the pinned source revisions." >&2
        return 1
    fi

    verify_running_service_image "el-1-gqrl-qrysm" "${node_image}"
    verify_running_service_image "cl-1-qrysm-gqrl" "${beacon_image}"
    verify_running_service_image "vc-1-gqrl-qrysm" "${validator_image}"
}

verify_running_enclave_bindings() {
    local container_id
    local bind_ips
    local bind_ip

    if [[ "${allow_wildcard_bind}" == "1" ]]; then
        echo "WARNING: wildcard host publication was explicitly acknowledged." >&2
        return
    fi

    container_id="$(service_container_id "el-1-gqrl-qrysm")"
    if [[ -z "${container_id}" ]]; then
        echo "Execution service container not found for bind verification." >&2
        return 1
    fi
    bind_ips="$(docker inspect "${container_id}" \
        --format '{{range $port, $bindings := .NetworkSettings.Ports}}{{range $bindings}}{{println .HostIp}}{{end}}{{end}}')"
    if [[ -z "${bind_ips}" ]]; then
        echo "Execution service has no inspectable host port bindings." >&2
        return 1
    fi

    while IFS= read -r bind_ip; do
        if is_wildcard_ip "${bind_ip}"; then
            echo "Execution service is published on all host interfaces (${bind_ip:-unspecified})." >&2
            return 1
        fi
    done <<< "${bind_ips}"
}

finish_start() {
    node "${repo_root}/scripts/wait-for-rpc.js" "${rpc_url}" "${chain_id}"

    if [[ ! -f "${local_config}" ]]; then
        cp "${example_config}" "${local_config}"
    fi

    echo "Enclave: ${enclave}"
    echo "Execution RPC client URL: ${rpc_url} (chain ${chain_id})"
    echo "Config: ${local_config}"
    kurtosis enclave inspect "${enclave}"
}

enclave_inspect=""
if enclave_inspect="$(kurtosis enclave inspect "${enclave}" 2>/dev/null)"; then
    enclave_status="$(sed -n 's/^Status:[[:space:]]*//p' <<< "${enclave_inspect}")"
    if [[ "${enclave_status}" != "RUNNING" ]]; then
        echo "Enclave ${enclave} exists with status ${enclave_status:-unknown}." >&2
        echo "Kurtosis cannot resume a stopped enclave. Remove it deliberately or choose a new KURTOSIS_ENCLAVE name." >&2
        exit 1
    fi
    if [[ "${force_rebuild}" == "1" ]]; then
        echo "STARK_FORCE_REBUILD=1 cannot replace images in a running enclave. Recreate the enclave deliberately." >&2
        exit 1
    fi
    verify_running_enclave_provenance
    verify_running_enclave_bindings
    finish_start
    exit 0
fi

ensure_node_image
require_safe_default_bind
ensure_qrysm_images

kurtosis run --enclave "${enclave}" "${package_manifest}" --args-file "${args_file}"

if ! verify_running_enclave_provenance || ! verify_running_enclave_bindings; then
    echo "The new enclave failed image or bind verification and will be stopped." >&2
    kurtosis enclave stop "${enclave}" || true
    exit 1
fi

finish_start
