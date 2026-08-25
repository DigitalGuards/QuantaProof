#!/usr/bin/env bash
# Fast-path QRL 2.0 execution node for contract tests: gqrl developer mode.
#
# Chain id 1337, one pre-funded unlocked developer account (qrl_accounts), a
# simulated beacon that seals a block as soon as a transaction is pending, and
# a 20,000,000 block gas limit (the consensus cap). Kurtosis stays the release
# gate; this node is for iteration.
#
# The data directory persists between runs, so the developer account and the
# deployed contracts survive a restart. The --dev.gaslimit value only applies
# when the directory is created: delete it to reset the chain.
#
# --ipcdisable is mandatory: gqrl otherwise fails with
# "listen unix ...gqrl.ipc: bind: invalid argument" when the datadir path is long.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
gqrl_bin="${GQRL_BIN:-${repo_root}/../go-qrl-stark/build/bin/gqrl}"
datadir="${STARK_DEV_DATADIR:-${repo_root}/build/dev-node}"
port="${STARK_DEV_PORT:-8545}"
verbosity="${STARK_DEV_VERBOSITY:-3}"

if [[ ! -x "${gqrl_bin}" ]]; then
    echo "gqrl not found at ${gqrl_bin}" >&2
    echo "Build it with 'GOTOOLCHAIN=auto make gqrl' in the go-qrl-stark worktree or set GQRL_BIN." >&2
    exit 1
fi

mkdir -p "${datadir}"

echo "gqrl dev node: ${gqrl_bin}" >&2
echo "RPC: http://127.0.0.1:${port} (chain 1337), datadir: ${datadir}" >&2

exec "${gqrl_bin}" \
    --dev \
    --dev.period 0 \
    --dev.gaslimit 20000000 \
    --nodiscover \
    --ipcdisable \
    --http \
    --http.addr 127.0.0.1 \
    --http.port "${port}" \
    --http.api qrl,net,web3,debug \
    --http.vhosts localhost \
    --verbosity "${verbosity}" \
    --datadir "${datadir}"
