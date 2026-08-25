#!/usr/bin/env bash
# Deploy site/ to a static webroot over SSH.
#
# Tars site/ (without README.md and tools/), streams it to the host, extracts
# it next to the webroot, sets the web server's ownership and swaps it into
# place: the current webroot becomes <webroot>.previous-<timestamp> and the
# new tree takes its name. Every host detail comes from the environment, so
# nothing about the target is written down here.
#
#   QUANTASTARK_DEPLOY_HOST      SSH host (required)
#   QUANTASTARK_DEPLOY_USER      SSH user (required)
#   QUANTASTARK_WEBROOT          target directory (default /var/www/quantastark)
#   QUANTASTARK_DEPLOY_SUDO      1 runs the remote commands through sudo -n
#   QUANTASTARK_OWNER            owner of the deployed tree (default www-data:www-data)
#   QUANTASTARK_SSH_OPTS         extra ssh options, for example "-p 2222"
#   QUANTASTARK_KEEP_PREVIOUS    .previous-* copies to keep (default 3)
#
# Usage: ./scripts/deploy-site.sh

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
site_dir="$repo_root/site"

fail() {
  echo "deploy-site: $*" >&2
  exit 1
}

[ -f "$site_dir/index.html" ] || fail "site/index.html is missing"
[ -n "${QUANTASTARK_DEPLOY_HOST:-}" ] || fail "QUANTASTARK_DEPLOY_HOST is not set"
[ -n "${QUANTASTARK_DEPLOY_USER:-}" ] || fail "QUANTASTARK_DEPLOY_USER is not set"

webroot="${QUANTASTARK_WEBROOT:-/var/www/quantastark}"
owner="${QUANTASTARK_OWNER:-www-data:www-data}"
keep="${QUANTASTARK_KEEP_PREVIOUS:-3}"
use_sudo="${QUANTASTARK_DEPLOY_SUDO:-0}"
ssh_bin="${QUANTASTARK_SSH_BIN:-ssh}"

case "$webroot" in
  /*/*) ;;
  *) fail "QUANTASTARK_WEBROOT must be an absolute path below the root directory" ;;
esac
case "$keep" in
  '' | *[!0-9]*) fail "QUANTASTARK_KEEP_PREVIOUS must be a whole number" ;;
esac
command -v base64 >/dev/null || fail "base64 is required locally"

# shellcheck disable=SC2206
ssh_opts=(${QUANTASTARK_SSH_OPTS:-})
target="$QUANTASTARK_DEPLOY_USER@$QUANTASTARK_DEPLOY_HOST"

# POSIX single-quoting for the remote positional parameters.
sq() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

# The remote script reads the tarball from stdin, so it travels in the command
# string (base64, decoded by the login shell) and its inputs travel as
# positional parameters; nothing is interpolated into the script text.
remote_script=$(
  cat <<'REMOTE'
set -euo pipefail
webroot=$1
owner=$2
keep=$3
use_sudo=$4
run() {
  if [ "$use_sudo" = 1 ]; then sudo -n "$@"; else "$@"; fi
}
parent=$(dirname "$webroot")
name=$(basename "$webroot")
stamp=$(date -u +%Y%m%dT%H%M%SZ)
incoming=$(run mktemp -d "$parent/.$name.incoming-XXXXXX")
run tar -xzf - -C "$incoming"
run chown -R "$owner" "$incoming"
run chmod 755 "$incoming"
previous=""
if [ -e "$webroot" ]; then
  previous="$webroot.previous-$stamp"
  n=1
  while [ -e "$previous" ]; do
    n=$((n + 1))
    previous="$webroot.previous-$stamp-$n"
  done
  # -T: a name collision fails; without it mv would nest one tree inside the other.
  run mv -T "$webroot" "$previous"
fi
run mv -T "$incoming" "$webroot"
echo "deployed: $webroot"
if [ -n "$previous" ]; then echo "previous: $previous"; fi
# Prune older copies beyond the newest $keep (the timestamp sorts them).
run find "$parent" -maxdepth 1 -name "$name.previous-*" -print | sort -r |
  tail -n +"$((keep + 1))" | while IFS= read -r old; do
  run rm -rf "$old"
  echo "pruned: $old"
done
run ls -la "$webroot"
REMOTE
)

encoded=$(printf '%s' "$remote_script" | base64 | tr -d '\n')
remote_command="bash -c \"\$(printf %s $encoded | base64 -d)\" deploy-site $(sq "$webroot") $(sq "$owner") $(sq "$keep") $(sq "$use_sudo")"

echo "deploy-site: shipping site/ to $target:$webroot"
tar -czf - -C "$site_dir" --exclude='./README.md' --exclude='./tools' . |
  "$ssh_bin" ${ssh_opts[@]+"${ssh_opts[@]}"} "$target" "$remote_command" ||
  fail "remote deployment failed"
