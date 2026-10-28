#!/usr/bin/env bash
# Applies a new release of the uAgent portal to an existing installation, and rolls it back if the new
# version does not come up. Called by the portal's Danger Zone through sudo, and safe to run by hand.
#
# Usage (as root, on the portal server):
#   uagent-maintenance status
#   uagent-maintenance fetch                 # bring the release branch down, print the target commit
#   uagent-maintenance verify <commit>       # check the target before anything is changed
#   uagent-maintenance apply  <commit>       # apply, restart, health-check, roll back on failure
#   uagent-maintenance rollback              # return to the commit recorded by the last apply
#
# What this never touches:
#   * /etc/uagent/portal.env    - secrets and configuration
#   * /etc/uagent/tls           - the certificate, its key and the private CA
#   * /var/lib/uagent           - agent records, accounts, the audit log and backups
# Only the code checkout and its npm packages are replaced, so a customer's configuration and
# operational data survive an update. The portal takes its own verified backup before calling this.
set -euo pipefail

INSTALL_DIR="${UAGENT_INSTALL_DIR:-/opt/uagent}"
STATE_DIR="${UAGENT_STATE_DIR:-/var/lib/uagent}"
ENV_FILE="${UAGENT_ENV_FILE:-/etc/uagent/portal.env}"
SERVICE_NAME="${UAGENT_SERVICE:-uagent-portal}"
BRANCH="${UAGENT_BRANCH:-main}"
# In a root-owned directory: the service account must not be able to point root at another file.
ROLLBACK_FILE="${UAGENT_RELEASE_RECORD:-/etc/uagent/last-release.json}"
HEALTH_TIMEOUT="${UAGENT_HEALTH_TIMEOUT:-60}"

log() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# One scratch directory for the whole run, removed however the script ends.
WORK=""
cleanup() { [ -n "$WORK" ] && rm -rf "$WORK"; return 0; }
trap cleanup EXIT

require_root() {
  [ "$(id -u)" -eq 0 ] || die "Run this as root: sudo $(basename "$0") $*"
}
require_checkout() {
  [ -d "${INSTALL_DIR}/.git" ] || die "${INSTALL_DIR} is not a git checkout, so this installation cannot be updated this way. Update it the way it was installed."
}

# The checkout belongs to the service account, so git runs as that account with hooks and fsmonitor
# disabled: nothing the account can write in .git is ever executed as root.
if [ "$(id -u)" -eq 0 ]; then
  AS_SERVICE=(runuser -u uagent -- env HOME="$STATE_DIR")
else
  AS_SERVICE=()
fi
GIT=("${AS_SERVICE[@]}" git -c core.hooksPath=/dev/null -c core.fsmonitor=false -c safe.directory="$INSTALL_DIR" -C "$INSTALL_DIR")

# Records how an apply or rollback ended, replacing whatever is there (never following a link).
record_release() {
  local previous="$1" target="$2" outcome="$3" tmp
  tmp="$(mktemp)"
  printf '{"previous":"%s","target":"%s","outcome":"%s","utc":"%s"}\n' \
    "$previous" "$target" "$outcome" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$tmp"
  rm -f "$ROLLBACK_FILE"
  install -o root -g root -m 0644 "$tmp" "$ROLLBACK_FILE"
  rm -f "$tmp"
}

# Restarting the portal closes the caller's end of our output. Everything after that goes to the journal,
# so a closed pipe cannot stop the health check or the rollback halfway.
to_journal() {
  trap '' PIPE
  if command -v logger >/dev/null 2>&1; then
    exec > >(logger -t uagent-maintenance) 2>&1
  else
    exec >/dev/null 2>&1
  fi
}

# A restart of the portal ends every process in its control group, including this one when the portal
# started it. Applying and rolling back therefore run in their own transient unit, so the health check
# and the automatic rollback still happen after the restart. Output stays visible to the caller.
detach_from_portal() {
  if [ -z "${UAGENT_DETACHED:-}" ] && command -v systemd-run >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    exec systemd-run --quiet --collect --wait --pipe --unit="uagent-update-$(date +%s)" \
      --setenv=UAGENT_DETACHED=1 -- "$0" "$@"
  fi
}

# A commit is the only accepted target, so a branch name or a path can never be substituted for one.
require_commit() {
  local ref="${1:-}"
  [ -n "$ref" ] || die "Name the commit to use. Run \"fetch\" first; it prints target=<commit>."
  [[ "$ref" =~ ^[0-9a-f]{7,40}$ ]] || die "\"${ref}\" is not a commit id."
  "${GIT[@]}" cat-file -e "${ref}^{commit}" 2>/dev/null || die "Commit ${ref} is not in this checkout. Run \"fetch\" first."
  "${GIT[@]}" rev-parse --verify --quiet "${ref}^{commit}"
}

current_commit() { "${GIT[@]}" rev-parse HEAD; }

# npm is installed under /usr/local/bin by the installer; a plain PATH lookup covers other layouts.
npm_bin() {
  if [ -x /usr/local/bin/npm ]; then echo /usr/local/bin/npm; else command -v npm || die "npm is not installed."; fi
}
node_bin() {
  if [ -x /usr/local/bin/node ]; then echo /usr/local/bin/node; else command -v node || die "node is not installed."; fi
}

health_port() {
  local port=""
  [ -f "$ENV_FILE" ] && port="$(sed -n 's/^PORTAL_HTTP_PORT=//p' "$ENV_FILE" | tail -1)"
  echo "${port:-80}"
}

wait_healthy() {
  local port deadline
  port="$(health_port)"
  deadline=$(( $(date +%s) + HEALTH_TIMEOUT ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if curl -fsS --max-time 3 "http://127.0.0.1:${port}/healthz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  return 1
}

install_packages() {
  local dir="${INSTALL_DIR}/portal"
  log "Installing portal packages"
  ( cd "$dir" && runuser -u uagent -- env HOME="$STATE_DIR" PATH="/usr/local/bin:${PATH}" "$(npm_bin)" ci --omit=dev ) \
    || die "The portal packages could not be installed. The release was not applied."
}

# This root-owned copy is never replaced from the checkout, which the service account can write. A new
# version of the helper is installed by the installer (install-centos.sh), run by an administrator.

cmd_status() {
  local head behind
  head="$(current_commit)"
  log "install=${INSTALL_DIR}"
  log "service=${SERVICE_NAME} ($(systemctl is-active "$SERVICE_NAME" 2>/dev/null || echo unknown))"
  log "branch=${BRANCH}"
  log "head=${head}"
  log "version=$("$(node_bin)" -p "require('${INSTALL_DIR}/portal/package.json').version" 2>/dev/null || echo unknown)"
  if "${GIT[@]}" rev-parse --verify --quiet "origin/${BRANCH}" >/dev/null; then
    behind="$("${GIT[@]}" rev-list --count "HEAD..origin/${BRANCH}")"
    log "available=$("${GIT[@]}" rev-parse "origin/${BRANCH}")"
    log "behind=${behind}"
  fi
  [ -f "$ROLLBACK_FILE" ] && log "rollback=$(sed -n 's/.*"previous":"\([0-9a-f]*\)".*/\1/p' "$ROLLBACK_FILE")"
  log "Status read; nothing was changed."
}

cmd_fetch() {
  log "Fetching ${BRANCH} from origin"
  "${GIT[@]}" fetch --prune origin "$BRANCH" || die "The release could not be fetched. Check this server's access to the git remote."
  local target head behind
  target="$("${GIT[@]}" rev-parse "origin/${BRANCH}")"
  head="$(current_commit)"
  behind="$("${GIT[@]}" rev-list --count "HEAD..origin/${BRANCH}")"
  log "target=${target}"
  if [ "$target" = "$head" ]; then
    log "Already on the latest release (${head:0:12}); applying it would change nothing."
  else
    log "Fetched ${behind} new commit(s). Target ${target:0:12}: $("${GIT[@]}" log -1 --format=%s "$target" | cut -c1-120)"
  fi
}

cmd_verify() {
  local target head dirty
  target="$(require_commit "${1:-}")"
  head="$(current_commit)"

  # Local edits in the checkout would be overwritten by a checkout, so the update stops instead.
  dirty="$("${GIT[@]}" status --porcelain -- portal uAgent.Agent uAgent.Shared scripts | head -5)"
  if [ -n "$dirty" ]; then
    die "The installation has local modifications that an update would overwrite:
${dirty}
Commit, stash or remove them, then run the update again."
  fi

  # The target must contain the portal, so a wrong commit cannot leave the service without its code.
  for required in portal/server.js portal/package.json portal/package-lock.json; do
    "${GIT[@]}" cat-file -e "${target}:${required}" 2>/dev/null || die "Commit ${target:0:12} does not contain ${required}; it is not a portal release."
  done

  # Check that the release really parses, reading the files from the target commit rather than from the
  # working tree, so a broken release is refused before the running version is replaced.
  # Unpacked and parsed as the service account: the archive's content is the account's to control.
  WORK="$(mktemp -d)"
  [ "$(id -u)" -eq 0 ] && chown uagent:uagent "$WORK"
  "${GIT[@]}" archive "$target" portal | "${AS_SERVICE[@]}" tar -x -C "$WORK"
  if ! ( cd "${WORK}/portal" && find . -name '*.js' -not -path './node_modules/*' -print0 | "${AS_SERVICE[@]}" xargs -0 -n1 "$(node_bin)" --check ) >"${WORK}/parse.log" 2>&1; then
    die "The release does not parse as valid JavaScript, so it was not applied: $(grep -m1 -E 'Error|error' "${WORK}/parse.log" || head -1 "${WORK}/parse.log")"
  fi

  log "from=${head}"
  log "to=${target}"
  log "version=$("${GIT[@]}" show "${target}:portal/package.json" | "$(node_bin)" -p 'JSON.parse(require("fs").readFileSync(0,"utf8")).version')"
  log "Release ${target:0:12} is complete and parses. Configuration, certificates and agent records are not part of it."
}

cmd_apply() {
  local target previous
  target="$(require_commit "${1:-}")"
  cmd_verify "$target" >/dev/null
  previous="$(current_commit)"

  install -d -m 0750 -o uagent -g uagent "$STATE_DIR"
  record_release "$previous" "$target" "applying"

  log "Applying ${target:0:12} (from ${previous:0:12})"
  "${GIT[@]}" checkout --quiet --detach "$target" || die "The checkout failed; nothing was changed."
  install_packages

  log "Restarting ${SERVICE_NAME}. Progress from here on is in: journalctl -t uagent-maintenance"
  to_journal
  systemctl restart "$SERVICE_NAME" || true
  if wait_healthy; then
    record_release "$previous" "$target" "applied"
    log "applied=${target}"
    log "The new version is running and answering /healthz."
    return 0
  fi

  # The new version did not come up, so the previous one goes back immediately. A failed update must not
  # leave the portal down, and the operator is told plainly which version is running.
  log "The new version did not answer /healthz within ${HEALTH_TIMEOUT}s. Restoring ${previous:0:12}."
  "${GIT[@]}" checkout --quiet --detach "$previous"
  ( cd "${INSTALL_DIR}/portal" && runuser -u uagent -- env HOME="$STATE_DIR" PATH="/usr/local/bin:${PATH}" "$(npm_bin)" ci --omit=dev ) || true
  record_release "$previous" "$target" "rolled-back"
  systemctl restart "$SERVICE_NAME" || true
  if wait_healthy; then
    log "rolled back to ${previous}"
    die "The release was rolled back. The portal is running the previous version (${previous:0:12}). Check: journalctl -u ${SERVICE_NAME} -n 80 --no-pager"
  fi
  log "rolled back to ${previous}"
  die "The release was rolled back, but the portal is still not answering. Check: journalctl -u ${SERVICE_NAME} -n 120 --no-pager"
}

cmd_rollback() {
  [ -f "$ROLLBACK_FILE" ] || die "No previous release is recorded, so there is nothing to roll back to."
  local previous
  previous="$(sed -n 's/.*"previous":"\([0-9a-f]*\)".*/\1/p' "$ROLLBACK_FILE")"
  [ -n "$previous" ] || die "The recorded rollback point in ${ROLLBACK_FILE} is unreadable."
  previous="$(require_commit "$previous")"
  log "Returning to ${previous:0:12}"
  local current
  current="$(current_commit)"
  "${GIT[@]}" checkout --quiet --detach "$previous"
  install_packages
  record_release "$previous" "$current" "rolled-back"
  to_journal
  systemctl restart "$SERVICE_NAME" || true
  wait_healthy || die "The portal did not answer /healthz after rolling back. Check: journalctl -u ${SERVICE_NAME} -n 120 --no-pager"
  log "rolled back to ${previous}"
}

# Earlier versions ran git as root, which can leave root-owned files git can no longer replace as the
# service account. -P: symbolic links are changed themselves, never followed.
own_checkout() {
  chown -R -P uagent:uagent "$INSTALL_DIR"
}

case "${1:-}" in
  status) require_checkout; cmd_status ;;
  fetch) require_root fetch; require_checkout; own_checkout; cmd_fetch ;;
  verify) require_root verify "${2:-}"; require_checkout; own_checkout; cmd_verify "${2:-}" ;;
  apply) require_root apply "${2:-}"; require_checkout; detach_from_portal "$@"; own_checkout; cmd_apply "${2:-}" ;;
  rollback) require_root rollback; require_checkout; detach_from_portal "$@"; own_checkout; cmd_rollback ;;
  ""|-h|--help|help) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//' ;;
  *) die "Unknown command \"$1\". Use status, fetch, verify, apply or rollback." ;;
esac
