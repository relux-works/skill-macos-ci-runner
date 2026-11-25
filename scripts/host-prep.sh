#!/bin/bash
# shellcheck shell=bash
#
# host-prep.sh: prepare a Mac as an isolated self-hosted GitHub Actions runner host for iOS/macOS test jobs:
# a standard CI account on its own encrypted, quota-capped APFS volume, a root-owned toolchain, a pf egress guard
# with a dead-man switch, sshd and host-service hardening, and a root-verified runner install.
#
# Design and threat model: references/DESIGN.md. Exact owner commands (hash-pinned): references/RUNBOOK.md.
# Known macOS pitfalls and how this script handles them: references/PITFALLS.md.
# Every site-specific value comes from ci-runner.conf (examples/ci-runner.conf); below, CI_USER, VOL_NAME,
# SUPPORT and the like name those configured values.
#
# Modes (always bash, never zsh; root modes are started as
#   /usr/bin/sudo /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /bin/bash $SUPPORT/setup/host-prep.sh MODE):
#   preflight              Read-only checks. No root, no prompts, no writes.
#   preflight --ioc        Root, read-only: root-compromise indicator checks (I1-I5) and the full pf state.
#   host                   Root, interactive. Volume, account, Xcode, hooks, host services, then pf with a
#                          10-minute dead-man switch. Prompts for the $VOL_NAME passphrase and the $CI_USER password.
#   confirm-pf             Root. Run from a FRESH second SSH login within 10 minutes of host: keeps pf enabled.
#   harden-runner [--rebaseline]
#                          Root, after references/RUNBOOK.md with $CI_USER LOGGED OUT. Installs the runner and Tuist
#                          from root-verified downloads, generates the LaunchAgent, hardens the home, records the
#                          persistence baseline. The runner starts at the next $CI_USER login.
#   ci-session-agents      Root, $CI_USER logged in. Only disables third-party global LaunchAgents in $CI_USER's
#                          launchd domain; touches no file. Needed only if harden-runner could not do it.
#
# Contract:
#   - Idempotent and fail-closed: the first failed check stops the run; earlier changes stay, nothing is rolled back
#     (except the pf dead-man switch, which rolls back pf by design when the owner does not confirm).
#   - No root operation follows a path $CI_USER controls. host (re-runs) and harden-runner refuse while any
#     $CI_USER process or crontab exists. Every root write into a $CI_USER-controlled tree is staged in a
#     root-only directory and renamed into place; metadata changes use -h and are re-verified with lstat; a symlink
#     or wrong file type at a root-managed path stops the run as suspected tampering.
#   - Secrets are typed only into the prompts of diskutil, sysadminctl, dscl or passwd; never argv, env or the log.
#   - Stock macOS tools only (no Homebrew).

set -Eeuo pipefail
umask 022
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
export LC_ALL=C

# ---------------------------------------------------------------------------------------------------------------
# Deployment configuration (ci-runner.conf; see examples/ci-runner.conf). Changing a value is a design change.
# ---------------------------------------------------------------------------------------------------------------
# >>> config-loader (identical in host-prep.sh and qualify.sh; tests/run.sh checks it)
# Deployment configuration. Every site-specific value comes from ci-runner.conf: next to this script when it runs
# from a file (the root-owned setup directory on the host), or the file named by MACOS_CI_CONF for modes that run
# from stdin or from the admin workstation. Root modes accept only a root-owned file that no group or other user
# can write, in a directory with the same property. The file is parsed, never sourced: strict KEY=VALUE lines,
# known keys only, a small character set, and a per-key format check before anything else runs.
readonly CONF_KEYS="CI_USER CI_UID CI_GID CI_FULLNAME OWNER_USER OWNER_UID EXPECTED_MODEL VOL_NAME VOL_QUOTA_BYTES
 VOL_RESERVE_BYTES MIN_CONTAINER_FREE_AFTER_BYTES SUPPORT_ROOT LABEL_PREFIX PF_ANCHOR_NAME RUNNER_ORG RUNNER_GROUP
 RUNNER_NAME RUNNER_EXTRA_LABEL RUNNER_REPO RUNNER_VERSION RUNNER_SHA256 TUIST_VERSION TUIST_SHA256 TUIST_TEAM_ID
 STOCK_PF_CONF_SHA256 STOCK_PF_APPLE_SHA256 SIMULATOR_NAME ADMIN_SSH_ALIAS HOST_TAILNET_IP TAILNET_PEER_IP"
# Keys that may be empty; every other key is required.
readonly CONF_OPTIONAL=" EXPECTED_MODEL HOST_TAILNET_IP TAILNET_PEER_IP "
conf_die() { printf 'config: %s\n' "$*" >&2; exit 2; }
# conf_format <key>: the extended regular expression a value of <key> must match.
conf_format() {
  case "$1" in
    CI_USER|OWNER_USER) echo '^[a-z_][a-z0-9_-]{0,30}$' ;;
    CI_UID|CI_GID|OWNER_UID) echo '^[1-9][0-9]{2,4}$' ;;
    CI_FULLNAME|SIMULATOR_NAME) echo '^[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}$' ;;
    EXPECTED_MODEL) echo '^([A-Za-z]+[0-9]+,[0-9]+)?$' ;;
    VOL_NAME|PF_ANCHOR_NAME) echo '^[A-Za-z][A-Za-z0-9]{1,30}$' ;;
    VOL_QUOTA_BYTES|VOL_RESERVE_BYTES|MIN_CONTAINER_FREE_AFTER_BYTES) echo '^[1-9][0-9]{10,14}$' ;;
    SUPPORT_ROOT) echo '^/opt/[a-z0-9][a-z0-9._-]{0,40}$' ;;
    LABEL_PREFIX) echo '^[a-z0-9-]+(\.[a-z0-9-]+){2,4}$' ;;
    RUNNER_ORG) echo '^[A-Za-z0-9][A-Za-z0-9-]{0,38}$' ;;
    RUNNER_GROUP|RUNNER_NAME|RUNNER_EXTRA_LABEL) echo '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' ;;
    RUNNER_REPO) echo '^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$' ;;
    RUNNER_VERSION|TUIST_VERSION) echo '^[0-9]+\.[0-9]+\.[0-9]+$' ;;
    RUNNER_SHA256|TUIST_SHA256|STOCK_PF_CONF_SHA256|STOCK_PF_APPLE_SHA256) echo '^[0-9a-f]{64}$' ;;
    TUIST_TEAM_ID) echo '^[A-Z0-9]{10}$' ;;
    ADMIN_SSH_ALIAS) echo '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' ;;
    HOST_TAILNET_IP|TAILNET_PEER_IP) echo '^(((25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9]))?$' ;;
    *) return 1 ;;
  esac
}
# conf_trusted <file>: under root, the file, its directory and that directory's parent are root:wheel, not symlinks,
# and not writable by group or others. Unprivileged runs skip it: they cannot change anything a root run trusts.
conf_trusted() {
  local f=$1 d m
  [ "$(id -u)" = 0 ] || return 0
  d=$(dirname "$f")
  # The group and other digits may hold only r and x (0, 1, 4, 5): 2, 3, 6 and 7 carry a write bit.
  for m in "$f" "$d" "$(dirname "$d")"; do
    [ ! -L "$m" ] || conf_die "$m is a symlink"
    case "$(stat -f '%Su:%Sg %Mp%03Lp' "$m")" in
      root:wheel\ 0[0-7][0145][0145]) ;;
      *) conf_die "$m must be root:wheel and not group/other-writable, is $(stat -f '%Su:%Sg %Mp%03Lp' "$m")" ;;
    esac
  done
}
load_config() {
  local f=$1 line key val n=0 re seen=" "
  [ -f "$f" ] && [ ! -L "$f" ] || conf_die "$f is missing or not a regular file"
  conf_trusted "$f"
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    case "$line" in ''|'#'*) continue ;; esac
    case "$line" in *=*) ;; *) conf_die "line $n is not KEY=VALUE" ;; esac
    key=${line%%=*}; val=${line#*=}
    [[ $key =~ ^[A-Z][A-Z0-9_]*$ ]] || conf_die "line $n: '$key' is not a key name"
    case " $(echo $CONF_KEYS) " in *" $key "*) ;; *) conf_die "line $n: unknown key '$key'" ;; esac
    case "$seen" in *" $key "*) conf_die "line $n: '$key' is set twice" ;; esac
    seen="$seen$key "
    re=$(conf_format "$key") || conf_die "line $n: no format for '$key'"
    [[ $val =~ $re ]] || conf_die "line $n: $key='$val' does not match $re"
    printf -v "$key" '%s' "$val"
  done < "$f"
  for key in $CONF_KEYS; do
    case "$seen" in *" $key "*) continue ;; esac
    case "$CONF_OPTIONAL" in *" $key "*) printf -v "$key" '%s' ""; continue ;; esac
    conf_die "required key $key is missing"
  done
  [ "$CI_UID" -gt 500 ] && [ "$CI_GID" -gt 500 ] || conf_die "CI_UID and CI_GID must be above 500"
  [ "$CI_UID" != "$OWNER_UID" ] && [ "$CI_USER" != "$OWNER_USER" ] || conf_die "the CI account must differ from the owner"
  [ "$VOL_RESERVE_BYTES" -le "$VOL_QUOTA_BYTES" ] || conf_die "VOL_RESERVE_BYTES exceeds VOL_QUOTA_BYTES"
  # The job-started hook refuses jobs below 15 GiB free on the volume: anything under 32 GiB leaves no room.
  [ "$VOL_QUOTA_BYTES" -ge 34359738368 ] || conf_die "VOL_QUOTA_BYTES must be at least 34359738368 (32 GiB)"
}
conf_path() {
  local src=${BASH_SOURCE[0]:-}
  if [ "$(id -u)" != 0 ] && [ -n "${MACOS_CI_CONF:-}" ]; then echo "$MACOS_CI_CONF"; return; fi
  if [ -n "$src" ] && [ -f "$src" ]; then echo "$(cd "$(dirname "$src")" && pwd -P)/ci-runner.conf"; return; fi
  [ -n "${MACOS_CI_CONF:-}" ] || conf_die "running from stdin: set MACOS_CI_CONF to the config file"
  echo "$MACOS_CI_CONF"
}
# <<< config-loader

load_config "$(conf_path)"
# shellcheck disable=SC2034  # some configured values are used only by the other script or the docs
readonly CI_USER CI_UID CI_GID CI_FULLNAME OWNER_USER OWNER_UID EXPECTED_MODEL VOL_NAME SUPPORT_ROOT LABEL_PREFIX \
  PF_ANCHOR_NAME RUNNER_ORG RUNNER_GROUP RUNNER_NAME RUNNER_EXTRA_LABEL RUNNER_REPO RUNNER_VERSION TUIST_VERSION \
  TUIST_TEAM_ID SIMULATOR_NAME ADMIN_SSH_ALIAS
readonly VOL_MOUNT=/Volumes/$VOL_NAME
readonly VOL_QUOTA=$VOL_QUOTA_BYTES VOL_RESERVE=$VOL_RESERVE_BYTES MIN_CONTAINER_FREE_AFTER=$MIN_CONTAINER_FREE_AFTER_BYTES
readonly CI_HOME=$VOL_MOUNT/home/$CI_USER
readonly RUNNER_PARENT=$VOL_MOUNT/runner
readonly RUNNER_DIR=$VOL_MOUNT/runner/actions-runner
readonly TOOLS_DIR=$VOL_MOUNT/tools
readonly STAGE_VOL=$VOL_MOUNT/.ci-stage            # root-only staging on the CI volume
readonly QUARANTINE=$VOL_MOUNT/.ci-quarantine      # root-only: replaced files the CI account wrote
readonly RUNNER_SHA=$RUNNER_SHA256
readonly RUNNER_URL=https://github.com/actions/runner/releases/download/v$RUNNER_VERSION/actions-runner-osx-arm64-$RUNNER_VERSION.tar.gz
readonly TUIST_SHA=$TUIST_SHA256
readonly TUIST_URL=https://github.com/tuist/tuist/releases/download/$TUIST_VERSION/tuist.zip
readonly RUNNER_LABEL=actions.runner.$RUNNER_ORG.$RUNNER_NAME
readonly RUNNER_PLIST=$CI_HOME/Library/LaunchAgents/$RUNNER_LABEL.plist
readonly RUNNER_STATE_NAMES=".runner .credentials .credentials_rsaparams .runner_migrated .credentials_migrated"
readonly CI_PLACEHOLDERS=".zshenv .zprofile .zshrc .zlogin .zlogout .bash_profile .bashrc .bash_login .profile .curlrc .netrc"
readonly SUPPORT=$SUPPORT_ROOT
readonly STAGE_DATA=$SUPPORT_ROOT/stage            # root-only staging on the Data volume
readonly XCODE=/Applications/Xcode.app
readonly DEV_DIR=/Applications/Xcode.app/Contents/Developer
readonly PF_LABEL=$LABEL_PREFIX.pf
readonly PF_PLIST=/Library/LaunchDaemons/$LABEL_PREFIX.pf.plist
readonly DEADMAN_LABEL=$LABEL_PREFIX.pf-deadman
readonly DEADMAN_PLIST=/Library/LaunchDaemons/$LABEL_PREFIX.pf-deadman.plist
readonly PF_DEADMAN_SECONDS=600
readonly PF_CI_FILE=/etc/pf.anchors/$LABEL_PREFIX PF_CI_ANCHOR=com.apple/250.$PF_ANCHOR_NAME
readonly PF_SS_FILE=/etc/pf.anchors/$LABEL_PREFIX.screensharing PF_SS_ANCHOR=com.apple/251.${PF_ANCHOR_NAME}ScreenSharing
readonly PF_TOKEN_FILE=/var/run/$LABEL_PREFIX.pf.token
readonly PF_STATE_FILE=/var/run/$LABEL_PREFIX.pf.state
readonly PF_LOG=/var/log/$LABEL_PREFIX.pf.log
readonly STOCK_PF_CONF_SHA=$STOCK_PF_CONF_SHA256       # stock macOS /etc/pf.conf (record it from a clean host)
readonly STOCK_PF_APPLE_SHA=$STOCK_PF_APPLE_SHA256     # stock /etc/pf.anchors/com.apple
readonly SSHD_DROPIN=/etc/ssh/sshd_config.d/50-$CI_USER.conf
readonly ALF=/usr/libexec/ApplicationFirewall/socketfilterfw
readonly VNC_LEGACY=/Library/Preferences/com.apple.VNCSettings.txt
readonly SU_PREFS=/Library/Preferences/com.apple.SoftwareUpdate
readonly SETUP_LOG=/var/log/$LABEL_PREFIX.setup.log

# render: fill the __KEY__ placeholders of a generated file (hooks, pf anchors, LaunchDaemons) from the validated
# configuration. Values contain none of sed's special characters (the config format excludes | & and \).
# Refuses a template that still holds a placeholder afterwards.
render() {
  local out
  out=$(sed -e "s|__CI_USER__|$CI_USER|g" -e "s|__CI_UID__|$CI_UID|g" -e "s|__CI_HOME__|$CI_HOME|g" \
    -e "s|__SUPPORT__|$SUPPORT|g" -e "s|__VOL_MOUNT__|$VOL_MOUNT|g" -e "s|__VOL_NAME__|$VOL_NAME|g" \
    -e "s|__RUNNER_LABEL__|$RUNNER_LABEL|g" -e "s|__RUNNER_PLIST__|$RUNNER_PLIST|g" \
    -e "s|__LABEL_PREFIX__|$LABEL_PREFIX|g" -e "s|__PF_ANCHOR_NAME__|$PF_ANCHOR_NAME|g" \
    -e "s|__CI_FULLNAME__|$CI_FULLNAME|g" -e "s|__RUNNER_NAME__|$RUNNER_NAME|g")
  [ -n "$out" ] || return 1
  if printf '%s\n' "$out" | grep -Eq '__[A-Z][A-Z_]*__'; then return 1; fi
  printf '%s\n' "$out"
}
# with_render <command> <args...>: render the template on stdin, then run <command> with the result on its stdin.
# The template is a here-document attached to this call (not nested inside $(...), which bash 3.2 misparses).
with_render() { local t; t=$(render) || die "a template for '$*' holds an unknown placeholder or is empty"; "$@" <<<"$t"; }

MODE=${1:-host}
OPT=${2:-}
REBASELINE=0
case "$MODE:$OPT" in
  preflight:) ;;
  preflight:--ioc) MODE=ioc ;;
  host:|confirm-pf:|ci-session-agents:|harden-runner:) ;;
  harden-runner:--rebaseline) REBASELINE=1 ;;
  *) echo "usage: bash $0 preflight [--ioc] | host | confirm-pf | harden-runner [--rebaseline] | ci-session-agents" >&2; exit 2 ;;
esac

# ---------------------------------------------------------------------------------------------------------------
# Output and failure handling
# ---------------------------------------------------------------------------------------------------------------
STEP=start
PREFLIGHT_FAILS=0
PF_ARMED=0
step() { STEP=$1; printf '\n== %s  %s\n' "$(date -u +%H:%M:%SZ)" "$1"; }
ok()   { printf '   ok       %s\n' "$*"; }
chg()  { printf '   CHANGED  %s\n' "$*"; }
info() { printf '   info     %s\n' "$*"; }
say()  { printf '\n   >>> %s\n' "$*"; }
die() {
  printf '\nFAILED in step "%s":\n  %s\n' "$STEP" "$*" >&2
  printf 'Stopped here. Changes made before this point are kept; nothing was rolled back.\n' >&2
  printf 'Fix the cause and re-run the same command. Finished steps are only re-checked.\n' >&2
  if [ "$PF_ARMED" = 1 ]; then
    printf 'NOTE: pf is armed. Unless confirm-pf runs from a fresh SSH login before %s, the dead-man switch rolls pf back.\n' \
      "$(date -u -r "$(cat "$SUPPORT/etc/pf-deadline" 2>/dev/null || echo 0)" +%H:%M:%SZ)" >&2
  fi
  exit 1
}
# In preflight mode a failed check is counted and the run continues, so one run lists every problem.
pfail() {
  if [ "$MODE" = preflight ]; then
    PREFLIGHT_FAILS=$((PREFLIGHT_FAILS + 1)); printf '   FAIL     %s\n' "$*"
  else
    die "$*"
  fi
}
# set -E carries the ERR trap into command substitutions and subshells. There it only ends the subshell with its
# status, silently: a real failure then fails the command in the main shell, which reports it below, while a
# substitution used as a display argument or in an if-test does not print a false "FAILED" line.
readonly MAIN_SUBSHELL=$BASH_SUBSHELL
# shellcheck disable=SC2154
trap 'rc=$?; if [ "$BASH_SUBSHELL" -gt "$MAIN_SUBSHELL" ]; then exit "$rc"; fi; trap - ERR; die "command failed with exit $rc at line $LINENO: $BASH_COMMAND"' ERR

plv() { plutil -extract "$1" raw -o - - 2>/dev/null; }       # value at a key path of the plist on stdin
has() { grep "$@" >/dev/null; }   # grep to the end of input: no SIGPIPE upstream under pipefail
nlines() { if [ -z "$1" ]; then echo 0; else printf '%s\n' "$1" | wc -l | tr -d ' '; fi; }
# Modes print with the setuid/setgid/sticky digit (%Mp) and without a leading 0: 1775, 755, 644. %Lp alone drops
# the sticky bit, so a 1775 directory would read back as 775.
perm_of() { stat -f '%Su:%Sg %Mp%03Lp' "$1" | sed 's/ 0\([0-7][0-7][0-7]\)$/ \1/'; }
# lmeta <path>: type|owner:group|mode|flags of the path itself (lstat: the last component is never followed).
lmeta() { local m; m=$(stat -f '%HT|%Su:%Sg|%Mp%03Lp|%Sf' "$1" 2>/dev/null) || { echo missing; return 0; }; printf '%s\n' "$m" | sed 's/|0\([0-7][0-7][0-7]\)|/|\1|/'; }
# want_meta <type> <owner:group> <mode> <flags|->: the lmeta string a correct path has.
want_meta() { printf '%s|%s|%s|%s' "$1" "$2" "${3#0}" "$4"; }
# sshd_value <key>: the effective value of an sshd option from `sshd -T`. OpenSSH 10.x prints CamelCase keys
# (DenyUsers), older releases lower case (denyusers): match case-insensitively (references/PITFALLS.md).
sshd_value() { sshd -T 2>/dev/null | awk -v k="$1" 'tolower($1) == tolower(k) {$1=""; print substr($0,2)}'; }

# assert_real_dirs <anchor> <path>: every component below the root-controlled <anchor> down to <path> must be a real
# directory, so a rename or mkdir under <path> cannot be redirected through a planted symlink.
assert_real_dirs() {
  local anchor=$1 path=$2 rel cur part
  case "$path" in "$anchor") return 0 ;; "$anchor"/*) ;; *) die "$path is not below $anchor" ;; esac
  rel=${path#"$anchor"/}; cur=$anchor
  while [ -n "$rel" ]; do
    part=${rel%%/*}
    if [ "$part" = "$rel" ]; then rel=""; else rel=${rel#*/}; fi
    cur=$cur/$part
    case "$(stat -f %HT "$cur" 2>/dev/null)" in
      Directory) ;;
      "") return 0 ;;                         # missing: everything below is created fresh by mkdir
      *) die "$cur is $(lmeta "$cur"), not a real directory: refusing (suspected tampering)" ;;
    esac
  done
}

# rename_nofollow <src> <dst>: rename(2). A symlink at <dst> is replaced, never followed; a directory at <dst> fails.
rename_nofollow() { /usr/bin/perl -e 'rename($ARGV[0], $ARGV[1]) or die "rename $ARGV[0] -> $ARGV[1]: $!\n"' "$1" "$2"; }

stage_for() { case "$1" in ${VOL_MOUNT}/*) echo "$STAGE_VOL" ;; *) echo "$STAGE_DATA" ;; esac; }

# install_file <dst> <owner:group> <mode> <flags|-> < content
# The content is written in a root-only stage directory on the same volume, given its owner and mode there, and
# renamed over <dst>. A regular file at <dst> is replaced; anything else (symlink, directory, socket) stops the run.
# The result is re-verified with lstat. Callers check the parent chain with assert_real_dirs where $CI_USER owns it.
install_file() {
  local dst=$1 og=$2 mode=$3 flags=$4 stage tmp before want
  stage=$(stage_for "$dst")
  [ "$(lmeta "$stage")" = "$(want_meta Directory root:wheel 0700 -)" ] || die "stage $stage is $(lmeta "$stage")"
  tmp=$(mktemp "$stage/f.XXXXXX")
  cat >"$tmp"
  chown "$og" "$tmp"; chmod "$mode" "$tmp"
  before=$(lmeta "$dst")
  case "$before" in
    missing|"Regular File|"*) ;;
    *) rm -f "$tmp"; die "$dst is $before, expected a regular file: refusing (suspected tampering)" ;;
  esac
  want=$(want_meta "Regular File" "$og" "$mode" "$flags")
  if [ "$before" = "$want" ] && cmp -s "$tmp" "$dst"; then
    rm -f "$tmp"; ok "$dst unchanged ($want)"; return 0
  fi
  [ "$before" = missing ] || chflags -h 0 "$dst"
  rename_nofollow "$tmp" "$dst"
  [ "$flags" = - ] || chflags -h "$flags" "$dst"
  [ "$(lmeta "$dst")" = "$want" ] || die "$dst reads back as $(lmeta "$dst"), expected $want"
  chg "$dst $want sha256 $(shasum -a 256 "$dst" | cut -c1-16 || true) (was: $before)"
}

# ensure_dir_safe <path> <owner:group> <mode> <flags|-|keep>: create, or correct, a real directory without following a
# symlink at <path>. "keep" leaves the current flags alone.
ensure_dir_safe() {
  local d=$1 og=$2 mode=$3 flags=$4 before want cur_flags
  before=$(lmeta "$d")
  case "$before" in
    missing) mkdir "$d" ;;
    "Directory|"*) ;;
    *) die "$d is $before, expected a directory: refusing (suspected tampering)" ;;
  esac
  cur_flags=$(stat -f %Sf "$d")
  [ "$flags" != keep ] || flags=$cur_flags
  want=$(want_meta Directory "$og" "$mode" "$flags")
  if [ "$(lmeta "$d")" != "$want" ]; then
    [ "$cur_flags" = - ] || chflags -h 0 "$d"
    chown -h "$og" "$d"; chmod -h "$mode" "$d"
    [ "$flags" = - ] || chflags -h "$flags" "$d"
  fi
  [ "$(lmeta "$d")" = "$want" ] || die "$d reads back as $(lmeta "$d"), expected $want"
  if [ "$before" = "$want" ]; then ok "$d $want"; else chg "$d $want (was: $before)"; fi
}

# quarantine <path> <quarantine-dir>: move whatever sits at <path> (file, directory or symlink, never followed) into a
# root-only quarantine directory on the same volume. Nothing is deleted.
quarantine() {
  local p=$1 q=$2 dst
  [ "$(lmeta "$p")" != missing ] || return 0
  dst="$q$p"
  mkdir -p "${dst%/*}"
  [ "$(stat -f %Sf "$p")" = - ] || chflags -h 0 "$p"
  rename_nofollow "$p" "$dst"
  chg "quarantined $p -> $dst"
}

# ---------------------------------------------------------------------------------------------------------------
# Guards for root work on $CI_USER's trees
# ---------------------------------------------------------------------------------------------------------------
# Refuse to touch $CI_USER's trees while any $CI_USER process could race the checks. Nothing is killed.
require_no_ci_processes() {
  dscl . read "/Users/$CI_USER" UniqueID >/dev/null 2>&1 || return 0
  local i list
  for i in $(seq 1 18); do
    list=$(ps -U "$CI_UID" -o pid=,etime=,comm= 2>/dev/null || true)
    if [ -z "$list" ]; then ok "no $CI_USER process exists"; return 0; fi
    [ "$i" != 1 ] || say "waiting up to 90 s for $CI_USER processes to end (log $CI_FULLNAME out first)"
    sleep 5
  done
  printf '%s\n' "$list" | sed 's/^/            /'
  die "$CI_USER still runs the processes listed above. Log $CI_FULLNAME out and re-run. Per-user daemons (distnoted, cfprefsd, CoreSimulator) can outlive a logout: 'sudo launchctl bootout user/$CI_UID' ends them; if they stay, reboot. Nothing was killed"
}
# A crontab would let $CI_USER run code while logged out, i.e. during this run.
require_no_ci_crontab() {
  [ "$(lmeta "/private/var/at/tabs/$CI_USER")" = missing ] \
    || die "$CI_USER has a crontab (/private/var/at/tabs/$CI_USER): suspected persistence; inspect and remove it, then re-run"
  [ -z "$(find /private/var/at/jobs -mindepth 1 -user "$CI_USER" -print -quit 2>/dev/null || true)" ] \
    || die "$CI_USER has an at job in /private/var/at/jobs: suspected persistence; inspect and remove it, then re-run"
  ok "no crontab or at job for $CI_USER"
}

# ---------------------------------------------------------------------------------------------------------------
# APFS helpers (plutil reads the plist from stdin, so preflight writes nothing)
# ---------------------------------------------------------------------------------------------------------------
data_container() { diskutil info -plist /System/Volumes/Data | plv APFSContainerReference || true; }
container_free() { diskutil info -plist /System/Volumes/Data | plv APFSContainerFree || true; }

# apfs_volumes <containerRef>: UUID, Name, CapacityQuota, CapacityReserve, Encryption, Locked (tab-separated).
apfs_volumes() {
  local want=$1 plist nc ci nv vi b
  plist=$(diskutil apfs list -plist)
  nc=$(printf '%s' "$plist" | plv Containers || echo 0)
  ci=0
  while [ "$ci" -lt "$nc" ]; do
    if [ "$(printf '%s' "$plist" | plv "Containers.$ci.ContainerReference" || true)" = "$want" ]; then
      nv=$(printf '%s' "$plist" | plv "Containers.$ci.Volumes" || echo 0)
      vi=0
      while [ "$vi" -lt "$nv" ]; do
        b="Containers.$ci.Volumes.$vi"
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
          "$(printf '%s' "$plist" | plv "$b.APFSVolumeUUID" || true)" \
          "$(printf '%s' "$plist" | plv "$b.Name" || true)" \
          "$(printf '%s' "$plist" | plv "$b.CapacityQuota" || true)" \
          "$(printf '%s' "$plist" | plv "$b.CapacityReserve" || true)" \
          "$(printf '%s' "$plist" | plv "$b.Encryption" || true)" \
          "$(printf '%s' "$plist" | plv "$b.Locked" || true)"
        vi=$((vi + 1))
      done
    fi
    ci=$((ci + 1))
  done
}
ci_volume_lines() { apfs_volumes "$(data_container)" | awk -F'\t' -v n="$VOL_NAME" '$2 == n'; }
vol_mountpoint() { diskutil info -plist "$1" 2>/dev/null | plv MountPoint || true; }

check_volume_line() {
  local uuid name quota reserve enc locked
  IFS=$'\t' read -r uuid name quota reserve enc locked <<<"$1"
  if [ "$quota" = "$VOL_QUOTA" ] && [ "$reserve" = "$VOL_RESERVE" ] && [ "$enc" = true ]; then
    ok "volume $name $uuid: quota $quota B, reserve $reserve B, encrypted, locked=$locked"
  else
    pfail "volume $name $uuid has quota=$quota reserve=$reserve encryption=$enc; expected $VOL_QUOTA / $VOL_RESERVE / true. diskutil cannot change a quota later; deleting and recreating the volume is a separate teardown decision for the owner"
  fi
}

# ---------------------------------------------------------------------------------------------------------------
# pf helpers
# ---------------------------------------------------------------------------------------------------------------
pf_count() { pfctl -a "$1" -s rules 2>/dev/null | grep -cE '^(block|pass)' || true; }
pf_want()  { pfctl -n -v -f "$1" 2>/dev/null | grep -cE '^(block|pass)' || true; }
pf_config_hash() { cat "$PF_CI_FILE" "$PF_SS_FILE" "$SUPPORT/sbin/pf-assert" "$PF_PLIST" | shasum -a 256 | cut -d' ' -f1; }
pf_anchors() { pfctl -s Anchors -v 2>/dev/null | sed 's/^[[:space:]]*//' | grep -v '^$' || true; }

# pf_state_dump: everything pf holds now, for the record before this script changes anything.
pf_state_dump() {
  local a
  echo "### pfctl -s info"; pfctl -s info 2>&1 || true
  echo "### pfctl -s References"; pfctl -s References 2>&1 || true
  echo "### pfctl -s rules"; pfctl -s rules 2>&1 || true
  echo "### pfctl -s nat"; pfctl -s nat 2>&1 || true
  echo "### pfctl -s Tables"; pfctl -s Tables 2>&1 || true
  echo "### pfctl -s Anchors -v"; pf_anchors
  for a in $(pf_anchors); do
    echo "### anchor $a: rules"; pfctl -a "$a" -s rules 2>&1 || true
    echo "### anchor $a: nat"; pfctl -a "$a" -s nat 2>&1 || true
    echo "### anchor $a: tables"; pfctl -a "$a" -s Tables 2>&1 || true
  done
  echo "### base files"; shasum -a 256 /etc/pf.conf /etc/pf.anchors/* 2>&1 || true
}

# pf_foreign_report: one line per pf rule, nat rule, table or base-file change that is neither stock macOS 27 nor
# this script's own. Empty output means stock.
pf_foreign_report() {
  local line a
  [ "$(shasum -a 256 /etc/pf.conf | cut -d' ' -f1)" = "$STOCK_PF_CONF_SHA" ] || echo "base: /etc/pf.conf differs from stock macOS"
  [ "$(shasum -a 256 /etc/pf.anchors/com.apple | cut -d' ' -f1)" = "$STOCK_PF_APPLE_SHA" ] || echo "base: /etc/pf.anchors/com.apple differs from stock macOS"
  { pfctl -s rules 2>/dev/null || true; pfctl -s nat 2>/dev/null || true; } | while IFS= read -r line; do
    case "$line" in
      ''|'scrub-anchor "com.apple/*" all fragment reassemble'|'scrub-anchor "com.apple/*" all'|'anchor "com.apple/*" all'|\
      'nat-anchor "com.apple/*" all'|'rdr-anchor "com.apple/*" all'|'dummynet-anchor "com.apple/*" all') ;;
      *) printf 'main: %s\n' "$line" ;;
    esac
  done
  { pfctl -s Tables 2>/dev/null || true; } | sed 's/^/main table: /'
  for a in $(pf_anchors); do
    case "$a" in
      "$PF_CI_ANCHOR"|"$PF_SS_ANCHOR") continue ;;                                     # ours
      com.apple/200.AirDrop|com.apple/200.AirDrop/*) continue ;;                       # Apple-managed at runtime
      com.apple/250.ApplicationFirewall|com.apple/250.ApplicationFirewall/*) continue ;;
    esac
    { pfctl -a "$a" -s rules 2>/dev/null || true; pfctl -a "$a" -s nat 2>/dev/null || true; } | while IFS= read -r line; do
      case "$a|$line" in
        *"|"|'com.apple|anchor "200.AirDrop/*" all'|'com.apple|anchor "250.ApplicationFirewall/*" all') ;;
        *) printf '%s: %s\n' "$a" "$line" ;;
      esac
    done
    { pfctl -a "$a" -s Tables 2>/dev/null || true; } | sed "s|^|$a table: |"
  done
}

pf_ready() {
  [ "$(pf_want "$PF_CI_FILE")" -gt 0 ] && [ "$(pf_want "$PF_SS_FILE")" -gt 0 ] \
    && pfctl -s info 2>/dev/null | has '^Status: Enabled' && [ -s "$PF_TOKEN_FILE" ] \
    && [ "$(pf_count "$PF_CI_ANCHOR")" = "$(pf_want "$PF_CI_FILE")" ] \
    && [ "$(pf_count "$PF_SS_ANCHOR")" = "$(pf_want "$PF_SS_FILE")" ] \
    && pfctl -a "$PF_CI_ANCHOR" -s Tables 2>/dev/null | has -x ci_block4 \
    && [ -s "$PF_STATE_FILE" ]
}

# probe_as <user> <host> <port>: 0 when <user> can open a TCP connection within 3 s.
probe_as() {
  local fam=-4
  case "$2" in *:*) fam=-6 ;; esac
  sudo -u "$1" -H /usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/nc "$fam" -z -G 3 "$2" "$3" >/dev/null 2>&1
}

# ---------------------------------------------------------------------------------------------------------------
# Preflight (read-only; also the first step of the root modes)
# ---------------------------------------------------------------------------------------------------------------
preflight() {
  step "preflight (read-only)"
  local model ver major admin_guid g nested members u_by_id id_by_u g_by_id id_by_g container free lines n xv t listen keys
  if [ "$MODE" = preflight ]; then
    info "running as $(id -un) (read-only mode; root-only facts are checked by the root modes)"
  else
    [ "$(id -u)" = 0 ] || die "run with sudo"
    if [ "$MODE" = host ]; then [ -t 0 ] || die "needs an interactive terminal for its prompts (use ssh -t or Terminal)"; fi
  fi

  [ "$(uname -m)" = arm64 ] && ok "arch arm64" || pfail "arch $(uname -m), expected arm64"
  model=$(sysctl -n hw.model)
  if [ -z "$EXPECTED_MODEL" ]; then info "model $model (EXPECTED_MODEL not set: any model accepted)"
  elif [ "$model" = "$EXPECTED_MODEL" ]; then ok "model $model"
  else pfail "model $model is not $EXPECTED_MODEL: wrong Mac?"; fi
  ver=$(sw_vers -productVersion); major=${ver%%.*}
  [ "$major" -ge 27 ] && ok "macOS $ver ($(sw_vers -buildVersion))" || pfail "macOS $ver is older than the qualified 27.x"
  [ "$(id -u "$OWNER_USER" 2>/dev/null || true)" = "$OWNER_UID" ] && ok "owner account $OWNER_USER has UID $OWNER_UID" \
    || pfail "account $OWNER_USER with UID $OWNER_UID not found"
  info "$(fdesetup status 2>/dev/null | head -1 || true)"

  admin_guid=$(dscl . read /Groups/admin GeneratedUID 2>/dev/null | awk '/^GeneratedUID:/{print $2}')
  for g in com.apple.access_ssh com.apple.access_screensharing; do
    nested=$(dscl . read "/Groups/$g" NestedGroups 2>/dev/null | awk '/^NestedGroups:/{$1=""; print substr($0,2)}' || true)
    members=$(dscl . read "/Groups/$g" GroupMembership 2>/dev/null | awk '/^GroupMembership:/{$1=""; print substr($0,2)}' || true)
    if [ -n "$admin_guid" ] && [ "$nested" = "$admin_guid" ] && ! printf ' %s ' "$members" | has " $CI_USER "; then
      ok "$g exists, nests only admin, members: ${members:-none}"
    else
      pfail "$g must exist and nest only admin ($admin_guid); found nested='$nested' members='$members'"
    fi
  done

  u_by_id=$(dscl . list /Users UniqueID | awk -v id="$CI_UID" '$2 == id {print $1}')
  id_by_u=$(dscl . list /Users UniqueID | awk -v n="$CI_USER" '$1 == n {print $2}')
  case "$u_by_id|$id_by_u" in
    "|") ok "UID $CI_UID is free and user $CI_USER does not exist yet" ;;
    "$CI_USER|$CI_UID") ok "user $CI_USER already exists with UID $CI_UID (ours)" ;;
    *) pfail "UID $CI_UID belongs to '$u_by_id'; user $CI_USER has UID '$id_by_u'" ;;
  esac
  g_by_id=$(dscl . list /Groups PrimaryGroupID | awk -v id="$CI_GID" '$2 == id {print $1}')
  id_by_g=$(dscl . list /Groups PrimaryGroupID | awk -v n="$CI_USER" '$1 == n {print $2}')
  case "$g_by_id|$id_by_g" in
    "|") ok "GID $CI_GID is free and group $CI_USER does not exist yet" ;;
    "$CI_USER|$CI_GID") ok "group $CI_USER already exists with GID $CI_GID (ours)" ;;
    *) pfail "GID $CI_GID belongs to '$g_by_id'; group $CI_USER has GID '$id_by_g'" ;;
  esac

  if [ -d "$XCODE" ] && xv=$(DEVELOPER_DIR="$DEV_DIR" xcodebuild -version 2>/dev/null | tr '\n' ' '); then
    ok "$XCODE: $xv(owner $(stat -f %Su:%Sg "$XCODE"))"
  else
    pfail "$XCODE is missing or xcodebuild does not run"
  fi

  grep -qE '^anchor "com\.apple/\*"' /etc/pf.conf && ok "/etc/pf.conf has the com.apple/* anchor point" \
    || pfail "/etc/pf.conf lacks 'anchor \"com.apple/*\"'; the CI anchor would never be evaluated"
  [ "$(shasum -a 256 /etc/pf.conf | cut -d' ' -f1)" = "$STOCK_PF_CONF_SHA" ] && ok "/etc/pf.conf is stock" \
    || pfail "/etc/pf.conf differs from the stock file recorded in STOCK_PF_CONF_SHA256"

  listen=$(netstat -an -p tcp 2>/dev/null | awk '$NF == "LISTEN" {print $4}' || true)
  if printf '%s\n' "$listen" | has -E '\.22$'; then ok "sshd listens on port 22"; else pfail "nothing listens on port 22 (Remote Login off?)"; fi

  container=$(data_container); free=$(container_free)
  if [ -z "$container" ] || [ -z "$free" ]; then
    pfail "cannot read the APFS container of /System/Volumes/Data"
  else
    lines=$(ci_volume_lines); n=$(nlines "$lines")
    if [ "$n" = 0 ]; then
      if [ "$free" -ge $((VOL_RESERVE + MIN_CONTAINER_FREE_AFTER)) ]; then
        ok "container $container has $((free / 1073741824)) GiB unallocated; volume $VOL_NAME will be created"
      else
        pfail "container $container has only $((free / 1073741824)) GiB unallocated; need the reserve $((VOL_RESERVE / 1073741824)) GiB + $((MIN_CONTAINER_FREE_AFTER / 1073741824)) GiB margin"
      fi
      [ ! -e "$VOL_MOUNT" ] || pfail "$VOL_MOUNT exists although no volume named $VOL_NAME is in $container"
    elif [ "$n" = 1 ]; then
      check_volume_line "$lines"
    else
      pfail "$n volumes named $VOL_NAME in $container; expected at most one"
    fi
  fi

  for t in diskutil sysadminctl dseditgroup dscl dsmemberutil createhomedir pfctl launchctl pmset defaults \
           plutil shasum sshd xcodebuild xcode-select mdutil nc curl lsof codesign perl tar ditto; do
    command -v "$t" >/dev/null 2>&1 || pfail "missing tool $t"
  done
  [ -x "$ALF" ] || pfail "missing $ALF"

  # Root-only integrity facts (indicators I1, I3): every root-owned control below assumes a clean root account.
  if [ "$(id -u)" = 0 ] && [ "$MODE" != ioc ]; then
    if [ -s /var/root/.ssh/authorized_keys ]; then
      keys=$(ssh-keygen -lf /var/root/.ssh/authorized_keys 2>&1 || true)
      printf '%s\n' "$keys" | sed 's/^/            /'
      die "root has SSH authorized_keys (fingerprints above). Stop: run 'preflight --ioc' and decide with the operator"
    fi
    ok "root has no SSH authorized_keys (indicator I1)"
    if grep -nE '^[^#]*NOPASSWD' /etc/sudoers >/dev/null 2>&1; then
      info "NOPASSWD lines in /etc/sudoers: $(grep -nE '^[^#]*NOPASSWD' /etc/sudoers | tr '\n' ';' || true) (review with 'preflight --ioc')"
    else
      ok "no NOPASSWD rule in /etc/sudoers (indicator I3); sudoers.d: $(ls /etc/sudoers.d 2>/dev/null | tr '\n' ' ' || true)"
    fi
  fi

  if [ "$MODE" = preflight ]; then
    printf '\npreflight: %s failed check(s)\n' "$PREFLIGHT_FAILS"
    if [ "$PREFLIGHT_FAILS" = 0 ]; then exit 0; else exit 1; fi
  fi
}

# ---------------------------------------------------------------------------------------------------------------
# preflight --ioc: root-compromise indicator checks I1-I5 (references/DESIGN.md) and the pf state. Read-only.
# ---------------------------------------------------------------------------------------------------------------
# site_list <file>: true for a usable optional site list of preflight --ioc; absent is false; present but not a
# root:wheel regular file without group/other write is a finding (the caller's `finding`) and false.
site_list() {
  [ -e "$1" ] || [ -L "$1" ] || return 1
  case "$(lmeta "$1")" in
    "Regular File|root:wheel|"[0-7][0145][0145]"|"*) return 0 ;;
    *) finding "$1 is not a root:wheel regular file without group/other write ($(lmeta "$1")); ignored"; return 1 ;;
  esac
}
mode_ioc() {
  [ "$(id -u)" = 0 ] || die "preflight --ioc needs sudo"
  local findings=0 f out tcc
  finding() { findings=$((findings + 1)); printf '   FINDING  %s\n' "$*"; }
  step "I1: root's SSH keys, root's home, and an optional site list of paths"
  ls -la /var/root /var/root/.ssh 2>&1 | sed 's/^/            /' || true          # a missing .ssh is the clean case
  if [ -s /var/root/.ssh/authorized_keys ]; then
    finding "root authorized_keys present: $(ssh-keygen -lf /var/root/.ssh/authorized_keys 2>&1 | tr '\n' ';' || true)"
  else ok "no root authorized_keys"; fi
  # Entries in root's home other than the stock ones and the site allowlist are findings for review (the listing
  # above shows them). SUPPORT/etc/root-home-allow (optional): extra entry names, one per line. Like every optional
  # list below it must be a root:wheel regular file without group/other write, or it is a finding and ignored.
  local allow=" Library .CFUserTextEncoding .forward .ssh .lesshst .viminfo .zsh_history .zsh_sessions .bash_history .bash_sessions .Trash " n
  if site_list "$SUPPORT/etc/root-home-allow"; then
    while IFS= read -r f || [ -n "$f" ]; do
      case "$f" in ''|'#'*) continue ;; */*|*' '*) finding "root-home-allow: '$f' is not a plain entry name"; continue ;; esac
      allow="$allow$f "
    done <"$SUPPORT/etc/root-home-allow"
  fi
  out=""
  for f in /var/root/.[!.]* /var/root/..?* /var/root/*; do
    [ -e "$f" ] || [ -L "$f" ] || continue                                             # an unmatched glob
    n=${f##*/}; case "$allow" in *" $n "*) ;; *) out="$out $n" ;; esac
  done
  [ -z "$out" ] && ok "root's home holds only stock or allowed entries" || finding "unexpected entries in /var/root:$out"
  # SUPPORT/etc/indicator-paths (optional): site-specific absolute paths that must be absent, one per line. Keep
  # such a list out of any public repository.
  if site_list "$SUPPORT/etc/indicator-paths"; then
    while IFS= read -r f || [ -n "$f" ]; do
      case "$f" in ''|'#'*) continue ;; /*) ;; *) finding "indicator-paths: '$f' is not an absolute path"; continue ;; esac
      [ "$(lmeta "$f")" = missing ] && ok "absent: listed path $f" || finding "present: listed path $f ($(lmeta "$f"))"
    done <"$SUPPORT/etc/indicator-paths"
  else info "no usable $SUPPORT/etc/indicator-paths: no site-specific paths checked"; fi
  step "I2: background task management (login and background items of all users)"
  out=$(sfltool dumpbtm 2>&1 || true)
  printf '%s\n' "$out" | grep -E '^[[:space:]]*(Name|Developer Name|Team Identifier|Type|Disposition|Identifier|URL|Executable Path):' \
    | sed 's/^[[:space:]]*/            /' || true                                      # no item lines is a normal result
  if printf '%s\n' "$out" | grep -E '(URL|Executable Path):' | has -E '/(bash|sh|zsh|python[0-9.]*|perl|ruby|osascript)( |$)|/var/tmp/|/private/tmp/|/Users/Shared/'; then
    finding "a login or background item runs an interpreter or lives in a shared temp path (see the lines above)"
  else ok "no login or background item runs an interpreter or lives in a shared temp path"; fi
  step "I3: sudoers"
  grep -nE 'NOPASSWD|^[#@]include' /etc/sudoers 2>&1 | sed 's/^/            /' || true
  ls -la /etc/sudoers.d 2>&1 | sed 's/^/            /' || true
  for f in /etc/sudoers.d/*; do [ -f "$f" ] && sed "s|^|            $f: |" "$f"; done
  if grep -qE '^[^#]*NOPASSWD:?[[:space:]]*ALL' /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then finding "a NOPASSWD ALL rule exists"
  else ok "no NOPASSWD ALL rule"; fi
  step "I4: crontabs, at jobs, periodic scripts"
  ls -la /private/var/at/tabs /private/var/at/jobs 2>&1 | sed 's/^/            /' || true
  out=$(find /private/var/at/tabs /private/var/at/jobs -mindepth 1 2>/dev/null | grep -v '/\.SEQ$' || true)
  [ -z "$out" ] && ok "no crontab or at job" || finding "crontab or at job present: $(printf '%s' "$out" | tr '\n' ' ')"
  # periodic(8) scripts changed after the installed macOS release are not Apple's stock set.
  out=$(find /etc/periodic /usr/local/etc/periodic -type f -newer /System/Library/CoreServices/SystemVersion.plist 2>/dev/null || true)
  [ -z "$out" ] && ok "no periodic script newer than the installed macOS" || finding "periodic scripts newer than the OS: $(printf '%s' "$out" | tr '\n' ' ')"
  step "I5: TCC grants and pf"
  tcc="/Library/Application Support/com.apple.TCC/TCC.db"
  if out=$(sqlite3 "$tcc" "select service, client, auth_value from access where auth_value = 2 and service in ('kTCCServiceScreenCapture','kTCCServiceAccessibility','kTCCServiceSystemPolicyAllFiles','kTCCServicePostEvent','kTCCServiceListenEvent','kTCCServiceDeveloperTool')" 2>&1); then
    printf '%s\n' "${out:-<no grants>}" | sed 's/^/            /'
    ok "TCC grants listed above (review for unknown clients)"
  else
    info "TCC.db not readable from this shell ($out): COULD NOT CHECK. Run this mode from Terminal at the Mac with Full Disk Access granted to Terminal"
  fi
  pf_state_dump | sed 's/^/            /'
  out=$(pf_foreign_report)
  [ -z "$out" ] && ok "pf state is stock macOS (plus, at most, this script's anchors)" || { printf '%s\n' "$out" | sed 's/^/   foreign  /'; finding "pf holds foreign rules (listed above)"; }
  step "root indicator checks: $findings finding(s)"
  if [ "$findings" = 0 ]; then exit 0; else exit 1; fi
}

# ---------------------------------------------------------------------------------------------------------------
# Host steps
# ---------------------------------------------------------------------------------------------------------------
step_ci_guards() {
  step "no $CI_USER process or crontab while root works on its trees"
  require_no_ci_processes
  require_no_ci_crontab
}

step_support_tree() {
  step "root-owned support tree $SUPPORT"
  [ "$(lmeta /opt)" = "$(want_meta Directory root:wheel 0755 -)" ] || die "/opt must be a root:wheel 755 directory without BSD flags, is $(lmeta /opt). A 'hidden' flag (set by some installers) is harmless but refused: 'sudo chflags nohidden /opt', then re-run"
  # Never adopt someone else's tree: an existing SUPPORT_ROOT must already be a root:wheel 755 directory
  # (for example one made by the install step of references/RUNBOOK.md), not a third-party directory such as a
  # package manager's prefix, whose ownership ensure_dir_safe would otherwise rewrite.
  case "$(lmeta "$SUPPORT")" in
    missing|"Directory|root:wheel|755|-") ;;
    *) die "$SUPPORT exists as $(lmeta "$SUPPORT"); SUPPORT_ROOT must be a new directory or one already root:wheel 755" ;;
  esac
  local d
  for d in "$SUPPORT" "$SUPPORT/etc" "$SUPPORT/sbin" "$SUPPORT/libexec" "$SUPPORT/hooks" "$SUPPORT/baseline" "$SUPPORT/setup"; do
    ensure_dir_safe "$d" root:wheel 0755 -
  done
  ensure_dir_safe "$SUPPORT/backup" root:wheel 0700 -
  ensure_dir_safe "$STAGE_DATA" root:wheel 0700 -
}

step_volume() {
  step "APFS volume $VOL_NAME: encrypted, quota $((VOL_QUOTA / 1073741824)) GiB, reserve $((VOL_RESERVE / 1073741824)) GiB, mounted at $VOL_MOUNT"
  local container lines n uuid mp tries recorded
  container=$(data_container)
  lines=$(ci_volume_lines); n=$(nlines "$lines")
  [ "$n" -le 1 ] || die "$n volumes named $VOL_NAME exist; expected at most one"
  if [ "$n" = 0 ]; then
    [ ! -e "$VOL_MOUNT" ] || die "$VOL_MOUNT exists although there is no $VOL_NAME volume"
    say "diskutil now asks for the passphrase of the new $VOL_NAME volume (input hidden)."
    say "Store it in your password manager first: it is needed after every reboot."
    diskutil apfs addVolume "$container" APFS "$VOL_NAME" -passprompt -quota "$VOL_QUOTA" -reserve "$VOL_RESERVE"
    chg "created APFS volume $VOL_NAME in $container"
    lines=$(ci_volume_lines)
    [ "$(nlines "$lines")" = 1 ] || die "volume $VOL_NAME not found after addVolume"
  fi
  check_volume_line "$lines"
  uuid=$(printf '%s\n' "$lines" | cut -f1)
  if [ -f "$SUPPORT/etc/volume-uuid" ]; then
    recorded=$(cat "$SUPPORT/etc/volume-uuid")
    [ "$recorded" = "$uuid" ] || die "volume $VOL_NAME is $uuid but $SUPPORT/etc/volume-uuid records $recorded"
  fi
  printf '%s\n' "$uuid" | install_file "$SUPPORT/etc/volume-uuid" root:wheel 0644 -

  if [ "$(printf '%s\n' "$lines" | cut -f6)" = true ]; then
    say "The $VOL_NAME volume is locked. diskutil asks for its passphrase."
    diskutil apfs unlockVolume "$uuid"
    chg "unlocked $VOL_NAME"
  fi
  mp=$(vol_mountpoint "$uuid")
  if [ -z "$mp" ]; then diskutil mount "$uuid" >/dev/null; chg "mounted $VOL_NAME"; mp=$(vol_mountpoint "$uuid"); fi
  [ "$mp" = "$VOL_MOUNT" ] || die "$VOL_NAME is mounted at '$mp', expected $VOL_MOUNT (a $CI_USER login before the unlock creates a stray $VOL_MOUNT; see NOTES)"
  ok "$VOL_NAME mounted at $mp"

  if mdutil -s "$VOL_MOUNT" 2>/dev/null | has -i 'indexing disabled'; then ok "Spotlight indexing disabled"; else
    mdutil -i off "$VOL_MOUNT" >/dev/null; chg "Spotlight indexing turned off"
    mdutil -s "$VOL_MOUNT" 2>/dev/null | has -i 'indexing disabled' || die "Spotlight indexing still on for $VOL_MOUNT"
  fi

  if [ -f "$SUPPORT/etc/volume-passphrase-verified" ]; then
    ok "passphrase verified earlier ($(cat "$SUPPORT/etc/volume-passphrase-verified"))"
  else
    say "Verifying the passphrase: the volume is locked now and diskutil asks for it once more."
    tries=0
    until diskutil apfs lockVolume "$uuid" >/dev/null 2>&1; do
      tries=$((tries + 1)); [ "$tries" -lt 4 ] || die "could not lock $VOL_NAME to verify the passphrase (volume busy)"
      sleep 3
    done
    tries=0
    until diskutil apfs unlockVolume "$uuid"; do
      tries=$((tries + 1))
      [ "$tries" -lt 3 ] || die "the passphrase did not unlock $VOL_NAME. The volume stays locked and is still empty; if the passphrase is lost, deleting it (diskutil apfs deleteVolume $uuid) is a separate decision, then re-run"
      say "Wrong passphrase, try again."
    done
    date -u +%Y-%m-%dT%H:%M:%SZ | install_file "$SUPPORT/etc/volume-passphrase-verified" root:wheel 0644 -
    [ "$(vol_mountpoint "$uuid")" = "$VOL_MOUNT" ] || die "$VOL_NAME did not mount at $VOL_MOUNT after unlock"
    chg "passphrase verified by lock and unlock"
  fi

  if [ "$(diskutil info -plist "$VOL_MOUNT" | plv GlobalPermissionsEnabled || true)" != true ]; then
    diskutil enableOwnership "$VOL_MOUNT" >/dev/null; chg "ownership enabled on $VOL_MOUNT"
  fi
  [ "$(diskutil info -plist "$VOL_MOUNT" | plv GlobalPermissionsEnabled || true)" = true ] || die "ownership is not enabled on $VOL_MOUNT"
  if mount | grep -F " on $VOL_MOUNT (" | has noowners; then die "$VOL_MOUNT is mounted with noowners"; fi
  ok "ownership enabled on $VOL_MOUNT ($(mount | grep -F " on $VOL_MOUNT (" | sed 's/.* (/(/' || true))"

  ensure_dir_safe "$VOL_MOUNT" root:wheel 0755 -
  ensure_dir_safe "$STAGE_VOL" root:wheel 0700 -
  ensure_dir_safe "$QUARANTINE" root:wheel 0700 -
  ensure_dir_safe "$VOL_MOUNT/home" root:wheel 0755 -
  ensure_dir_safe "$RUNNER_PARENT" root:wheel 0755 -
  # Root-owned and sticky before anything is written into it: $CI_USER can add its own files (02: tarball,
  # config.sh state) but can never rename or replace a root-owned entry.
  if dscl . read "/Groups/$CI_USER" PrimaryGroupID >/dev/null 2>&1; then
    ensure_dir_safe "$RUNNER_DIR" "root:$CI_USER" 1775 -
  else
    ensure_dir_safe "$RUNNER_DIR" root:wheel 1775 -      # step_group gives it group $CI_USER
  fi
  ensure_dir_safe "$TOOLS_DIR" root:wheel 0755 -
  ensure_dir_safe "$TOOLS_DIR/tuist" root:wheel 0755 -

  if tmutil destinationinfo 2>/dev/null | has '^Name'; then
    info "Time Machine has a destination: exclude $VOL_MOUNT in System Settings > General > Time Machine > Options"
  else
    ok "no Time Machine destination configured"
  fi
}

step_group() {
  step "group $CI_USER (GID $CI_GID)"
  local gid
  gid=$(dscl . read "/Groups/$CI_USER" PrimaryGroupID 2>/dev/null | awk '/^PrimaryGroupID:/{print $2}' || true)
  if [ -z "$gid" ]; then
    dseditgroup -o create -i "$CI_GID" -r "$CI_FULLNAME" "$CI_USER"
    chg "created group $CI_USER"
    gid=$(dscl . read "/Groups/$CI_USER" PrimaryGroupID 2>/dev/null | awk '/^PrimaryGroupID:/{print $2}' || true)
  fi
  [ "$gid" = "$CI_GID" ] || die "group $CI_USER has GID '$gid', expected $CI_GID"
  ok "group $CI_USER GID $gid"
  # The runner directory was created before the group existed on a first run: give it its final group now.
  ensure_dir_safe "$RUNNER_DIR" "root:$CI_USER" 1775 -
}

uattr() { dscl . read "/Users/$CI_USER" "$1" 2>/dev/null | awk -v k="$1:" '$1 == k {$1=""; print substr($0,2)}' || true; }

step_user() {
  step "standard user $CI_USER (UID $CI_UID, home $CI_HOME, not admin, no secure token)"
  if ! dscl . read "/Users/$CI_USER" UniqueID >/dev/null 2>&1; then
    say "sysadminctl now asks for the new $CI_USER password (input hidden)."
    say "Store it in your password manager first: it is needed for the GUI login after every reboot."
    say "A sysadminctl message about FileVault/FDE is expected: this account must not unlock FileVault."
    say "Run this from Terminal at the Mac with Full Disk Access: over SSH without it, macOS refuses directory writes"
    say "(eDSPermissionError), and sysadminctl silently assigns the next free UID (references/PITFALLS.md)."
    sysadminctl -addUser "$CI_USER" -fullName "$CI_FULLNAME" -UID "$CI_UID" -GID "$CI_GID" \
      -shell /bin/zsh -home "$CI_HOME" -password -
    dscl . read "/Users/$CI_USER" UniqueID >/dev/null 2>&1 || die "sysadminctl did not create $CI_USER"
    chg "created user $CI_USER"
  fi
  [ "$(uattr UniqueID)" = "$CI_UID" ] || die "$CI_USER has UniqueID '$(uattr UniqueID)', expected $CI_UID. If sysadminctl ran without Full Disk Access it fell back to the next free UID: from Terminal at the Mac with Full Disk Access run 'sudo dscl . -create /Users/$CI_USER UniqueID $CI_UID' (the account owns no files yet), then re-run (references/PITFALLS.md)"
  if [ "$(uattr PrimaryGroupID)" != "$CI_GID" ]; then
    dscl . create "/Users/$CI_USER" PrimaryGroupID "$CI_GID"; chg "PrimaryGroupID set to $CI_GID"
  fi
  [ "$(uattr NFSHomeDirectory)" = "$CI_HOME" ] || die "$CI_USER home is '$(uattr NFSHomeDirectory)', expected $CI_HOME"
  if [ "$(uattr UserShell)" != /bin/zsh ]; then dscl . create "/Users/$CI_USER" UserShell /bin/zsh; chg "shell set to /bin/zsh"; fi
  ok "UID $(uattr UniqueID), GID $(uattr PrimaryGroupID), home $(uattr NFSHomeDirectory), shell $(uattr UserShell)"

  if [ -f "$SUPPORT/etc/ci-password-verified" ]; then
    ok "password verified earlier ($(cat "$SUPPORT/etc/ci-password-verified"))"
  else
    say "Type the $CI_USER password once more to verify it."
    if ! dscl . -authonly "$CI_USER"; then
      say "That did not match. passwd now sets the $CI_USER password again (it asks twice)."
      passwd "$CI_USER"
      say "Type the new $CI_USER password once more to verify it."
      dscl . -authonly "$CI_USER" || die "the $CI_USER password could not be verified; re-run to try again"
    fi
    date -u +%Y-%m-%dT%H:%M:%SZ | install_file "$SUPPORT/etc/ci-password-verified" root:wheel 0644 -
    chg "password verified"
  fi
}

step_home() {
  step "home $CI_HOME"
  # The home's parent is root-owned, so the home itself cannot be swapped. Its inside belongs to $CI_USER; host
  # only builds the skeleton once, before $CI_USER has ever run anything. harden-runner owns everything else.
  if [ -f "$SUPPORT/etc/home-initialized" ]; then
    case "$(lmeta "$CI_HOME")" in
      "Directory|$CI_USER:$CI_USER|700|"*) ok "$CI_HOME $(lmeta "$CI_HOME") (initialized $(cat "$SUPPORT/etc/home-initialized"))" ;;
      *) die "$CI_HOME is $(lmeta "$CI_HOME"), expected Directory|$CI_USER:$CI_USER|700" ;;
    esac
    return 0
  fi
  if [ "$(lmeta "$CI_HOME")" = missing ]; then
    createhomedir -c -u "$CI_USER" >/dev/null 2>&1 || true
    if [ "$(lmeta "$CI_HOME")" = missing ]; then
      mkdir "$CI_HOME"
      ditto "/System/Library/User Template/Non_localized" "$CI_HOME"
      ditto "/System/Library/User Template/English.lproj" "$CI_HOME"
    fi
    chg "created home from the user template"
  fi
  case "$(lmeta "$CI_HOME")" in "Directory|"*) ;; *) die "$CI_HOME is $(lmeta "$CI_HOME"), not a directory" ;; esac
  # Fresh tree: $CI_USER has never logged in or run a process (step_ci_guards). -P: no symlink is followed.
  chown -R -P "$CI_USER:$CI_USER" "$CI_HOME"
  ensure_dir_safe "$CI_HOME" "$CI_USER:$CI_USER" 0700 -
  local d
  for d in tmp work ci-logs; do ensure_dir_safe "$CI_HOME/$d" "$CI_USER:$CI_USER" 0700 -; done
  date -u +%Y-%m-%dT%H:%M:%SZ | install_file "$SUPPORT/etc/home-initialized" root:wheel 0644 -
}

step_identity_readback() {
  step "$CI_USER privilege readback (all must hold)"
  local g out fv
  for g in admin staff wheel _developer com.apple.access_ssh com.apple.access_screensharing _lpadmin; do
    out=$(dsmemberutil checkmembership -U "$CI_USER" -G "$g" 2>&1 || true)
    case "$out" in
      *"is not a member"*) ok "not a member of $g" ;;
      *) die "membership check for $g returned: $out" ;;
    esac
  done
  out=$(dsmemberutil checkmembership -U "$CI_USER" -G "$CI_USER" 2>&1 || true)
  case "$out" in
    *"is not a member"*) die "positive control failed: $CI_USER is not a member of its own group" ;;
    *"is a member"*) ok "member of its own group $CI_USER (positive control for the checks above)" ;;
    *) die "membership check for $CI_USER returned: $out" ;;
  esac
  out=$(sysadminctl -secureTokenStatus "$CI_USER" 2>&1 || true)
  case "$out" in *DISABLED*) ok "secure token DISABLED" ;; *) die "secure token status: $out" ;; esac
  fv=$(fdesetup list 2>/dev/null | cut -d, -f1 | sort | tr '\n' ' ')
  [ "$fv" = "$OWNER_USER " ] && ok "FileVault unlock users: $fv" || die "FileVault unlock users are '$fv', expected only $OWNER_USER"
  if grep -rqsw "$CI_USER" /etc/sudoers /etc/sudoers.d; then die "$CI_USER appears in sudoers"; fi
  out=$(sudo -l -U "$CI_USER" 2>&1 || true)
  case "$out" in *"not allowed to run sudo"*) ok "sudo -l -U $CI_USER: not allowed to run sudo" ;; *) die "sudo -l -U $CI_USER: $out" ;; esac
}

# cron and at: $CI_USER may not install jobs that run while it is logged out.
step_cron_deny() {
  step "cron and at denied for $CI_USER"
  local f cur
  for f in /private/var/at/cron.deny /private/var/at/at.deny; do
    cur=$(cat "$f" 2>/dev/null || true)
    if printf '%s\n' "$cur" | has -x "$CI_USER"; then ok "$f lists $CI_USER"; continue; fi
    { [ -z "$cur" ] || printf '%s\n' "$cur"; printf '%s\n' "$CI_USER"; } | install_file "$f" root:wheel 0644 -
  done
}

step_xcode() {
  step "Xcode: root-owned toolchain, first launch done, license accepted"
  if [ -n "$(find "$XCODE" \( ! -user root -o ! -group wheel \) -print -quit 2>/dev/null)" ]; then
    say "chown -R root:wheel $XCODE (a few minutes). If this fails with 'Operation not permitted', macOS App"
    say "Management protection blocked it: run this script from Terminal at the Mac with App Management allowed."
    chown -R -P root:wheel "$XCODE"
    chg "$XCODE owned by root:wheel"
  fi
  if [ -n "$(find "$XCODE" ! -type l -perm +022 -print -quit 2>/dev/null)" ]; then
    chmod -R -P go-w "$XCODE"; chg "removed group/other write bits inside $XCODE"
  fi
  [ -z "$(find "$XCODE" \( ! -user root -o ! -group wheel \) -print -quit 2>/dev/null)" ] || die "$XCODE still has non-root files"
  [ -z "$(find "$XCODE" ! -type l -perm +022 -print -quit 2>/dev/null)" ] || die "$XCODE still has group/other-writable files"
  ok "$XCODE: every file root:wheel, nothing group/other-writable"
  if [ "$(xcode-select -p)" != "$DEV_DIR" ]; then xcode-select -s "$DEV_DIR"; chg "xcode-select -> $DEV_DIR"; fi
  ok "xcode-select -p = $(xcode-select -p)"
  if ! DEVELOPER_DIR="$DEV_DIR" xcodebuild -checkFirstLaunchStatus >/dev/null 2>&1; then
    DEVELOPER_DIR="$DEV_DIR" xcodebuild -runFirstLaunch; chg "xcodebuild -runFirstLaunch done"
  fi
  DEVELOPER_DIR="$DEV_DIR" xcodebuild -checkFirstLaunchStatus >/dev/null 2>&1 || die "first launch still incomplete"
  ok "first launch complete (checkFirstLaunchStatus exit 0)"
  if ! DEVELOPER_DIR="$DEV_DIR" xcodebuild -license check >/dev/null 2>&1; then
    DEVELOPER_DIR="$DEV_DIR" xcodebuild -license accept; chg "license accepted"
  fi
  DEVELOPER_DIR="$DEV_DIR" xcodebuild -license check >/dev/null 2>&1 || die "license not accepted"
  ok "license accepted (license check exit 0)"
}

# ---------------------------------------------------------------------------------------------------------------
# Root-owned support files (hooks, manifest, pf loader, dead-man). Read-only to $CI_USER.
# ---------------------------------------------------------------------------------------------------------------
write_ci_manifest() {
  with_render install_file "$SUPPORT/libexec/ci-manifest" root:wheel 0755 - <<'MANIFEST_EOF'
#!/bin/bash
# ci-manifest: prints the persistence-relevant files of the __CI_USER__ account, one fact per line, in a fixed order.
# Recorded once by root as the baseline (host-prep.sh harden-runner, before the runner first starts) and
# compared by the job-started hook before every job. Run as __CI_USER__ with a clean environment. Credential files
# are listed by owner and mode only and are never read. Live session state (launchd jobs, processes, launchd
# environment) is checked by rule in the job-started hook, not here.
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C
readonly H=__CI_HOME__
readonly R=__VOL_MOUNT__/runner/actions-runner
readonly T=__VOL_MOUNT__/tools

# fact <path>: kind, owner, group, mode, flags and, for regular files, sha256. Never follows the last component.
fact() {
  local p=$1
  if [ -L "$p" ]; then printf 'link  %s -> %s\n' "$p" "$(readlink "$p")"
  elif [ -f "$p" ]; then printf 'file  %s %s %s\n' "$p" "$(stat -f '%Su:%Sg:%Mp%03Lp:%Sf' "$p")" "$(shasum -a 256 <"$p" | cut -d' ' -f1)"
  elif [ -d "$p" ]; then printf 'dir   %s %s\n' "$p" "$(stat -f '%Su:%Sg:%Mp%03Lp:%Sf' "$p")"
  elif [ -e "$p" ]; then printf 'other %s %s\n' "$p" "$(stat -f '%HT:%Su:%Sg:%Mp%03Lp:%Sf' "$p")"
  else printf 'none  %s\n' "$p"
  fi
}

echo "## identity"
id
echo "## home: every top-level entry (the home is append-only, so this set only grows); volatile session files excluded"
fact "$H"
find "$H" -mindepth 1 -maxdepth 1 ! -name .DS_Store ! -name .zsh_history ! -name .zsh_sessions ! -name .lesshst \
  | sort | while IFS= read -r p; do fact "$p"; done
echo "## startup paths below the top level"
for f in .config/git .MacOSX Library/LaunchAgents; do fact "$H/$f"; done
echo "## LaunchAgents entries"
if [ -d "$H/Library/LaunchAgents" ] && [ ! -L "$H/Library/LaunchAgents" ]; then
  find "$H/Library/LaunchAgents" -mindepth 1 -maxdepth 1 | sort | while IFS= read -r p; do fact "$p"; done
fi
echo "## SwiftPM mirrors and registries"
for f in "$H/Library/org.swift.swiftpm/configuration/mirrors.json" "$H/Library/org.swift.swiftpm/configuration/registries.json" \
         "$H/.swiftpm/configuration/mirrors.json" "$H/.swiftpm/configuration/registries.json"; do
  fact "$f"
done
echo "## crontab"
printf 'crontab sha256 %s\n' "$({ crontab -l 2>/dev/null || true; } | shasum -a 256 | cut -d' ' -f1)"
echo "## runner directory (registration state by owner and mode only; _diag and broker-migration files excluded)"
fact "$(dirname "$R")"
fact "$R"
find "$R" -mindepth 1 -maxdepth 1 ! -name _diag ! -name .runner_migrated ! -name .credentials_migrated | sort | while IFS= read -r p; do
  case "${p##*/}" in
    .runner|.credentials|.credentials_rsaparams) printf 'state %s %s\n' "$p" "$(stat -f '%Su:%Sg:%Lp' "$p")" ;;
    *) fact "$p" ;;
  esac
done
echo "## runner binaries not root-owned or group/other-writable (must stay empty)"
find "$R"/bin "$R"/externals ! -type l \( ! -user root -o -perm +022 \) -print 2>/dev/null | sort | sed -n '1,20p'
echo "## tools not root-owned or group/other-writable (must stay empty)"
find "$T" ! -type l \( ! -user root -o -perm +022 \) -print 2>/dev/null | sort | sed -n '1,20p'
MANIFEST_EOF
}

write_hooks() {
  with_render install_file "$SUPPORT/hooks/job-started.sh" root:wheel 0755 - <<'STARTED_EOF'
#!/bin/bash
# job-started.sh: runner job-started hook for __CI_USER__ on the CI host (ACTIONS_RUNNER_HOOK_JOB_STARTED in the
# root-owned runner .env). Root-owned and read-only to __CI_USER__. Runs as __CI_USER__ before the job's steps and
# re-executes itself with a clean environment; any failed check fails the job before repository code runs.
set -euo pipefail
readonly CI_UID=__CI_UID__ CI_USER=__CI_USER__
readonly H=__CI_HOME__
readonly SUPPORT=__SUPPORT__
readonly RUNNER_DIR=__VOL_MOUNT__/runner/actions-runner
readonly RUNNER_LABEL=__RUNNER_LABEL__
readonly RUNNER_PLIST=__RUNNER_PLIST__
guard_fail() { printf '::error title=__CI_USER__ host guard::%s\n' "$*"; exit 1; }
has() { grep "$@" >/dev/null; }   # grep to the end of input: no SIGPIPE upstream under pipefail

# job_allowed <label> <plist path> <program>: Apple job definitions (on the sealed system volume or in
# /Library/Apple), Apple GUI applications, and the runner itself. Everything else, including any job a process
# submitted (launchctl submit, SMAppService), is refused whatever its label says.
job_allowed() {
  case "$1" in com.apple.xpc.launchd.unmanaged.*) return 0 ;; esac   # plain processes: checked by proc_allowed
  case "$2" in
    /System/*|/Library/Apple/*) return 0 ;;
    "$RUNNER_PLIST") [ "$1" = "$RUNNER_LABEL" ] && [ "$3" = "$RUNNER_DIR/runsvc.sh" ] && return 0 ;;
    "(submitted by runningboardd."*)
      case "$1:$3" in application.*:/System/*) return 0 ;; esac ;;
  esac
  return 1
}

# exe_allowed <executable>: what a clean __CI_USER__ session may run outside the runner's process tree: Apple
# system agents and services. Interpreters and shells are never allowed there, wherever they live.
exe_allowed() {
  case "$1" in
    */Ruby.framework/*|*/Python.framework/*|*/Python3.framework/*|*/Tcl.framework/*|*/Tk.framework/*|*/Perl/*|\
    */JavaScriptCore.framework/*/Helpers/*) return 1 ;;
    /System/*|/usr/libexec/*|/usr/sbin/*|/Library/Apple/*|/Library/Developer/PrivateFrameworks/*|\
    /Library/Developer/CoreSimulator/*|/usr/bin/ssh-agent) return 0 ;;
    /Applications/Xcode.app/*/XPCServices/*) return 0 ;;
  esac
  return 1
}

# session_check <uid>: launchd environment, launchd jobs and processes of __CI_USER__'s GUI session.
session_check() {
  local uid=$1 out k l info path prog bad="" rpid tree changed pid ppid exe exes ps_list
  out=$(launchctl print "gui/$uid" 2>/dev/null) || guard_fail "no GUI (Aqua) launchd domain for uid $uid"
  for k in $(printf '%s\n' "$out" | awk '/^\tenvironment = \{/ {f=1; next} f && /^\t\}/ {f=0} f {print $1}'); do
    [ "$k" = SSH_AUTH_SOCK ] || bad="$bad env:$k"
  done
  for k in BASH_ENV ENV ZDOTDIR PATH DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH DYLD_FRAMEWORK_PATH; do
    [ -z "$(launchctl getenv "$k" 2>/dev/null)" ] || bad="$bad getenv:$k"
  done
  for l in $(printf '%s\n' "$out" | awk '/^\tservices = \{/ {f=1; next} f && /^\t\}/ {f=0} f {print $NF}'); do
    info=$(launchctl print "gui/$uid/$l" 2>/dev/null) || continue
    path=$(printf '%s\n' "$info" | awk -F' = ' '/^\tpath = / && !seen++ {print $2}')
    prog=$(printf '%s\n' "$info" | awk -F' = ' '/^\tprogram = / && !seen++ {print $2}')
    job_allowed "$l" "$path" "$prog" || bad="$bad job:${l}[${path}|${prog}]"
  done
  rpid=$(launchctl print "gui/$uid/$RUNNER_LABEL" 2>/dev/null | awk '$1 == "pid" && !seen++ {print $3}')
  [ -n "$rpid" ] || guard_fail "the runner LaunchAgent reports no pid"
  ps_list=$(ps -U "$uid" -o pid=,ppid=) || guard_fail "cannot list __CI_USER__ processes"
  # The runner's tree, plus this hook's own process (its ps/lsof/awk children): when root's qualify.sh runs the hook
  # outside a job, the hook is not a descendant of the runner but is still root-owned code.
  tree=" $rpid $$ "; changed=1
  while [ "$changed" = 1 ]; do
    changed=0
    while read -r pid ppid; do
      case "$tree" in
        *" $pid "*) ;;
        *" $ppid "*) tree="$tree$pid "; changed=1 ;;
      esac
    done <<<"$ps_list"
  done
  exes=$({ lsof -a -u "$CI_USER" -d txt -Fpn 2>/dev/null || true; } | awk '/^p/ {p = substr($0, 2); first = 1; next} /^n/ && first {print p " " substr($0, 2); first = 0}')
  while read -r pid ppid; do
    case "$tree" in *" $pid "*) ;; *)
      exe=$(printf '%s\n' "$exes" | awk -v p="$pid" '$1 == p && !seen++ {sub(/^[0-9]+ /, ""); print}')
      if [ -z "$exe" ]; then
        if kill -0 "$pid" 2>/dev/null; then bad="$bad proc:${pid}[unknown executable]"; fi
      elif ! exe_allowed "$exe"; then
        bad="$bad proc:${pid}[${exe}]"
      fi ;;
    esac
  done <<<"$ps_list"
  [ -z "$bad" ] || guard_fail "unexpected state in __CI_USER__'s session:$bad"
}

main() {
  if [ "${CI_HOOK_CLEAN:-}" != 1 ]; then
    exec /usr/bin/env -i CI_HOOK_CLEAN=1 PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C \
      HOME="${HOME:-}" DEVELOPER_DIR="${DEVELOPER_DIR:-}" /bin/bash --noprofile --norc "$0"
  fi
  local g want have vol_free_k data_free_k t now
  [ "$(id -u)" = "$CI_UID" ] && [ "$(id -un)" = "$CI_USER" ] || guard_fail "unexpected identity $(id -un) ($(id -u))"
  [ "${HOME:-}" = "$H" ] || guard_fail "unexpected HOME ${HOME:-unset}"
  for g in $(id -Gn); do
    case "$g" in
      admin|staff|wheel|_developer|com.apple.access_ssh|com.apple.access_screensharing) guard_fail "__CI_USER__ is in group $g" ;;
    esac
  done
  want=$(cat "$SUPPORT/etc/volume-uuid")
  have=$(diskutil info -plist __VOL_MOUNT__ 2>/dev/null | plutil -extract VolumeUUID raw -o - - 2>/dev/null || true)
  [ -n "$want" ] && [ "$have" = "$want" ] || guard_fail "__VOL_MOUNT__ is not the recorded __VOL_NAME__ volume"
  if mount | grep -F " on __VOL_MOUNT__ (" | has noowners; then guard_fail "__VOL_NAME__ ignores ownership"; fi
  [ "${DEVELOPER_DIR:-}" = /Applications/Xcode.app/Contents/Developer ] || guard_fail "DEVELOPER_DIR is not pinned"
  [ "$(stat -f %Su /Applications/Xcode.app)" = root ] || guard_fail "Xcode.app is not root-owned"

  # Network guard canary. Non-root cannot read pf, so probe it: sshd listens on *:22 and Tailscale answers on
  # 100.100.100.100:53 for every other user. A connect that succeeds here means the per-user block is off.
  # Limitation: if Remote Login and Tailscale are both off, these probes cannot tell.
  for t in "127.0.0.1 22" "100.100.100.100 53"; do
    set -- $t
    if nc -4 -z -G 2 "$1" "$2" >/dev/null 2>&1; then guard_fail "network guard inactive: $1:$2 reachable as __CI_USER__"; fi
  done
  if nc -6 -z -G 2 ::1 22 >/dev/null 2>&1; then guard_fail "network guard inactive: [::1]:22 reachable as __CI_USER__"; fi

  vol_free_k=$(df -k __VOL_MOUNT__ | awk 'NR == 2 {print $4}')
  data_free_k=$(df -k /System/Volumes/Data | awk 'NR == 2 {print $4}')
  [ "$vol_free_k" -ge 15728640 ] || guard_fail "__VOL_NAME__ has less than 15 GiB free ($((vol_free_k / 1048576)) GiB)"
  [ "$data_free_k" -ge 41943040 ] || guard_fail "the Data volume has less than 40 GiB free ($((data_free_k / 1048576)) GiB)"

  session_check "$CI_UID"

  [ -s "$SUPPORT/baseline/manifest" ] || guard_fail "no recorded baseline"
  now=$("$SUPPORT/libexec/ci-manifest") || guard_fail "ci-manifest failed"
  if ! printf '%s\n' "$now" | diff -u "$SUPPORT/baseline/manifest" -; then
    guard_fail "persistence baseline changed (diff above): treat as suspected compromise, rebuild or re-baseline after review"
  fi
  echo "__CI_USER__ host guard: ok"
}
if [ "${BASH_SOURCE[0]:-$0}" = "$0" ]; then main "$@"; fi
STARTED_EOF

  with_render install_file "$SUPPORT/hooks/job-completed.sh" root:wheel 0755 - <<'COMPLETED_EOF'
#!/bin/bash
# job-completed.sh: runner job-completed hook for __CI_USER__ on the CI host (ACTIONS_RUNNER_HOOK_JOB_COMPLETED).
# Root-owned and read-only to __CI_USER__. Runs as __CI_USER__ after the job, re-executed with a clean environment.
# Every path is fixed; no symlink is followed; a failed cleanup fails the job visibly.
set -uo pipefail
readonly H=__CI_HOME__
readonly WORK=__CI_HOME__/work
rc=0
warn() { printf '::warning title=__CI_USER__ cleanup::%s\n' "$*"; rc=1; }

# wipe_dir <dir>: delete the contents of a real directory without following symlinks or crossing file systems.
wipe_dir() {
  local d=$1
  [ -e "$d" ] || return 0
  if [ -L "$d" ] || [ ! -d "$d" ]; then warn "$d is not a plain directory; left alone"; return 0; fi
  find -x "$d" -mindepth 1 -delete 2>/dev/null || warn "could not empty $d"
}

main() {
  if [ "${CI_HOOK_CLEAN:-}" != 1 ]; then
    exec /usr/bin/env -i CI_HOOK_CLEAN=1 PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C \
      HOME="${HOME:-}" DEVELOPER_DIR="${DEVELOPER_DIR:-}" GITHUB_WORKSPACE="${GITHUB_WORKSPACE:-}" \
      GITHUB_REPOSITORY="${GITHUB_REPOSITORY:-}" GITHUB_RUN_ID="${GITHUB_RUN_ID:-}" GITHUB_JOB="${GITHUB_JOB:-}" \
      /bin/bash --noprofile --norc "$0"
  fi
  local ws real d p shared_k=0 sz vol_used_k data_free_k ut uc
  [ "$(id -u)" = __CI_UID__ ] || { echo "::error::job-completed hook running as $(id -un)"; exit 1; }

  xcrun simctl shutdown all >/dev/null 2>&1 || true
  xcrun simctl erase all >/dev/null 2>&1 || warn "simctl erase all failed"

  # The job workspace is removed entirely, so nothing a job leaves behind (.git/config, hooks, build products) is
  # inherited by the next job. Only a real directory at least two levels below the work root.
  ws=${GITHUB_WORKSPACE:-}
  if [ -n "$ws" ] && [ -e "$ws" ]; then
    if [ -L "$ws" ]; then
      rm -f "$ws" || warn "could not remove workspace symlink $ws"
    elif [ -d "$ws" ]; then
      real=$(cd "$ws" && pwd -P)
      case "$real" in
        "$WORK"/?*/?*) rm -rf "$real" || warn "could not remove workspace $real" ;;
        *) warn "workspace $real is outside $WORK; left alone" ;;
      esac
    fi
  fi
  wipe_dir "$WORK/_actions"
  wipe_dir "$WORK/_tool"
  wipe_dir "$H/tmp"
  wipe_dir "$H/Library/Developer/Xcode/DerivedData"

  # Files __CI_USER__ left in the shared temp and shared directories of the Data volume (not bounded by the quota).
  for d in /private/tmp /private/var/tmp /Users/Shared; do
    while IFS= read -r p; do
      if [ -n "$p" ]; then
        sz=$(du -sk "$p" 2>/dev/null | cut -f1); shared_k=$((shared_k + ${sz:-0}))
        rm -rf "$p" || warn "could not remove $p"
      fi
    done <<<"$(find -x "$d" -mindepth 1 -maxdepth 1 -user __CI_USER__ ! -name 'com.apple.*' 2>/dev/null)"
  done

  if [ -f "$H/Library/Keychains/login.keychain-db" ]; then
    security list-keychains -d user -s "$H/Library/Keychains/login.keychain-db" >/dev/null 2>&1 || warn "keychain list reset failed"
    security default-keychain -d user -s "$H/Library/Keychains/login.keychain-db" >/dev/null 2>&1 || true
  fi

  mkdir -p "$H/ci-logs"
  vol_used_k=$(df -k __VOL_MOUNT__ | awk 'NR == 2 {print $3}')
  data_free_k=$(df -k /System/Volumes/Data | awk 'NR == 2 {print $4}')
  ut=$(du -sk "$(getconf DARWIN_USER_TEMP_DIR)" 2>/dev/null | awk '{print $1}')
  uc=$(du -sk "$(getconf DARWIN_USER_CACHE_DIR)" 2>/dev/null | awk '{print $1}')
  printf '%s\t%s\t%s\t%s\tvol_used_k=%s\tdata_free_k=%s\tuser_tmp_k=%s\tuser_cache_k=%s\tshared_removed_k=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${GITHUB_REPOSITORY:-}" "${GITHUB_RUN_ID:-}" "${GITHUB_JOB:-}" \
    "$vol_used_k" "$data_free_k" "${ut:-?}" "${uc:-?}" "$shared_k" >>"$H/ci-logs/usage.tsv"
  exit "$rc"
}
if [ "${BASH_SOURCE[0]:-$0}" = "$0" ]; then main "$@"; fi
COMPLETED_EOF
}

write_pf_files() {
  with_render install_file "$PF_CI_FILE" root:wheel 0644 - <<'PF_CI_EOF'
# __LABEL_PREFIX__: pf rules for the __CI_USER__ CI user (uid __CI_UID__) on the CI host.
# Loaded into com.apple/250.__PF_ANCHOR_NAME__ by __SUPPORT__/sbin/pf-assert (LaunchDaemon __LABEL_PREFIX__.pf)
# at boot, before any login, and re-asserted every 30 seconds.
# __CI_USER__ may open TCP/UDP connections to the public IPv4 Internet only. Refused: loopback (the owner's localhost
# services), LAN, tailnet (100.64.0.0/10), link-local, multicast, broadcast and reserved ranges, and all IPv6.
# Inbound connections to sockets owned by __CI_USER__ are dropped.
# pf "user" matching applies to TCP and UDP sockets only. DNS is resolved by mDNSResponder (another uid).
table <ci_block4> const { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/4, 240.0.0.0/4 }
block return out log quick inet proto { tcp udp } from any to <ci_block4> user __CI_UID__
block return out log quick inet6 proto { tcp udp } all user __CI_UID__
# Allowed egress creates state, so reply packets match that state and never reach the inbound block below.
# pf associates every packet of a connection with the socket owner, so without state the replies would match it.
pass out quick inet proto tcp all user __CI_UID__ flags S/SA keep state
pass out quick inet proto udp all user __CI_UID__ keep state
block drop in log quick proto { tcp udp } all user __CI_UID__
PF_CI_EOF

  with_render install_file "$PF_SS_FILE" root:wheel 0644 - <<'PF_SS_EOF'
# __LABEL_PREFIX__.screensharing: Screen Sharing (VNC, port 5900) answers only on loopback, so it is
# reachable only through an SSH tunnel: ssh -N -L 5901:127.0.0.1:5900 <host>, then vnc://localhost:5901.
# Loaded into com.apple/251.__PF_ANCHOR_NAME__ScreenSharing by the same LaunchDaemon. __CI_USER__ cannot reach loopback at all.
block drop in log quick on ! lo0 proto { tcp udp } from any to any port 5900
PF_SS_EOF

  with_render install_file "$SUPPORT/sbin/pf-assert" root:wheel 0755 - <<'PF_ASSERT_EOF'
#!/bin/bash
# pf-assert: keeps the __CI_USER__ pf anchors loaded and pf enabled, and guards the Data volume. Run as root by the
# LaunchDaemon __LABEL_PREFIX__.pf at boot (before any login) and every 30 s. Never flushes or replaces a
# ruleset it does not own: /etc/pf.conf is loaded only into an empty main ruleset. Logs changes and errors only.
set -uo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C
readonly LOG=/var/log/__LABEL_PREFIX__.pf.log
readonly TOKEN_FILE=/var/run/__LABEL_PREFIX__.pf.token
readonly STATE_FILE=/var/run/__LABEL_PREFIX__.pf.state
readonly FLAGS=/var/run/__LABEL_PREFIX__.flags
readonly PAIRS="com.apple/250.__PF_ANCHOR_NAME__=/etc/pf.anchors/__LABEL_PREFIX__ com.apple/251.__PF_ANCHOR_NAME__ScreenSharing=/etc/pf.anchors/__LABEL_PREFIX__.screensharing"
readonly CI_UID=__CI_UID__ RUNNER_LABEL=__RUNNER_LABEL__
readonly DATA_FLOOR_K=26214400                    # 25 GiB
readonly VOL_UUID_FILE=__SUPPORT__/etc/volume-uuid
log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >>"$LOG"; }
has() { grep "$@" >/dev/null; }   # grep to the end of input: no SIGPIPE upstream under pipefail
# cond <name> <on|off> <message>: log a condition when it starts and when it clears, not every 30 s.
cond() {
  local f="$FLAGS/$1"
  if [ "$2" = on ]; then [ -e "$f" ] || { : >"$f"; log "$3"; }
  else [ ! -e "$f" ] || { rm -f "$f"; log "cleared: $1"; }; fi
}
enabled() { pfctl -s info 2>/dev/null | has '^Status: Enabled'; }
# readback <anchor>: the rules and table contents pf holds for the anchor.
readback() {
  local t
  pfctl -a "$1" -s rules 2>/dev/null
  for t in $(pfctl -a "$1" -s Tables 2>/dev/null); do echo "table $t"; pfctl -a "$1" -t "$t" -T show 2>/dev/null; done
}
[ -d "$FLAGS" ] || mkdir -m 0700 "$FLAGS"
rc=0

# 1. Apple's main ruleset must carry the com.apple/* anchor point. Load /etc/pf.conf only into an EMPTY main
#    ruleset; a non-empty one without the hook belongs to another component and is left alone.
main_rules=$({ pfctl -s rules 2>/dev/null; pfctl -s nat 2>/dev/null; } | tr -d '\r')
if ! printf '%s\n' "$main_rules" | has -E '^anchor "com\.apple/\*"'; then
  if [ -z "$(printf '%s' "$main_rules" | tr -d '[:space:]')" ]; then
    if pfctl -q -f /etc/pf.conf 2>>"$LOG"; then log "loaded /etc/pf.conf into the empty main ruleset"
    else log "ERROR: pfctl -f /etc/pf.conf failed"; rc=1; fi
  else
    cond main-foreign on "ERROR: the main pf ruleset is not empty and lacks the com.apple/* anchor point; another component owns it. Nothing changed; __CI_USER__ jobs fail closed at the start-hook canary"
    exit 1
  fi
fi
cond main-foreign off ""

# 2. Our anchors: reload when the file content or what pf holds differs from what was last loaded.
for pair in $PAIRS; do
  a=${pair%%=*}; f=${pair#*=}
  if [ ! -f "$f" ]; then log "ERROR: $f is missing"; rc=1; continue; fi
  fh=$(shasum -a 256 "$f" | cut -d' ' -f1)
  rh=$(readback "$a" | shasum -a 256 | cut -d' ' -f1)
  rec=$(awk -v a="$a" '$1 == a {print $2 " " $3}' "$STATE_FILE" 2>/dev/null)
  if [ "$rec" != "$fh $rh" ]; then
    if pfctl -q -a "$a" -f "$f" 2>>"$LOG"; then
      rh=$(readback "$a" | shasum -a 256 | cut -d' ' -f1)
      { awk -v a="$a" '$1 != a' "$STATE_FILE" 2>/dev/null; echo "$a $fh $rh"; } >"$STATE_FILE.tmp" && mv -f "$STATE_FILE.tmp" "$STATE_FILE"
      log "loaded $f into $a (file sha256 $fh)"
    else log "ERROR: loading $f into $a failed"; rc=1; fi
  fi
done

# 3. Hold our own enable reference (pfctl -E), so pf stays enabled when other components release theirs.
#    /var/run is cleared at boot, so the first run after boot always takes one.
if ! enabled || [ ! -s "$TOKEN_FILE" ]; then
  out=$(pfctl -E 2>&1); tok=$(printf '%s\n' "$out" | awk -F': *' '/^Token/ && !seen++ {print $2}')
  if enabled; then printf '%s\n' "${tok:-unknown}" >"$TOKEN_FILE"; log "pf enable reference taken (token ${tok:-unknown})"
  else log "ERROR: pf not enabled after pfctl -E: $out"; rc=1; fi
fi

# 4. Disk guard: the quota bounds __CI_USER__'s home, not /tmp, /Users/Shared or /var/folders on the Data volume.
data_free_k=$(df -k /System/Volumes/Data | awk 'NR == 2 {print $4}')
if [ "${data_free_k:-0}" -lt "$DATA_FLOOR_K" ]; then
  if launchctl print "gui/$CI_UID/$RUNNER_LABEL" >/dev/null 2>&1; then
    launchctl bootout "gui/$CI_UID/$RUNNER_LABEL" 2>>"$LOG" && log "disk guard: runner booted out ($((data_free_k / 1048576)) GiB free on Data)"
  fi
  cond disk-low on "ERROR: the Data volume has less than 25 GiB free ($((data_free_k / 1048576)) GiB); the runner stays off"
else
  cond disk-low off ""
fi

# 5. Volume guard: a stray __VOL_MOUNT__ (__CI_USER__ logged in before the unlock) or a second mount.
want=$(cat "$VOL_UUID_FILE" 2>/dev/null || true)
if [ -e "__VOL_MOUNT__ 1" ]; then
  cond vol-mismatch on "ERROR: '__VOL_MOUNT__ 1' exists: the volume mounted beside a stray __VOL_MOUNT__"
elif [ -e __VOL_MOUNT__ ] && [ -n "$want" ] && \
     [ "$(diskutil info -plist __VOL_MOUNT__ 2>/dev/null | plutil -extract VolumeUUID raw -o - - 2>/dev/null)" != "$want" ]; then
  cond vol-mismatch on "ERROR: __VOL_MOUNT__ is not the __VOL_NAME__ volume (stray directory on the Data volume?)"
else
  cond vol-mismatch off ""
fi
exit "$rc"
PF_ASSERT_EOF

  with_render install_file "$SUPPORT/sbin/pf-deadman" root:wheel 0755 - <<'PF_DEADMAN_EOF'
#!/bin/bash
# pf-deadman: rolls back the __CI_USER__ pf guard unless the owner confirms it (host-prep.sh confirm-pf) before the
# recorded deadline. Run as root by the LaunchDaemon __LABEL_PREFIX__.pf-deadman (RunAtLoad), so it survives a
# dropped SSH session, and at boot it rolls back at once if the deadline passed without a confirmation.
set -uo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C
readonly R=__SUPPORT__
readonly LOG=/var/log/__LABEL_PREFIX__.pf.log
readonly DEADLINE=$R/etc/pf-deadline ARMED=$R/etc/pf-armed-hash CONFIRMED=$R/etc/pf-confirmed
readonly PF_LABEL=__LABEL_PREFIX__.pf PF_PLIST=/Library/LaunchDaemons/__LABEL_PREFIX__.pf.plist
readonly SELF_LABEL=__LABEL_PREFIX__.pf-deadman SELF_PLIST=/Library/LaunchDaemons/__LABEL_PREFIX__.pf-deadman.plist
readonly TOKEN_FILE=/var/run/__LABEL_PREFIX__.pf.token STATE_FILE=/var/run/__LABEL_PREFIX__.pf.state
log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >>"$LOG"; }
confirmed() { [ -s "$ARMED" ] && [ -s "$CONFIRMED" ] && [ "$(cut -d' ' -f1 "$CONFIRMED")" = "$(cat "$ARMED")" ]; }
disarm() { rm -f "$SELF_PLIST"; launchctl bootout "system/$SELF_LABEL" >/dev/null 2>&1; exit 0; }

while :; do
  if confirmed; then log "dead-man: pf guard confirmed; disarmed"; disarm; fi
  [ "$(date +%s)" -lt "$(cat "$DEADLINE" 2>/dev/null || echo 0)" ] || break
  sleep 5
done
log "dead-man: no confirmation before the deadline: rolling back the __CI_USER__ pf guard"
launchctl disable "system/$PF_LABEL"
launchctl bootout "system/$PF_LABEL" >/dev/null 2>&1
if [ -f "$PF_PLIST" ]; then mv -f "$PF_PLIST" "$R/backup/__LABEL_PREFIX__.pf.plist.rolled-back-$(date -u +%Y%m%dT%H%M%SZ)"; fi
for a in com.apple/250.__PF_ANCHOR_NAME__ com.apple/251.__PF_ANCHOR_NAME__ScreenSharing; do
  pfctl -a "$a" -F rules >>"$LOG" 2>&1
  pfctl -a "$a" -F Tables >>"$LOG" 2>&1
done
tok=$(cat "$TOKEN_FILE" 2>/dev/null || true)
case "$tok" in ''|unknown) log "dead-man: no enable token recorded" ;; *) pfctl -X "$tok" >>"$LOG" 2>&1 ;; esac
rm -f "$TOKEN_FILE" "$STATE_FILE"
log "dead-man: rollback done: $(pfctl -s info 2>/dev/null | head -1)"
disarm
PF_DEADMAN_EOF

  with_render install_file "$PF_PLIST" root:wheel 0644 - <<'PF_PLIST_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>__LABEL_PREFIX__.pf</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>__SUPPORT__/sbin/pf-assert</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>StartInterval</key>
  <integer>30</integer>
  <key>StandardOutPath</key>
  <string>/var/log/__LABEL_PREFIX__.pf.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/__LABEL_PREFIX__.pf.log</string>
</dict>
</plist>
PF_PLIST_EOF

  with_render install_file "$SUPPORT/etc/pf-deadman.plist.template" root:wheel 0644 - <<'DEADMAN_PLIST_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>__LABEL_PREFIX__.pf-deadman</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>__SUPPORT__/sbin/pf-deadman</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/var/log/__LABEL_PREFIX__.pf.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/__LABEL_PREFIX__.pf.log</string>
</dict>
</plist>
DEADMAN_PLIST_EOF
}

step_support_files() {
  step "root-owned CI support files: manifest, job hooks"
  write_ci_manifest
  write_hooks
}

step_firewall() {
  step "application firewall on, stealth mode on"
  if "$ALF" --getglobalstate | has -E 'State = [12]'; then ok "$("$ALF" --getglobalstate)"; else
    "$ALF" --setglobalstate on >/dev/null; chg "firewall turned on"
    "$ALF" --getglobalstate | has -E 'State = [12]' || die "firewall still off"
  fi
  if "$ALF" --getstealthmode | has -i 'stealth mode is on'; then ok "$("$ALF" --getstealthmode)"; else
    "$ALF" --setstealthmode on >/dev/null; chg "stealth mode turned on"
    "$ALF" --getstealthmode | has -i 'stealth mode is on' || die "stealth mode still off"
  fi
  info "$("$ALF" --getallowsigned | tr '\n' ' ' || true)"
}

step_sshd() {
  step "sshd: DenyUsers $CI_USER, PermitRootLogin no"
  with_render install_file "$SSHD_DROPIN" root:wheel 0644 - <<'SSHD_EOF'
# Managed by host-prep.sh (__LABEL_PREFIX__): the CI account never logs in over SSH, and neither does root.
DenyUsers __CI_USER__
PermitRootLogin no
SSHD_EOF
  if ! sshd -t >/dev/null 2>&1; then
    rm -f "$SSHD_DROPIN"
    die "sshd -t rejected the configuration; $SSHD_DROPIN was removed again so new SSH logins keep working"
  fi
  local deny root
  deny=$(sshd_value DenyUsers)
  root=$(sshd_value PermitRootLogin)
  [ "$deny" = "$CI_USER" ] || die "sshd -T reports denyusers '$deny', expected '$CI_USER'"
  [ "$root" = no ] || die "sshd -T reports permitrootlogin '$root', expected 'no'"
  ok "sshd -t ok; effective denyusers $deny, permitrootlogin $root ($OWNER_USER unaffected)"
}

launchd_override() { launchctl print-disabled system 2>/dev/null | awk -F'=> ' -v l="\"$1\"" 'index($0, l) {print $2}' | tr -d ' '; }

step_smb() {
  step "File Sharing (SMB) off"
  local st; st=$(launchd_override com.apple.smbd)
  case "$st" in disabled|true) ok "com.apple.smbd launchd override: $st" ;;
    *) launchctl disable system/com.apple.smbd; chg "com.apple.smbd disabled (was: ${st:-unset})" ;; esac
  if launchctl print system/com.apple.smbd >/dev/null 2>&1; then
    launchctl bootout system/com.apple.smbd 2>/dev/null || true
    chg "com.apple.smbd booted out"
  fi
  sleep 1
  if lsof -nP -iTCP:445 -sTCP:LISTEN >/dev/null 2>&1; then
    die "port 445 still listens; turn off System Settings > General > Sharing > File Sharing, then re-run"
  fi
  ok "nothing listens on TCP 445; override now: $(launchd_override com.apple.smbd)"
}

step_screensharing() {
  step "Screen Sharing: kept for the owner, loopback-only (pf, in the pf step), no stored VNC password, not for $CI_USER"
  info "com.apple.screensharing launchd override: $(launchd_override com.apple.screensharing)"
  local out; out=$(dsmemberutil checkmembership -U "$CI_USER" -G com.apple.access_screensharing 2>&1 || true)
  case "$out" in *"is not a member"*) ok "$CI_USER may not authenticate to Screen Sharing" ;; *) die "Screen Sharing access for $CI_USER: $out" ;; esac
  if [ -e "$VNC_LEGACY" ]; then
    local dst; dst="$SUPPORT/backup/com.apple.VNCSettings.txt.$(date -u +%Y%m%dT%H%M%SZ)"
    mv "$VNC_LEGACY" "$dst"; chown root:wheel "$dst"; chmod 0400 "$dst"
    chg "stored legacy VNC password removed from /Library/Preferences ($VNC_LEGACY moved to $dst, root-only)"
  fi
  [ ! -e "$VNC_LEGACY" ] || die "$VNC_LEGACY still present"
  ok "no stored legacy VNC password; qualify.sh remote checks the offered auth types"
}

su_bool() {
  local key=$1 want=$2 cur
  cur=$(defaults read "$SU_PREFS" "$key" 2>/dev/null || echo unset)
  if [ "$cur" = "$want" ]; then ok "$key = $cur"; else
    if [ "$want" = 1 ]; then defaults write "$SU_PREFS" "$key" -bool true; else defaults write "$SU_PREFS" "$key" -bool false; fi
    chg "$key $cur -> $(defaults read "$SU_PREFS" "$key")"
    [ "$(defaults read "$SU_PREFS" "$key")" = "$want" ] || die "$key did not become $want"
  fi
}

step_updates() {
  step "software updates: check and download automatically, install macOS updates manually, security responses automatic"
  su_bool AutomaticCheckEnabled 1
  su_bool AutomaticDownload 1
  su_bool AutomaticallyInstallMacOSUpdates 0
  su_bool CriticalUpdateInstall 1
  su_bool ConfigDataInstall 1
  info "$(softwareupdate --schedule 2>/dev/null | head -1 || true)"
}

step_power() {
  step "power: never sleep on AC, independent of any keep-awake tool"
  local cur; cur=$(pmset -g custom | awk '/^AC Power:/ {f=1; next} /^[A-Za-z].*:$/ {f=0} f && $1 == "sleep" {print $2}')
  if [ "$cur" = 0 ]; then ok "AC sleep 0"; else
    pmset -c sleep 0; chg "AC sleep $cur -> 0"
    cur=$(pmset -g custom | awk '/^AC Power:/ {f=1; next} /^[A-Za-z].*:$/ {f=0} f && $1 == "sleep" {print $2}')
    [ "$cur" = 0 ] || die "AC sleep is $cur after pmset -c sleep 0"
  fi
  info "SleepDisabled $(pmset -g | awk '/SleepDisabled/ {print $2}' || true) (system-wide); keep the lid open and ventilated"
}

# disable_ci_session_agents <strict>: third-party LaunchAgents in /Library/LaunchAgents start in every Aqua session,
# including $CI_USER's. Disables them in gui/${CI_UID} only (the owner's session untouched). strict=1 dies on failure.
disable_ci_session_agents() {
  local strict=$1 p l
  for p in /Library/LaunchAgents/*.plist; do
    [ -f "$p" ] || continue
    l=$(plutil -extract Label raw -o - "$p" 2>/dev/null || true)
    case "$l" in ""|com.apple.*) continue ;; esac
    if launchctl print-disabled "gui/$CI_UID" 2>/dev/null | has -F "\"$l\" => disabled"; then
      ok "$l disabled for gui/$CI_UID"
    elif launchctl disable "gui/$CI_UID/$l" 2>/dev/null && launchctl print-disabled "gui/$CI_UID" 2>/dev/null | has -F "\"$l\" => disabled"; then
      chg "$l disabled for gui/$CI_UID"
    else
      [ "$strict" = 1 ] && die "could not disable $l for gui/$CI_UID"
      info "$l: gui/$CI_UID refuses the override without a session; after the next $CI_USER login run 'ci-session-agents'"
    fi
    if launchctl print "gui/$CI_UID/$l" >/dev/null 2>&1; then
      launchctl bootout "gui/$CI_UID/$l" 2>/dev/null || true
      ! launchctl print "gui/$CI_UID/$l" >/dev/null 2>&1 || die "$l still loaded in gui/$CI_UID"
      chg "$l booted out of gui/$CI_UID"
    fi
  done
  return 0
}

step_ci_session_agents() {
  step "third-party global LaunchAgents disabled for $CI_USER's session (the owner's session untouched)"
  disable_ci_session_agents 0
}

step_airplay() {
  step "AirPlay Receiver off in the owner's session"
  local cur listen i
  if launchctl print "gui/$OWNER_UID" >/dev/null 2>&1; then
    cur=$(launchctl asuser "$OWNER_UID" sudo -u "$OWNER_USER" defaults -currentHost read com.apple.controlcenter AirplayRecieverEnabled 2>/dev/null || echo unset)
    if [ "$cur" != 0 ]; then
      launchctl asuser "$OWNER_UID" sudo -u "$OWNER_USER" defaults -currentHost write com.apple.controlcenter AirplayRecieverEnabled -bool false
      chg "AirplayRecieverEnabled $cur -> 0 (the owner's ByHost preferences)"
    else
      ok "AirplayRecieverEnabled = 0"
    fi
    listen=$(lsof -nP -a -u "$OWNER_USER" -iTCP -sTCP:LISTEN 2>/dev/null | grep -E ':(5000|7000) \(LISTEN\)' || true)
    if [ -n "$listen" ]; then
      launchctl kickstart -k "gui/$OWNER_UID/com.apple.controlcenter" >/dev/null 2>&1 || true
      chg "ControlCenter restarted in the owner's session"
      sleep 5
    fi
  else
    cur=$(sudo -u "$OWNER_USER" defaults -currentHost read com.apple.controlcenter AirplayRecieverEnabled 2>/dev/null || echo unset)
    [ "$cur" = 0 ] || { sudo -u "$OWNER_USER" defaults -currentHost write com.apple.controlcenter AirplayRecieverEnabled -bool false; chg "AirplayRecieverEnabled -> 0 (no GUI session; applies at next login)"; }
  fi
  for i in 1 2; do
    listen=$(lsof -nP -a -u "$OWNER_USER" -iTCP -sTCP:LISTEN 2>/dev/null | grep -E ':(5000|7000) \(LISTEN\)' || true)
    [ -z "$listen" ] || die "the owner's session still listens on 5000/7000: turn off System Settings > General > AirDrop & Handoff > AirPlay Receiver, then re-run"
    [ "$i" = 2 ] || sleep 5
  done
  ok "no AirPlay Receiver listener (TCP 5000/7000) in the owner's session"
}

# ---------------------------------------------------------------------------------------------------------------
# pf: pre-state check, files, dead-man switch, load, enable, functional proof. The last host step.
# ---------------------------------------------------------------------------------------------------------------
arm_deadman() {
  local hash=$1 deadline
  deadline=$(( $(date +%s) + PF_DEADMAN_SECONDS ))
  # A confirmation belongs to one arming: an old one for the same files must not disarm the new dead-man.
  rm -f "$SUPPORT/etc/pf-confirmed"
  printf '%s\n' "$hash" | install_file "$SUPPORT/etc/pf-armed-hash" root:wheel 0644 -
  printf '%s\n' "$deadline" | install_file "$SUPPORT/etc/pf-deadline" root:wheel 0644 -
  launchctl bootout "system/$DEADMAN_LABEL" >/dev/null 2>&1 || true
  install_file "$DEADMAN_PLIST" root:wheel 0644 - <"$SUPPORT/etc/pf-deadman.plist.template"
  plutil -lint "$DEADMAN_PLIST" >/dev/null || die "$DEADMAN_PLIST is not a valid plist"
  launchctl bootstrap system "$DEADMAN_PLIST"
  sleep 1
  launchctl print "system/$DEADMAN_LABEL" 2>/dev/null | has 'state = running' || die "the dead-man did not start; pf was NOT enabled"
  PF_ARMED=1
  chg "dead-man armed: pf rolls back at $(date -u -r "$deadline" +%H:%M:%SZ) unless confirm-pf runs from a fresh SSH login"
}

step_pf() {
  step "pf: pre-state, per-user guard for $CI_USER, loopback-only Screen Sharing, dead-man switch"
  local ts dump foreign f i cur t host port code
  ts=$(date -u +%Y%m%dT%H%M%SZ)
  dump=$(pf_state_dump)
  printf '%s\n' "$dump" | install_file "$SUPPORT/etc/pf-prestate-$ts.txt" root:wheel 0600 -
  info "before any change: $(pfctl -s info 2>/dev/null | head -1 | sed 's/  */ /g' || true)"
  info "enable references before: $(pfctl -s References 2>/dev/null | sed -n '2,$p' | wc -l | tr -d ' ' || true)"
  foreign=$(pf_foreign_report)
  if [ -n "$foreign" ]; then
    printf '%s\n' "$foreign" | sed 's/^/   foreign  /'
    die "pf holds rules or base files this script did not write (above; full dump $SUPPORT/etc/pf-prestate-$ts.txt). Enabling pf could activate them. Nothing in pf was changed; decide with the operator"
  fi
  ok "pf state is stock macOS (plus, at most, this script's own anchors); dump: $SUPPORT/etc/pf-prestate-$ts.txt"

  write_pf_files
  for f in "$PF_CI_FILE" "$PF_SS_FILE"; do
    pfctl -n -f "$f" >/dev/null 2>&1 || die "pf syntax check failed for $f"
    ok "pf syntax ok: $f ($(pf_want "$f") rules)"
  done
  plutil -lint "$PF_PLIST" >/dev/null || die "$PF_PLIST is not a valid plist"
  plutil -lint "$SUPPORT/etc/pf-deadman.plist.template" >/dev/null || die "$SUPPORT/etc/pf-deadman.plist.template is not a valid plist"

  cur=$(pf_config_hash)
  if [ -s "$SUPPORT/etc/pf-confirmed" ] && [ "$(cut -d' ' -f1 "$SUPPORT/etc/pf-confirmed")" = "$cur" ] \
     && launchctl print "system/$PF_LABEL" >/dev/null 2>&1 && pf_ready; then
    ok "pf configuration unchanged since the owner confirmed it ($(cut -d' ' -f2- "$SUPPORT/etc/pf-confirmed")); no dead-man needed"
    return 0
  fi
  arm_deadman "$cur"

  # Load both anchors explicitly (atomic replace), then let the loader record them and take the enable reference.
  pfctl -q -a "$PF_CI_ANCHOR" -f "$PF_CI_FILE"
  pfctl -q -a "$PF_SS_ANCHOR" -f "$PF_SS_FILE"
  rm -f "$PF_STATE_FILE"
  launchctl enable "system/$PF_LABEL"
  launchctl bootout "system/$PF_LABEL" >/dev/null 2>&1 || true
  launchctl bootstrap system "$PF_PLIST"
  chg "LaunchDaemon $PF_LABEL bootstrapped (RunAtLoad, every 30 s)"
  for i in $(seq 1 30); do pf_ready && break; sleep 1; done
  pf_ready || die "pf not ready after 30 s; see $PF_LOG and pfctl -s info"
  ok "$(pfctl -s info 2>/dev/null | head -1 | sed 's/  */ /g' || true)"
  ok "enable token held: $(cat "$PF_TOKEN_FILE")"
  pfctl -a "$PF_CI_ANCHOR" -s rules 2>/dev/null | sed 's/^/   rule     /' || true
  pfctl -a "$PF_SS_ANCHOR" -s rules 2>/dev/null | sed 's/^/   rule     /' || true

  # Functional proof. Each forbidden probe is paired with the same probe as the owner account, which must succeed;
  # otherwise the block cannot be told apart from "nothing listens there".
  for t in "127.0.0.1 22" "::1 22" "100.100.100.100 53"; do
    set -- $t; host=$1; port=$2
    if ! probe_as "$OWNER_USER" "$host" "$port"; then
      if [ "$host" = 100.100.100.100 ]; then
        info "tailnet probe SKIPPED: $OWNER_USER cannot reach $host:$port (Tailscale down?); the table still lists 100.64.0.0/10"
        continue
      fi
      die "control failed: $OWNER_USER cannot reach $host:$port, so the $CI_USER block cannot be proven"
    fi
    if probe_as "$CI_USER" "$host" "$port"; then die "$CI_USER can reach $host:$port: the pf guard does not work"; fi
    ok "$host:$port reachable as $OWNER_USER (control), refused for $CI_USER"
  done
  code=$(sudo -u "$CI_USER" -H /usr/bin/env -i PATH=/usr/bin:/bin curl -sS -o /dev/null -m 20 -w '%{http_code}' https://github.com 2>/dev/null || true)
  [ "$code" = 200 ] || die "$CI_USER cannot reach https://github.com (HTTP '$code'): the guard blocks too much"
  ok "https://github.com reachable for $CI_USER (HTTP 200)"
}

host_summary() {
  local uuid; uuid=$(cat "$SUPPORT/etc/volume-uuid")
  step "host preparation complete"
  if [ "$PF_ARMED" = 1 ]; then
    cat <<SUMMARY_EOF
   >>> pf is ARMED. Before $(date -u -r "$(cat "$SUPPORT/etc/pf-deadline")" +%H:%M:%SZ), open a NEW terminal on the admin workstation and run
       references/RUNBOOK.md step 4, with pin and root set as in its "Rules for every root command" (a fresh SSH login
       is the proof that pf did not cut SSH off):
         ssh -t ${ADMIN_SSH_ALIAS} "\$pin && \$root/host-prep.sh confirm-pf"
       Without it, pf rolls back by itself (even across a reboot); re-run host to arm it again.
SUMMARY_EOF
  fi
  cat <<SUMMARY_EOF
   Next: references/RUNBOOK.md (GUI session as $CI_USER), then, with $CI_USER logged out: harden-runner.
   After every reboot: FileVault unlock at the Mac, then as ${OWNER_USER} over SSH (or install the optional
   boot-time unlock, scripts/volume-unlock.sh):
       diskutil apfs unlockVolume $uuid      (prefix sudo if it reports missing rights)
   and only then log in $CI_USER. Never log $CI_USER in while the volume is locked.
   Screen Sharing from the admin workstation:  ssh -N -L 5901:127.0.0.1:5900 ${ADMIN_SSH_ALIAS}   and open vnc://localhost:5901
   Log of this run: $SETUP_LOG
SUMMARY_EOF
}

# ---------------------------------------------------------------------------------------------------------------
# confirm-pf and ci-session-agents
# ---------------------------------------------------------------------------------------------------------------
# ssh_login_epoch: start time (epoch seconds) of the nearest sshd ancestor of this process; empty without one.
# On macOS 27 the per-connection process shows as "sshd-session: <owner>@ttys001" (user) under "sshd-session: <owner> [postauth]".
ssh_login_epoch() {
  local pid=$$ comm lstart i
  for i in $(seq 1 40); do
    pid=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ' || true)
    { [ -n "$pid" ] && [ "$pid" -gt 1 ]; } || return 0
    comm=$(ps -o comm= -p "$pid" 2>/dev/null || true)
    case "${comm##*/}" in
      sshd*)
        lstart=$(ps -o lstart= -p "$pid" 2>/dev/null | tr -s ' ' | sed 's/ *$//' || true)
        date -j -f '%a %b %d %T %Y' "$lstart" +%s 2>/dev/null || true
        return 0 ;;
    esac
  done
}

mode_confirm_pf() {
  step "confirm the pf guard (from a fresh SSH login)"
  local deadline armed_at now login i
  [ -s "$SUPPORT/etc/pf-armed-hash" ] || die "no pf arming is recorded; run host first"
  launchctl print "system/$DEADMAN_LABEL" >/dev/null 2>&1 \
    || die "the dead-man is not running: it already rolled pf back (see $PF_LOG), or pf was confirmed earlier. If it rolled back, re-run host"
  deadline=$(cat "$SUPPORT/etc/pf-deadline" 2>/dev/null || echo 0)
  armed_at=$((deadline - PF_DEADMAN_SECONDS)); now=$(date +%s)
  [ "$now" -lt $((deadline - 30)) ] \
    || die "less than 30 s before the deadline (or past it): the dead-man may already be rolling back. Let it finish (see $PF_LOG), then re-run host"
  login=$(ssh_login_epoch)
  [ -n "$login" ] || die "not started from an SSH login. Run confirm-pf over a NEW ssh session from the admin workstation: that login is the proof that pf does not cut SSH off"
  [ "$login" -ge "$armed_at" ] \
    || die "this SSH login started at $(date -u -r "$login" +%H:%M:%SZ), before pf was armed at $(date -u -r "$armed_at" +%H:%M:%SZ). Open a NEW ssh session and run confirm-pf there"
  ok "fresh SSH login since $(date -u -r "$login" +%H:%M:%SZ) (pf armed at $(date -u -r "$armed_at" +%H:%M:%SZ), deadline $(date -u -r "$deadline" +%H:%M:%SZ))"
  [ "$(pf_config_hash)" = "$(cat "$SUPPORT/etc/pf-armed-hash")" ] || die "the pf files changed since arming; re-run host"
  pf_ready || die "the pf guard is not ready; see $PF_LOG"
  printf '%s %s\n' "$(cat "$SUPPORT/etc/pf-armed-hash")" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" | install_file "$SUPPORT/etc/pf-confirmed" root:wheel 0644 -
  # The dead-man sees the confirmation within 5 s and removes itself; make sure either way.
  for i in $(seq 1 15); do launchctl print "system/$DEADMAN_LABEL" >/dev/null 2>&1 || break; sleep 1; done
  launchctl bootout "system/$DEADMAN_LABEL" >/dev/null 2>&1 || true
  rm -f "$DEADMAN_PLIST"
  ! launchctl print "system/$DEADMAN_LABEL" >/dev/null 2>&1 || die "the dead-man is still loaded"
  [ ! -e "$DEADMAN_PLIST" ] || die "$DEADMAN_PLIST still present"
  # The loader must have survived: loaded, not disabled, plist in place, pf ready. Otherwise it rolled back meanwhile.
  launchctl print "system/$PF_LABEL" >/dev/null 2>&1 || die "the pf loader is not loaded (rolled back meanwhile?): re-run host"
  if launchctl print-disabled system 2>/dev/null | has -F "\"$PF_LABEL\" => disabled"; then die "the pf loader is disabled (rolled back meanwhile): re-run host"; fi
  [ -f "$PF_PLIST" ] || die "$PF_PLIST is missing (rolled back meanwhile): re-run host"
  pf_ready || die "the pf guard is not ready after the confirmation; see $PF_LOG"
  ok "pf guard confirmed and kept; dead-man disarmed and removed; loader loaded, enabled, plist present"
}

mode_ci_session_agents() {
  step "third-party global LaunchAgents off in $CI_USER's logged-in session (no file is touched)"
  launchctl print "gui/$CI_UID" >/dev/null 2>&1 || die "$CI_USER has no GUI session: log it in first"
  disable_ci_session_agents 1
}

# ---------------------------------------------------------------------------------------------------------------
# harden-runner: after references/RUNBOOK.md, $CI_USER logged out
# ---------------------------------------------------------------------------------------------------------------
# fetch_verified <url> <sha256> <dst>: download as root into the root-only stage and verify before any use.
fetch_verified() {
  local url=$1 sha=$2 dst=$3 tries=0
  until curl -fsSL --proto '=https' --tlsv1.2 -o "$dst" "$url"; do
    tries=$((tries + 1)); [ "$tries" -lt 3 ] || die "download failed: $url"
    sleep 5
  done
  printf '%s  %s\n' "$sha" "$dst" | shasum -a 256 -c - >/dev/null 2>&1 || die "SHA256 mismatch for $url; nothing was installed"
  ok "downloaded and verified $(basename "$url") (sha256 ${sha:0:16})"
}

runner_plist_content() {
  cat <<RUNNER_PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>$RUNNER_LABEL</string>
    <key>ProgramArguments</key>
    <array>
      <string>$RUNNER_DIR/runsvc.sh</string>
    </array>
    <key>UserName</key>
    <string>$CI_USER</string>
    <key>WorkingDirectory</key>
    <string>$RUNNER_DIR</string>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$CI_HOME/Library/Logs/$RUNNER_LABEL/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>$CI_HOME/Library/Logs/$RUNNER_LABEL/stderr.log</string>
    <key>EnvironmentVariables</key>
    <dict>
      <key>ACTIONS_RUNNER_SVC</key>
      <string>1</string>
    </dict>
    <key>ProcessType</key>
    <string>Interactive</string>
    <key>SessionCreate</key>
    <true/>
  </dict>
</plist>
RUNNER_PLIST_EOF
}

harden_preconditions() {
  step "harden-runner preconditions"
  dscl . read "/Users/$CI_USER" UniqueID >/dev/null 2>&1 || die "$CI_USER does not exist; run host first"
  [ "$(vol_mountpoint "$(cat "$SUPPORT/etc/volume-uuid" 2>/dev/null || echo none)")" = "$VOL_MOUNT" ] || die "$VOL_NAME is not unlocked and mounted at $VOL_MOUNT"
  [ -s "$SUPPORT/etc/pf-confirmed" ] && [ "$(cut -d' ' -f1 "$SUPPORT/etc/pf-confirmed")" = "$(pf_config_hash)" ] \
    || die "the pf guard is not confirmed for the current pf files; finish host and confirm-pf first"
  pf_ready || die "pf guard not ready; run host first"
  local f
  for f in "$SUPPORT/libexec/ci-manifest" "$SUPPORT/hooks/job-started.sh" "$SUPPORT/hooks/job-completed.sh"; do
    [ "$(lmeta "$f")" = "$(want_meta "Regular File" root:wheel 0755 -)" ] || die "$f is $(lmeta "$f"); run host first"
  done
  require_no_ci_processes
  require_no_ci_crontab
  [ "$(lmeta "$RUNNER_DIR")" = "$(want_meta Directory "root:$CI_USER" 1775 -)" ] || die "$RUNNER_DIR is $(lmeta "$RUNNER_DIR"); run host first"
  [ "$(lmeta "$RUNNER_DIR/.runner")" != missing ] || die "$RUNNER_DIR/.runner missing: run config.sh per references/RUNBOOK.md first"
  case "$(lmeta "$RUNNER_DIR/.runner")" in "Regular File|$CI_USER:"*) ;; *) die "$RUNNER_DIR/.runner is $(lmeta "$RUNNER_DIR/.runner"): suspected tampering" ;; esac
  grep -q "\"agentName\": *\"$RUNNER_NAME\"" "$RUNNER_DIR/.runner" || die "$RUNNER_DIR/.runner is not registered as $RUNNER_NAME"
  grep -q '"gitHubUrl": *"https://github.com/'"$RUNNER_ORG"'"' "$RUNNER_DIR/.runner" || die "runner is not registered to https://github.com/$RUNNER_ORG"
  ok "runner $RUNNER_NAME registered for $RUNNER_ORG"
}

harden_runner_files() {
  step "runner $RUNNER_VERSION from a root-verified download; $CI_USER's copies quarantined, never adopted"
  local work q e name
  work=$(mktemp -d "$STAGE_VOL/runner.XXXXXX")
  q="$QUARANTINE/$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -m 0700 "$q"
  QUAR_RUN=$q
  fetch_verified "$RUNNER_URL" "$RUNNER_SHA" "$work/runner.tgz"
  mkdir "$work/tree"
  tar -xzf "$work/runner.tgz" -o -C "$work/tree"
  chown -R -P root:wheel "$work/tree"; chmod -R -P go-w "$work/tree"
  [ -f "$work/tree/bin/Runner.Listener" ] && [ -f "$work/tree/bin/runsvc.sh" ] && [ -f "$work/tree/bin/darwin.svc.sh.template" ] \
    || die "the runner archive lacks bin/Runner.Listener, bin/runsvc.sh or bin/darwin.svc.sh.template"

  # Classify every entry: registration state stays with $CI_USER, everything else goes to quarantine.
  for e in "$RUNNER_DIR"/* "$RUNNER_DIR"/.[!.]* "$RUNNER_DIR"/..?*; do
    [ "$(lmeta "$e")" != missing ] || continue
    name=${e##*/}
    case " $RUNNER_STATE_NAMES " in
      *" $name "*)
        case "$(lmeta "$e")" in "Regular File|$CI_USER:"*) ok "kept state file $name ($(lmeta "$e"))" ;;
          *) die "$e is $(lmeta "$e"): a registration state file must be a regular file owned by $CI_USER (suspected tampering)" ;; esac
        continue ;;
    esac
    if [ "$name" = _diag ]; then
      case "$(lmeta "$e")" in "Directory|$CI_USER:"*) ok "kept _diag ($(lmeta "$e"))"; continue ;;
        *) die "$e is $(lmeta "$e"): _diag must be a directory owned by $CI_USER (suspected tampering)" ;; esac
    fi
    quarantine "$e" "$q"
  done
  # Install the pristine archive tree by rename, then the root-generated files.
  for e in "$work/tree"/* "$work/tree"/.[!.]*; do
    [ -e "$e" ] || continue
    rename_nofollow "$e" "$RUNNER_DIR/${e##*/}"
  done
  chg "installed runner $RUNNER_VERSION archive tree (root:wheel, not group/other-writable)"
  install_file "$RUNNER_DIR/runsvc.sh" root:wheel 0755 - <"$RUNNER_DIR/bin/runsvc.sh"
  sed -e "s/{{SvcDescription}}/GitHub Actions Runner ($RUNNER_ORG.$RUNNER_NAME)/" -e "s/{{SvcNameVar}}/$RUNNER_LABEL/" \
    "$RUNNER_DIR/bin/darwin.svc.sh.template" | install_file "$RUNNER_DIR/svc.sh" root:wheel 0755 -
  printf '%s\n' "$RUNNER_PLIST" | install_file "$RUNNER_DIR/.service" root:wheel 0644 -
  with_render install_file "$RUNNER_DIR/.env" root:wheel 0644 - <<'RUNNER_ENV_EOF'
LANG=en_US.UTF-8
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
TMPDIR=__CI_HOME__/tmp
GIT_CONFIG_NOSYSTEM=1
GIT_TERMINAL_PROMPT=0
TUIST_CONFIG_STATS_OPT_OUT=1
BASH_ENV=
ENV=
ZDOTDIR=
DYLD_INSERT_LIBRARIES=
DYLD_LIBRARY_PATH=
DYLD_FRAMEWORK_PATH=
ACTIONS_RUNNER_HOOK_JOB_STARTED=__SUPPORT__/hooks/job-started.sh
ACTIONS_RUNNER_HOOK_JOB_COMPLETED=__SUPPORT__/hooks/job-completed.sh
RUNNER_ENV_EOF
  printf '%s\n' "$TOOLS_DIR/tuist/$TUIST_VERSION:/usr/bin:/bin:/usr/sbin:/sbin" | install_file "$RUNNER_DIR/.path" root:wheel 0644 -
  rmdir "$work/tree"; rm -f "$work/runner.tgz"; rmdir "$work"

  # Readback: every entry is root-managed or a known $CI_USER state entry.
  for e in "$RUNNER_DIR"/* "$RUNNER_DIR"/.[!.]* "$RUNNER_DIR"/..?*; do
    [ "$(lmeta "$e")" != missing ] || continue
    name=${e##*/}
    case " $RUNNER_STATE_NAMES _diag " in *" $name "*) continue ;; esac
    case "$(lmeta "$e")" in "Regular File|root:wheel|"*|"Directory|root:wheel|"*) ;; *) die "$e reads back as $(lmeta "$e")" ;; esac
  done
  [ -z "$(find "$RUNNER_DIR"/bin "$RUNNER_DIR"/externals ! -type l \( ! -user root -o -perm +022 \) -print -quit)" ] \
    || die "runner binaries are writable by $CI_USER"
  [ "$(lmeta "$RUNNER_DIR")" = "$(want_meta Directory "root:$CI_USER" 1775 -)" ] || die "$RUNNER_DIR is $(lmeta "$RUNNER_DIR")"
  ok "$RUNNER_DIR: root-owned sticky directory, root-owned runner, $CI_USER state only: $(find "$RUNNER_DIR" -mindepth 1 -maxdepth 1 -user "$CI_USER" -exec basename {} \; | sort | tr '\n' ' ' || true)"
}

harden_tuist() {
  step "Tuist $TUIST_VERSION from a root-verified download"
  local dst="$TOOLS_DIR/tuist/$TUIST_VERSION" work
  [ "$(lmeta "$TOOLS_DIR/tuist")" = "$(want_meta Directory root:wheel 0755 -)" ] || die "$TOOLS_DIR/tuist is $(lmeta "$TOOLS_DIR/tuist")"
  if [ "$(lmeta "$dst")" = "$(want_meta Directory root:wheel 0755 -)" ] \
     && [ -z "$(find "$dst" ! -type l \( ! -user root -o -perm +022 \) -print -quit)" ] \
     && codesign --verify --strict "$dst/tuist" 2>/dev/null \
     && [ "$(codesign -dv "$dst/tuist" 2>&1 | awk -F= '$1 == "TeamIdentifier" {print $2}')" = "$TUIST_TEAM_ID" ]; then
    ok "$dst present, root-owned, signature valid (team $TUIST_TEAM_ID)"; return 0
  fi
  [ "$(lmeta "$dst")" = missing ] || quarantine "$dst" "$QUAR_RUN"
  work=$(mktemp -d "$STAGE_VOL/tuist.XXXXXX")
  fetch_verified "$TUIST_URL" "$TUIST_SHA" "$work/tuist.zip"
  mkdir "$work/tree"
  ditto -x -k "$work/tuist.zip" "$work/tree"
  chown -R -P root:wheel "$work/tree"; chmod -R -P go-w "$work/tree"; chmod 0755 "$work/tree"
  codesign --verify --strict "$work/tree/tuist" 2>/dev/null || die "Tuist fails code signature verification"
  [ "$(codesign -dv "$work/tree/tuist" 2>&1 | awk -F= '$1 == "TeamIdentifier" {print $2}')" = "$TUIST_TEAM_ID" ] || die "Tuist is not signed by team $TUIST_TEAM_ID"
  rename_nofollow "$work/tree" "$dst"
  rm -f "$work/tuist.zip"; rmdir "$work"
  [ "$(lmeta "$dst")" = "$(want_meta Directory root:wheel 0755 -)" ] || die "$dst reads back as $(lmeta "$dst")"
  chg "installed Tuist $TUIST_VERSION at $dst (root:wheel, team $TUIST_TEAM_ID)"
}

# harden_home_file <name> <owner:group> <mode> < content: a root-managed file directly in the home. A differing
# regular file is quarantined first (never adopted); a symlink or other type stops the run.
harden_home_file() {
  local p="$CI_HOME/$1" tmp
  case "$(lmeta "$p")" in
    missing) ;;
    "Regular File|"*)
      tmp=$(mktemp "$STAGE_VOL/cmp.XXXXXX"); cat >"$tmp"
      if ! cmp -s "$tmp" "$p" || [ "$(lmeta "$p")" != "$(want_meta "Regular File" "$2" "$3" schg)" ]; then quarantine "$p" "$QUAR_RUN"; fi
      install_file "$p" "$2" "$3" schg <"$tmp"; rm -f "$tmp"; return 0 ;;
    *) die "$p is $(lmeta "$p"), expected a regular file: refusing (suspected tampering)" ;;
  esac
  install_file "$p" "$2" "$3" schg
}

# harden_placeholder_dir <path>: an empty root-owned immutable directory that keeps $CI_USER from creating <path>.
harden_placeholder_dir() {
  local p=$1
  case "$(lmeta "$p")" in
    missing) ;;
    "Directory|root:wheel|755|schg") [ -z "$(ls -A "$p")" ] && { ok "$p placeholder $(lmeta "$p")"; return 0; } ;;
    "Directory|"*|"Regular File|"*) ;;          # quarantined below (for example a stale git lock file)
    *) die "$p is $(lmeta "$p"): refusing (suspected tampering)" ;;
  esac
  [ "$(lmeta "$p")" = missing ] || quarantine "$p" "$QUAR_RUN"
  ensure_dir_safe "$p" root:wheel 0755 schg
}

harden_home() {
  step "$CI_USER home: LaunchAgent and startup files root-controlled and immutable, home append-only"
  local f e
  [ "$(stat -f %HT "$CI_HOME")" = Directory ] || die "$CI_HOME is not a directory"
  case "$(lmeta "$CI_HOME")" in "Directory|$CI_USER:$CI_USER|700|"*) ;; *) die "$CI_HOME is $(lmeta "$CI_HOME")" ;; esac
  # The append-only flag blocks the renames and replacements below too: lift it for the duration (no $CI_USER
  # process exists, see the preconditions) and set it again at the end.
  [ "$(stat -f %Sf "$CI_HOME")" = - ] || chflags -h 0 "$CI_HOME"

  for f in tmp work ci-logs Library Library/Logs "Library/Logs/$RUNNER_LABEL" .config; do
    assert_real_dirs "$CI_HOME" "$(dirname "$CI_HOME/$f")"
  done
  for f in tmp work ci-logs; do ensure_dir_safe "$CI_HOME/$f" "$CI_USER:$CI_USER" 0700 -; done
  ensure_dir_safe "$CI_HOME/Library" "$CI_USER:$CI_USER" 0700 keep
  ensure_dir_safe "$CI_HOME/Library/Logs" "$CI_USER:$CI_USER" 0755 keep
  ensure_dir_safe "$CI_HOME/Library/Logs/$RUNNER_LABEL" "$CI_USER:$CI_USER" 0755 -
  ensure_dir_safe "$CI_HOME/.config" "$CI_USER:$CI_USER" 0700 -
  # Tools create these at the top level on first use (Tuist: .cache, .local; SwiftPM: .swiftpm; .NET: .dotnet).
  # Created now, they are part of the baseline, and a later job adding them does not look like persistence.
  for f in .cache .local .swiftpm .dotnet; do ensure_dir_safe "$CI_HOME/$f" "$CI_USER:$CI_USER" 0700 keep; done

  # Startup files: root content, immutable. Placeholders are empty files that only take the names.
  with_render harden_home_file .gitconfig root:wheel 0644 <<'GITCONFIG_EOF'
# Managed by root (host-prep.sh harden-runner, __LABEL_PREFIX__). Root-owned and immutable (schg), in an
# append-only home: __CI_USER__ can neither edit, rename nor replace it.
[url "https://github.com/"]
	insteadOf = git@github.com:
	insteadOf = ssh://git@github.com/
[credential]
	helper =
[core]
	sshCommand = /usr/bin/false
[init]
	defaultBranch = main
[advice]
	detachedHead = false
GITCONFIG_EOF
  for f in $CI_PLACEHOLDERS; do harden_home_file "$f" root:wheel 0644 </dev/null; done
  harden_placeholder_dir "$CI_HOME/.ssh"
  harden_placeholder_dir "$CI_HOME/.config/git"
  # git takes ~/.gitconfig.lock before writing global config. Holding that name with an immutable directory makes
  # any "git config --global" in a job fail at once instead of leaving a lock file the append-only home keeps forever.
  harden_placeholder_dir "$CI_HOME/.gitconfig.lock"

  # LaunchAgents: only the runner, generated here. launchctl(1): an agent in ~/Library/LaunchAgents must be owned by
  # the user loading it and not group/world-writable; schg keeps $CI_USER from changing it anyway.
  ensure_dir_safe "$CI_HOME/Library/LaunchAgents" "$CI_USER:$CI_USER" 0755 -
  for e in "$CI_HOME/Library/LaunchAgents"/* "$CI_HOME/Library/LaunchAgents"/.[!.]*; do
    [ "$(lmeta "$e")" != missing ] || continue
    [ "$e" = "$RUNNER_PLIST" ] && continue
    die "unexpected entry in $CI_USER's LaunchAgents: $e ($(lmeta "$e")): suspected persistence; inspect it, then re-run"
  done
  case "$(lmeta "$RUNNER_PLIST")" in
    missing) ;;
    "Regular File|"*)
      if ! runner_plist_content | cmp -s - "$RUNNER_PLIST"; then quarantine "$RUNNER_PLIST" "$QUAR_RUN"; fi ;;
    *) die "$RUNNER_PLIST is $(lmeta "$RUNNER_PLIST"): refusing (suspected tampering)" ;;
  esac
  runner_plist_content | install_file "$RUNNER_PLIST" "$CI_USER:$CI_USER" 0644 schg
  plutil -lint "$RUNNER_PLIST" >/dev/null || die "$RUNNER_PLIST is not a valid plist"
  ensure_dir_safe "$CI_HOME/Library/LaunchAgents" "$CI_USER:$CI_USER" 0755 schg
  ensure_dir_safe "$CI_HOME" "$CI_USER:$CI_USER" 0700 sappnd
}

harden_baseline() {
  step "persistence baseline ($CI_USER's files, read as $CI_USER; recorded before the runner first starts)"
  local now old ans
  now=$(sudo -u "$CI_USER" -H /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME="$CI_HOME" LC_ALL=C \
        /bin/bash --noprofile --norc "$SUPPORT/libexec/ci-manifest")
  [ -n "$now" ] || die "ci-manifest printed nothing"
  if [ -s "$SUPPORT/baseline/manifest" ]; then
    old=$(cat "$SUPPORT/baseline/manifest")
    if [ "$old" = "$now" ]; then ok "account state equals the recorded baseline"; return 0; fi
    printf '%s\n' "$now" | diff -u "$SUPPORT/baseline/manifest" - | sed 's/^/            /' || true
    [ "$REBASELINE" = 1 ] || die "the account differs from the recorded baseline (diff above). Review it; to accept it, re-run with: harden-runner --rebaseline"
    [ -t 0 ] || die "--rebaseline needs an interactive terminal for its confirmation"
    printf '   Type REBASELINE to record the state above as the new baseline: '; read -r ans
    [ "$ans" = REBASELINE ] || die "baseline not changed"
  fi
  printf '%s\n' "$now" | install_file "$SUPPORT/baseline/manifest" root:wheel 0644 -
  now=$(sudo -u "$CI_USER" -H /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME="$CI_HOME" LC_ALL=C \
        /bin/bash --noprofile --norc "$SUPPORT/libexec/ci-manifest")
  [ "$now" = "$(cat "$SUPPORT/baseline/manifest")" ] || die "a second manifest run differs from the baseline: the manifest is not stable"
  ok "a second manifest run equals the baseline"
}

harden_runner() {
  harden_preconditions
  harden_runner_files
  harden_tuist
  harden_home
  step "third-party global LaunchAgents in $CI_USER's launchd domain"
  disable_ci_session_agents 0
  harden_baseline
  step "harden-runner complete"
  cat <<HARDEN_EOF
   Next: log in $CI_FULLNAME (tunnelled Screen Sharing or at the Mac). The runner starts from the root-generated
   LaunchAgent with the session; switch back to $OWNER_USER. If the step above reported a deferred agent, run
   ci-session-agents now. Then the operator runs qualify.sh (owner, remote) and the owner runs its root mode.
   Quarantined $CI_USER copies: ${QUAR_RUN:-none} (root-only; delete after review).
HARDEN_EOF
}

# ---------------------------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------------------------
QUAR_RUN=""
main() {
  if [ "$MODE" != preflight ]; then
    [ "$(id -u)" = 0 ] || { echo "run as root: /usr/bin/sudo /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /bin/bash $0 $MODE" >&2; exit 1; }
    export HOME=/var/root
    cd /
  fi
  if [ "$MODE" != preflight ] && [ "$MODE" != ioc ]; then
    touch "$SETUP_LOG"; chown root:wheel "$SETUP_LOG"; chmod 0644 "$SETUP_LOG"
    exec > >(tee -a "$SETUP_LOG") 2>&1
    printf '\n######## %s host-prep.sh %s %s (sha256 %s)\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$MODE" "$OPT" \
      "$(shasum -a 256 "$0" 2>/dev/null | cut -c1-16)"
  fi
  case "$MODE" in
    preflight) preflight ;;
    ioc) preflight; mode_ioc ;;
    host)
      preflight
      step_ci_guards
      step_support_tree
      step_volume
      step_group
      step_user
      step_home
      step_identity_readback
      step_cron_deny
      step_xcode
      step_support_files
      step_firewall
      step_sshd
      step_smb
      step_screensharing
      step_updates
      step_power
      step_ci_session_agents
      step_airplay
      step_pf
      host_summary
      ;;
    confirm-pf) mode_confirm_pf ;;
    ci-session-agents) mode_ci_session_agents ;;
    harden-runner) preflight; harden_runner ;;
  esac
}
# Run unless sourced (the fixtures source this file to test its helpers); "bash -s" has no BASH_SOURCE.
if [ "${BASH_SOURCE[0]:-$0}" = "$0" ]; then main; fi
