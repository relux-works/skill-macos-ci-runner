#!/bin/bash
# shellcheck shell=bash
#
# qualify.sh: qualification of a CI host prepared by host-prep.sh (host, confirm-pf, harden-runner) after the first
# CI-account login. Every forbidden probe is paired with a positive control, so a block can be told apart from
# "nothing there". A probe whose control fails is SKIP (not proven), never PASS. RESID lines are accepted residual
# risks awaiting the owner's decision (references/DESIGN.md); they do not fail the run.
#
# Modes (always bash; root modes via /usr/bin/sudo /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /bin/bash):
#   owner           on the CI host as the owner account, no sudo:
#                     ssh <host> 'MACOS_CI_CONF=<support>/setup/ci-runner.conf bash -s -- owner' < qualify.sh
#   remote          on the admin workstation (MACOS_CI_CONF=<local copy of the config>): tailnet view, tunnelled
#                   Screen Sharing handshake, GitHub runner-group state
#   root [smb-host] the CI host, sudo, CI account logged in: pf, accounts, network pairs owner vs CI account (TCP, UDP,
#                   tailnet peer, inbound, optional SMB mount), root-helper sockets, prevention probes, the real
#                   job-started hook (clean, then a planted change), runner service and baseline. Writes only
#                   short-lived probe files as the CI account, removed again.
#   root-postbuild  the CI host, sudo, CI account logged in: one simulator boot and one xcodebuild as the CI account,
#                   then the real start hook; lists every refused job or process. Must pass before the first real job.
#   root-inbound    the CI host, sudo: holds an owner and a CI-account TCP listener on all interfaces for 180 s
#   remote-inbound  the admin workstation, while root-inbound runs: the owner listener answers, the CI one does not
#   root-boot       the CI host, sudo, right after a reboot and FileVault unlock, BEFORE the CI-account login
#   ci              as the CI account without sudo, e.g. a step of a qualification workflow on the runner
#   quota-fixture   the CI host, sudo. WRITES: a 1 GiB test volume, filled as the CI account, then deleted. Asks first.
# Exit status: 0 when no check failed.

set -uo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C

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
readonly CI_USER CI_UID CI_GID OWNER_USER OWNER_UID VOL_NAME SUPPORT_ROOT LABEL_PREFIX PF_ANCHOR_NAME RUNNER_ORG \
  RUNNER_GROUP RUNNER_NAME RUNNER_EXTRA_LABEL RUNNER_REPO TUIST_VERSION TUIST_TEAM_ID SIMULATOR_NAME ADMIN_SSH_ALIAS \
  HOST_TAILNET_IP TAILNET_PEER_IP
readonly VOL_MOUNT=/Volumes/$VOL_NAME VOL_QUOTA=$VOL_QUOTA_BYTES VOL_RESERVE=$VOL_RESERVE_BYTES
readonly CI_HOME=$VOL_MOUNT/home/$CI_USER
readonly RUNNER_DIR=$VOL_MOUNT/runner/actions-runner
readonly TOOLS_DIR=$VOL_MOUNT/tools
readonly RUNNER_LABEL=actions.runner.$RUNNER_ORG.$RUNNER_NAME
readonly RUNNER_PLIST=$CI_HOME/Library/LaunchAgents/$RUNNER_LABEL.plist
readonly SUPPORT=$SUPPORT_ROOT
readonly PF_CI_FILE=/etc/pf.anchors/$LABEL_PREFIX PF_CI_ANCHOR=com.apple/250.$PF_ANCHOR_NAME
readonly PF_SS_FILE=/etc/pf.anchors/$LABEL_PREFIX.screensharing PF_SS_ANCHOR=com.apple/251.${PF_ANCHOR_NAME}ScreenSharing
readonly PF_PLIST=/Library/LaunchDaemons/$LABEL_PREFIX.pf.plist
readonly DEADMAN_PLIST=/Library/LaunchDaemons/$LABEL_PREFIX.pf-deadman.plist
readonly PF_STATE_FILE=/var/run/$LABEL_PREFIX.pf.state
readonly ALF=/usr/libexec/ApplicationFirewall/socketfilterfw

MODE=${1:-}
ARG2=${2:-}
P=0; F=0; S=0; RS=0
hdr()   { printf '\n## %s\n' "$*"; }
pass()  { P=$((P + 1)); printf 'PASS  %-36s %s\n' "$1" "$2"; }
fail()  { F=$((F + 1)); printf 'FAIL  %-36s %s\n' "$1" "$2"; }
skip()  { S=$((S + 1)); printf 'SKIP  %-36s %s\n' "$1" "$2"; }
resid() { RS=$((RS + 1)); printf 'RESID %-36s %s\n' "$1" "$2"; }
is() { if [ "$3" = "$4" ]; then pass "$1" "$2 = $3"; else fail "$1" "$2: got '$3', want '$4'"; fi; }
yes_() { local id=$1 d=$2; shift 2; if "$@" >/dev/null 2>&1; then pass "$id" "$d"; else fail "$id" "$d"; fi; }
# denied <id> <description> <command...>: PASS only when the command fails with a permission error.
denied() {
  local id=$1 d=$2 out; shift 2
  if out=$("$@" 2>&1); then fail "$id" "$d: was allowed"; return; fi
  case "$out" in
    *"Permission denied"*|*"Operation not permitted"*|*"not permitted"*) pass "$id" "$d: refused (${out##*: })" ;;
    *) fail "$id" "$d: failed for another reason: $(printf '%s' "$out" | head -1)" ;;
  esac
}
# Modes print with the setuid/setgid/sticky digit (%Mp) and without a leading 0: 1775, 755, 644. %Lp alone drops
# the sticky bit, so a 1775 directory would read back as 775.
perm_of() { local m; m=$(stat -f '%Su:%Sg %Mp%03Lp' "$1" 2>/dev/null) || { echo missing; return 0; }; printf '%s\n' "$m" | sed 's/ 0\([0-7][0-7][0-7]\)$/ \1/'; }
lmeta() { local m; m=$(stat -f '%HT|%Su:%Sg|%Mp%03Lp|%Sf' "$1" 2>/dev/null) || { echo missing; return 0; }; printf '%s\n' "$m" | sed 's/|0\([0-7][0-7][0-7]\)|/|\1|/'; }
# sshd_value <key>: the effective value of an sshd option from `sshd -T`. OpenSSH 10.x prints CamelCase keys
# (DenyUsers), older releases lower case (denyusers): match case-insensitively (references/PITFALLS.md).
sshd_value() { sshd -T 2>/dev/null | awk -v k="$1" 'tolower($1) == tolower(k) {$1=""; print substr($0,2)}'; }
plv() { plutil -extract "$1" raw -o - - 2>/dev/null; }
has() { grep "$@" >/dev/null; }   # grep to the end of input: no SIGPIPE upstream under pipefail
fam_of() { case "$1" in *:*) echo -6 ;; *) echo -4 ;; esac; }
tcp() { nc "$(fam_of "$1")" -z -G 3 "$1" "$2" >/dev/null 2>&1; }
listening() { local l; l=$(netstat -an -p tcp 2>/dev/null | awk '$NF == "LISTEN" {print $4}'); printf '%s\n' "$l" | grep -E "[.]$1\$" >/dev/null; }
gateway() { route -n get default 2>/dev/null | awk '/gateway:/ {print $2}'; }
finish() { printf '\nRESULT mode=%s pass=%s fail=%s skip=%s resid=%s\n' "$MODE" "$P" "$F" "$S" "$RS"; [ "$F" = 0 ]; exit $?; }
need_root() { [ "$(id -u)" = 0 ] || { echo "$MODE mode needs sudo" >&2; exit 2; }; export HOME=/var/root; cd /; }
cfg_hash() { cat "$PF_CI_FILE" "$PF_SS_FILE" "$SUPPORT/sbin/pf-assert" "$PF_PLIST" 2>/dev/null | shasum -a 256 | cut -d' ' -f1; }

# The ${VOL_NAME} volume record: UUID, Quota, Reserve, Encryption (tab-separated).
ci_volume() {
  local plist nc ci nv vi b c
  c=$(diskutil info -plist /System/Volumes/Data | plv APFSContainerReference || true)
  plist=$(diskutil apfs list -plist)
  nc=$(printf '%s' "$plist" | plv Containers || echo 0); ci=0
  while [ "$ci" -lt "$nc" ]; do
    if [ "$(printf '%s' "$plist" | plv "Containers.$ci.ContainerReference" || true)" = "$c" ]; then
      nv=$(printf '%s' "$plist" | plv "Containers.$ci.Volumes" || echo 0); vi=0
      while [ "$vi" -lt "$nv" ]; do
        b="Containers.$ci.Volumes.$vi"
        if [ "$(printf '%s' "$plist" | plv "$b.Name" || true)" = ${VOL_NAME} ]; then
          printf '%s\t%s\t%s\t%s\n' "$(printf '%s' "$plist" | plv "$b.APFSVolumeUUID")" \
            "$(printf '%s' "$plist" | plv "$b.CapacityQuota")" "$(printf '%s' "$plist" | plv "$b.CapacityReserve")" \
            "$(printf '%s' "$plist" | plv "$b.Encryption")"
        fi
        vi=$((vi + 1))
      done
    fi
    ci=$((ci + 1))
  done
}

# ---------------------------------------------------------------------------------------------------------------
# owner: host facts readable without root, as the owner account
# ---------------------------------------------------------------------------------------------------------------
mode_owner() {
  local g out v uuid quota reserve enc f gw p code
  hdr "account ${CI_USER}"
  is user.uid "UniqueID" "$(dscl . read /Users/$CI_USER UniqueID 2>/dev/null | awk '{print $2}')" "$CI_UID"
  is user.gid "PrimaryGroupID" "$(dscl . read /Users/$CI_USER PrimaryGroupID 2>/dev/null | awk '{print $2}')" "$CI_GID"
  is user.home "NFSHomeDirectory" "$(dscl . read /Users/$CI_USER NFSHomeDirectory 2>/dev/null | awk '{print $2}')" "$CI_HOME"
  out=$(dsmemberutil checkmembership -U $CI_USER -G $CI_USER 2>&1 || true)
  case "$out" in *"is a member"*) pass user.own-group "member of its own group (control for the group checks)" ;;
    *) fail user.own-group "own group membership: $out" ;; esac
  for g in admin staff wheel _developer com.apple.access_ssh com.apple.access_screensharing; do
    out=$(dsmemberutil checkmembership -U $CI_USER -G "$g" 2>&1 || true)
    case "$out" in *"is not a member"*) pass "user.not-in.$g" "not a member of $g" ;; *) fail "user.not-in.$g" "$out" ;; esac
  done
  for f in /private/var/at/cron.deny /private/var/at/at.deny; do
    yes_ "user.${f##*/}" "$f lists $CI_USER" grep -qx "$CI_USER" "$f"
  done

  hdr "volume ${VOL_NAME}"
  v=$(ci_volume)
  if [ -z "$v" ]; then fail vol.exists "no APFS volume named ${VOL_NAME}"; else
    IFS=$'\t' read -r uuid quota reserve enc <<<"$v"
    is vol.quota "CapacityQuota (bytes)" "$quota" "$VOL_QUOTA"
    is vol.reserve "CapacityReserve (bytes)" "$reserve" "$VOL_RESERVE"
    is vol.encrypted "Encryption" "$enc" true
    is vol.uuid-recorded "UUID equals $SUPPORT/etc/volume-uuid" "$uuid" "$(cat $SUPPORT/etc/volume-uuid 2>/dev/null)"
    is vol.mounted "MountPoint" "$(diskutil info -plist "$uuid" 2>/dev/null | plv MountPoint)" "$VOL_MOUNT"
    is vol.owners "GlobalPermissionsEnabled" "$(diskutil info -plist "$VOL_MOUNT" 2>/dev/null | plv GlobalPermissionsEnabled)" true
    if mount | grep -F " on $VOL_MOUNT (" | has noowners; then fail vol.mount-flags "mounted with noowners"; else pass vol.mount-flags "mounted without noowners"; fi
    yes_ vol.spotlight-off "Spotlight indexing disabled" sh -c "mdutil -s $VOL_MOUNT 2>&1 | grep -i 'indexing disabled' >/dev/null"
    if [ -e "${VOL_MOUNT} 1" ]; then fail vol.no-stray "'${VOL_MOUNT} 1' exists (stray mount point)"; else pass vol.no-stray "no '${VOL_MOUNT} 1'"; fi
  fi

  hdr "directories and the owner's view of them"
  is dir.volume-root "$VOL_MOUNT" "$(perm_of $VOL_MOUNT)" "root:wheel 755"
  is dir.stage "$VOL_MOUNT/.ci-stage" "$(perm_of $VOL_MOUNT/.ci-stage)" "root:wheel 700"
  is dir.home "$CI_HOME" "$(perm_of $CI_HOME)" "${CI_USER}:${CI_USER} 700"
  is dir.home-flags "$CI_HOME flags" "$(stat -f %Sf $CI_HOME 2>/dev/null)" sappnd
  is dir.runner-parent "${RUNNER_DIR%/*}" "$(perm_of "${RUNNER_DIR%/*}")" "root:wheel 755"
  is dir.runner "$RUNNER_DIR" "$(perm_of $RUNNER_DIR)" "root:${CI_USER} 1775"
  is dir.tools "$TOOLS_DIR/tuist" "$(perm_of $TOOLS_DIR/tuist)" "root:wheel 755"
  # 700, or the stock 750 (group staff): the CI account is not in staff, so neither lets it in.
  case "$(perm_of "/Users/$OWNER_USER")" in
    "$OWNER_USER:staff 700"|"$OWNER_USER:staff 750") pass dir.owner-home "/Users/$OWNER_USER is $(perm_of "/Users/$OWNER_USER")" ;;
    *) fail dir.owner-home "/Users/$OWNER_USER is $(perm_of "/Users/$OWNER_USER"), want owner:staff 700 or 750" ;;
  esac
  yes_ dir.home-stat "owner can stat the CI home (control)" stat "$CI_HOME"
  denied dir.home-list "owner lists ${CI_USER}'s home" ls "$CI_HOME"

  hdr "toolchain"
  is xcode.owner "/Applications/Xcode.app owner" "$(stat -f %Su:%Sg /Applications/Xcode.app 2>/dev/null)" "root:wheel"
  is xcode.no-foreign-files "files not root:wheel" "$(find /Applications/Xcode.app \( ! -user root -o ! -group wheel \) -print -quit 2>/dev/null | wc -l | tr -d ' ')" 0
  is xcode.no-writable "group/other-writable files" "$(find /Applications/Xcode.app ! -type l -perm +022 -print -quit 2>/dev/null | wc -l | tr -d ' ')" 0
  yes_ xcode.first-launch "xcodebuild -checkFirstLaunchStatus exit 0" xcodebuild -checkFirstLaunchStatus
  yes_ xcode.license "xcodebuild -license check exit 0" xcodebuild -license check
  if [ -x "$TOOLS_DIR/tuist/$TUIST_VERSION/tuist" ]; then
    yes_ tuist.signature "codesign --verify --strict" codesign --verify --strict "$TOOLS_DIR/tuist/$TUIST_VERSION/tuist"
    is tuist.team "TeamIdentifier" "$(codesign -dv "$TOOLS_DIR/tuist/$TUIST_VERSION/tuist" 2>&1 | awk -F= '$1 == "TeamIdentifier" {print $2}')" "$TUIST_TEAM_ID"
    is tuist.writable "Tuist files not root-owned or writable" "$(find "$TOOLS_DIR" ! -type l \( ! -user root -o -perm +022 \) -print 2>/dev/null | wc -l | tr -d ' ')" 0
  else fail tuist.present "$TOOLS_DIR/tuist/$TUIST_VERSION/tuist missing"; fi

  hdr "root-owned files (read-only to owner and ${CI_USER})"
  for f in "$SUPPORT/libexec/ci-manifest:root:wheel 755" "$SUPPORT/hooks/job-started.sh:root:wheel 755" \
           "$SUPPORT/hooks/job-completed.sh:root:wheel 755" "$SUPPORT/sbin/pf-assert:root:wheel 755" "$SUPPORT/sbin/pf-deadman:root:wheel 755" \
           "$SUPPORT/baseline/manifest:root:wheel 644" "$SUPPORT/etc/pf-confirmed:root:wheel 644" "$PF_CI_FILE:root:wheel 644" "$PF_SS_FILE:root:wheel 644" \
           "$PF_PLIST:root:wheel 644" "/etc/ssh/sshd_config.d/50-${CI_USER}.conf:root:wheel 644" \
           "$RUNNER_DIR/.env:root:wheel 644" "$RUNNER_DIR/.path:root:wheel 644" "$RUNNER_DIR/runsvc.sh:root:wheel 755" \
           "$RUNNER_DIR/svc.sh:root:wheel 755" "$RUNNER_DIR/.service:root:wheel 644"; do
    is "file.${f%%:*}" "owner/mode" "$(perm_of "${f%%:*}")" "${f#*:}"
  done
  if [ ! -f "$SUPPORT/hooks/job-started.sh" ]; then fail file.hook-writable "job-started.sh missing"
  elif [ -w "$SUPPORT/hooks/job-started.sh" ]; then fail file.hook-writable "job-started.sh writable by owner"
  else pass file.hook-writable "job-started.sh exists and is not writable by owner"; fi
  if [ -f "$RUNNER_DIR/bin/Runner.Listener" ]; then
    is runner.binaries "runner bin/externals files not root-owned or writable" \
      "$(find "$RUNNER_DIR"/bin "$RUNNER_DIR"/externals ! -type l \( ! -user root -o -perm +022 \) -print 2>/dev/null | wc -l | tr -d ' ')" 0
  else fail runner.binaries "runner not installed ($RUNNER_DIR/bin/Runner.Listener missing)"; fi
  for v in "DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer" "TMPDIR=$CI_HOME/tmp" "GIT_CONFIG_NOSYSTEM=1" \
           "TUIST_CONFIG_STATS_OPT_OUT=1" "BASH_ENV=" "ENV=" "DYLD_INSERT_LIBRARIES=" \
           "ACTIONS_RUNNER_HOOK_JOB_STARTED=$SUPPORT/hooks/job-started.sh" "ACTIONS_RUNNER_HOOK_JOB_COMPLETED=$SUPPORT/hooks/job-completed.sh"; do
    yes_ "runner.env.${v%%=*}" ".env has '$v'" grep -qxF "$v" "$RUNNER_DIR/.env"
  done
  is runner.path ".path" "$(cat "$RUNNER_DIR/.path" 2>/dev/null)" "$TOOLS_DIR/tuist/$TUIST_VERSION:/usr/bin:/bin:/usr/sbin:/sbin"
  is runner.registration ".runner agentName" "$(grep -oE '"agentName": *"[^"]*"' "$RUNNER_DIR/.runner" 2>/dev/null | sed -E 's/.*"([^"]*)"$/\1/')" "$RUNNER_NAME"

  hdr "pf loader and dead-man (owner view; loaded rules are checked in root mode)"
  yes_ pf.daemon "LaunchDaemon ${LABEL_PREFIX}.pf loaded" launchctl print system/${LABEL_PREFIX}.pf
  is pf.daemon-exit "pf-assert last exit code" "$(launchctl print system/${LABEL_PREFIX}.pf 2>/dev/null | awk -F'= ' '/last exit code/ && !seen++ {print $2}')" 0
  is pf.interval "pf-assert StartInterval" "$(plutil -extract StartInterval raw -o - "$PF_PLIST" 2>/dev/null)" 30
  if [ -f /var/log/${LABEL_PREFIX}.pf.log ]; then
    is pf.log-errors "ERROR lines in the last 50 pf log lines" "$(tail -n 50 /var/log/${LABEL_PREFIX}.pf.log | grep -c ERROR)" 0
  else fail pf.log-errors "no pf log: pf-assert never ran"; fi
  is pf.confirmed "confirmed hash equals the current pf files" "$(cut -d' ' -f1 "$SUPPORT/etc/pf-confirmed" 2>/dev/null)" "$(cfg_hash)"
  if [ ! -s "$SUPPORT/etc/pf-confirmed" ]; then fail pf.deadman "pf was never confirmed (no $SUPPORT/etc/pf-confirmed)"
  elif [ -e "$DEADMAN_PLIST" ] || launchctl print system/${LABEL_PREFIX}.pf-deadman >/dev/null 2>&1; then
    fail pf.deadman "the dead-man is still armed: pf rolls back unless confirm-pf runs"
  else pass pf.deadman "confirmed, no dead-man armed"; fi
  yes_ pf.rule-v4 "anchor blocks private IPv4 for uid $CI_UID" grep -q '^block return out log quick inet proto { tcp udp } from any to <ci_block4> user '"$CI_UID"'$' "$PF_CI_FILE"
  yes_ pf.rule-v6 "anchor blocks all IPv6 for uid $CI_UID" grep -q '^block return out log quick inet6 proto { tcp udp } all user '"$CI_UID"'$' "$PF_CI_FILE"
  yes_ pf.rule-in "anchor drops inbound to uid $CI_UID" grep -q '^block drop in log quick proto { tcp udp } all user '"$CI_UID"'$' "$PF_CI_FILE"
  yes_ pf.rule-state "anchor keeps state for allowed egress" grep -q '^pass out quick inet proto tcp all user '"$CI_UID"' flags S/SA keep state$' "$PF_CI_FILE"
  yes_ pf.rule-5900 "Screen Sharing loopback-only rule" grep -q '^block drop in log quick on ! lo0 proto { tcp udp } from any to any port 5900$' "$PF_SS_FILE"

  hdr "host services"
  yes_ alf.on "application firewall on" sh -c "$ALF --getglobalstate | grep -E 'State = [12]' >/dev/null"
  yes_ alf.stealth "stealth mode on" sh -c "$ALF --getstealthmode | grep -i 'stealth mode is on' >/dev/null"
  yes_ listen.22 "sshd listens on 22 (control for the listener checks)" listening 22
  if listening 445; then fail listen.445 "SMB listens on 445"; else pass listen.445 "nothing listens on 445"; fi
  is smb.override "launchd override com.apple.smbd" "$(launchctl print-disabled system 2>/dev/null | awk -F'=> ' '/"com.apple.smbd"/ {print $2}')" disabled
  for p in 5000 7000; do if listening $p; then fail "listen.$p" "AirPlay port $p listens"; else pass "listen.$p" "nothing listens on $p"; fi; done
  yes_ listen.5900 "Screen Sharing still listens (kept for the owner; network reach is checked in remote mode)" listening 5900
  if [ -e /Library/Preferences/com.apple.VNCSettings.txt ]; then fail vnc.legacy "legacy VNC password file present"; else pass vnc.legacy "no legacy VNC password file"; fi
  yes_ sshd.dropin-deny "sshd drop-in denies ${CI_USER}" grep -qx "DenyUsers $CI_USER" "/etc/ssh/sshd_config.d/50-$CI_USER.conf"
  yes_ sshd.dropin-root "sshd drop-in forbids root logins" grep -qx 'PermitRootLogin no' /etc/ssh/sshd_config.d/50-${CI_USER}.conf
  is su.auto-install "AutomaticallyInstallMacOSUpdates" "$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null)" 0
  is su.critical "CriticalUpdateInstall" "$(defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null)" 1
  is su.configdata "ConfigDataInstall" "$(defaults read /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall 2>/dev/null)" 1
  is power.ac-sleep "AC sleep" "$(pmset -g custom | awk '/^AC Power:/ {f=1; next} /^[A-Za-z].*:$/ {f=0} f && $1 == "sleep" {print $2}')" 0

  hdr "network as owner (controls for the ${CI_USER} probes of the root and ci modes)"
  yes_ net.owner.loopback4 "owner reaches 127.0.0.1:22" tcp 127.0.0.1 22
  yes_ net.owner.loopback6 "owner reaches [::1]:22" tcp ::1 22
  yes_ net.owner.tailnet "owner reaches 100.100.100.100:53" tcp 100.100.100.100 53
  if [ -z "$TAILNET_PEER_IP" ]; then skip net.owner.tailnet-peer "TAILNET_PEER_IP not configured"
  elif tcp "$TAILNET_PEER_IP" 22; then pass net.owner.tailnet-peer "owner reaches the tailnet peer $TAILNET_PEER_IP:22"; else skip net.owner.tailnet-peer "tailnet peer $TAILNET_PEER_IP:22 not reachable as owner"; fi
  gw=$(gateway); out=""
  for p in 80 443 53; do if tcp "$gw" "$p"; then out=$p; break; fi; done
  if [ -n "$out" ]; then pass net.owner.lan "owner reaches LAN gateway $gw:$out"; else skip net.owner.lan "no open TCP port on gateway ${gw:-?}"; fi
  code=$(curl -sS -o /dev/null -m 15 -w '%{http_code}' https://github.com 2>/dev/null || true)
  is net.owner.github "owner HTTPS to github.com" "$code" 200
}

# ---------------------------------------------------------------------------------------------------------------
# remote and remote-inbound: from the admin workstation (the operator)
# ---------------------------------------------------------------------------------------------------------------
# rfb_types <port>: the security types a VNC server offers on 127.0.0.1:<port> (RFB 3.8 handshake, no auth).
rfb_types() {
  perl -e 'alarm shift; exec @ARGV' 10 bash -c '
    exec 3<>"/dev/tcp/127.0.0.1/$1" || exit 1
    ver=$(dd bs=1 count=12 <&3 2>/dev/null)
    case "$ver" in RFB\ *) ;; *) exit 2 ;; esac
    printf "RFB 003.008\n" >&3
    n=$(dd bs=1 count=1 <&3 2>/dev/null | od -An -tu1 | tr -d " ")
    [ -n "$n" ] && [ "$n" -gt 0 ] || exit 3
    dd bs=1 count="$n" <&3 2>/dev/null | od -An -tu1 | tr -s " " | sed "s/^ //"
  ' _ "$1"
}

# ghq <gh api args...>: gh from Homebrew on the admin workstation; any gh failure prints GH_ERROR so no check passes on empty output.
ghq() {
  local gh; gh=$(PATH=/opt/homebrew/bin:/usr/local/bin:$PATH command -v gh) || { echo GH_ERROR; return 1; }
  "$gh" "$@" 2>/dev/null || { echo GH_ERROR; return 1; }
}

mode_remote() {
  local p tun types gid repos runner labels other
  hdr "tailnet view of the CI host (${HOST_TAILNET_IP:-not configured})"
  yes_ remote.ssh "SSH reaches the CI host (control: host up)" ssh -o BatchMode=yes "$ADMIN_SSH_ALIAS" true
  if [ -z "$HOST_TAILNET_IP" ]; then skip remote.closed "HOST_TAILNET_IP not configured: the closed-port checks need a target"
  elif ! tcp "$HOST_TAILNET_IP" 22; then fail remote.22 "TCP 22 on $HOST_TAILNET_IP not reachable: the closed-port checks have no control"
  else
    pass remote.22 "TCP 22 open (control for the closed ports)"
    for p in 445 5900 5000 7000 3283; do
      if tcp "$HOST_TAILNET_IP" "$p"; then fail "remote.closed.$p" "TCP $p reachable over the tailnet"; else pass "remote.closed.$p" "TCP $p not reachable over the tailnet"; fi
    done
  fi

  hdr "Screen Sharing through an SSH tunnel (loopback on the CI host)"
  ssh -o BatchMode=yes -N -o ExitOnForwardFailure=yes -L 127.0.0.1:15901:127.0.0.1:5900 "$ADMIN_SSH_ALIAS" &
  tun=$!
  for _ in 1 2 3 4 5 6 7 8 9 10; do tcp 127.0.0.1 15901 && break; sleep 1; done
  if types=$(rfb_types 15901); then
    pass remote.tunnel "VNC answers through the tunnel (types: $types)"
    case " $types " in *" 2 "*) fail remote.vnc-legacy "server still offers legacy VNC password auth (type 2)" ;;
      *) pass remote.vnc-legacy "no legacy VNC password auth (type 2) offered (detection not control-tested: see references/DESIGN.md)" ;; esac
  else
    fail remote.tunnel "no RFB handshake through the tunnel"
  fi
  kill "$tun" 2>/dev/null; wait "$tun" 2>/dev/null

  hdr "GitHub ($RUNNER_ORG)"
  gid=$(ghq api "orgs/$RUNNER_ORG/actions/runner-groups" --jq ".runner_groups[] | select(.name == \"$RUNNER_GROUP\") | .id")
  if [ "$gid" = GH_ERROR ]; then fail gh.api "gh api failed (gh missing or not authenticated)"
  elif [ -z "$gid" ]; then fail gh.group "runner group $RUNNER_GROUP missing"; else
    is gh.group.visibility "$RUNNER_GROUP visibility" "$(ghq api "orgs/$RUNNER_ORG/actions/runner-groups/$gid" --jq .visibility)" selected
    is gh.group.public "$RUNNER_GROUP allows public repositories" "$(ghq api "orgs/$RUNNER_ORG/actions/runner-groups/$gid" --jq .allows_public_repositories)" false
    repos=$(ghq api "orgs/$RUNNER_ORG/actions/runner-groups/$gid/repositories" --jq '[.repositories[].full_name] | sort | join(",")')
    is gh.group.repos "$RUNNER_GROUP repositories" "$repos" "$RUNNER_REPO"
    runner=$(ghq api "orgs/$RUNNER_ORG/actions/runner-groups/$gid/runners" --jq ".runners[] | select(.name == \"$RUNNER_NAME\") | .status")
    is gh.runner.status "$RUNNER_NAME status" "$runner" online
    labels=$(ghq api "orgs/$RUNNER_ORG/actions/runner-groups/$gid/runners" --jq ".runners[] | select(.name == \"$RUNNER_NAME\") | [.labels[].name] | sort | join(\",\")")
    is gh.runner.labels "$RUNNER_NAME labels" "$labels" "$(printf '%s\n' ARM64 macOS self-hosted "$RUNNER_EXTRA_LABEL" | LC_ALL=C sort | paste -sd, -)"
    is gh.group.runners "runners in $RUNNER_GROUP" "$(ghq api "orgs/$RUNNER_ORG/actions/runner-groups/$gid/runners" --jq '[.runners[].name] | join(",")')" "$RUNNER_NAME"
    # The other groups of the org must not admit this repository (a job routed elsewhere would bypass this host's
    # isolation story only if a group grants it; listing them makes an accidental grant visible). Groups with
    # visibility "all" or "private" admit every (private) repository and are listed for review.
    ghq api "orgs/$RUNNER_ORG/actions/runner-groups" --paginate --jq ".runner_groups[] | select(.id != $gid and .visibility != \"selected\") | \"info  group \\(.name) (id \\(.id)) has visibility \\(.visibility): it admits every eligible repository\"" || true
    for other in $(ghq api "orgs/$RUNNER_ORG/actions/runner-groups" --paginate --jq ".runner_groups[] | select(.id != $gid and .visibility == \"selected\") | .id"); do
      is "gh.group-$other.repo" "group $other does not list $RUNNER_REPO" "$(ghq api "orgs/$RUNNER_ORG/actions/runner-groups/$other/repositories" --jq "[.repositories[].full_name] | any(. == \"$RUNNER_REPO\")")" false
    done
  fi
  skip gh.cross-repo "a job from another repository stays queued: prove it once with a disposable private repository (references/RUNBOOK.md)"
}

mode_remote_inbound() {
  hdr "inbound over the tailnet while 'root-inbound' runs on the CI host"
  if [ -z "$HOST_TAILNET_IP" ]; then skip remote.inbound "HOST_TAILNET_IP not configured"
  elif tcp "$HOST_TAILNET_IP" 18081; then pass remote.inbound.control "owner listener $HOST_TAILNET_IP:18081 reachable (control)"
    if tcp "$HOST_TAILNET_IP" 18080; then fail remote.inbound "${CI_USER} listener $HOST_TAILNET_IP:18080 reachable"
    else pass remote.inbound "${CI_USER} listener $HOST_TAILNET_IP:18080 not reachable"; fi
  else skip remote.inbound "control failed: the owner listener on 18081 is not reachable (is root-inbound running?)"; fi
}

# ---------------------------------------------------------------------------------------------------------------
# root modes: the CI host with sudo (the owner)
# ---------------------------------------------------------------------------------------------------------------
as_owner() { sudo -u "$OWNER_USER" -H /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME="/Users/$OWNER_USER" "$@"; }
as_ci() { sudo -u "$CI_USER" -H /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME="$CI_HOME" "$@"; }
# stop_bg <pid>...: stop background probes started through as_owner/as_ci. $! is the sudo wrapper; sudo does not
# relay a signal sent from its own process group, so the probe (its child) is signalled first, by parent PID.
stop_bg() { local p; for p in "$@"; do pkill -TERM -P "$p" 2>/dev/null || true; kill "$p" 2>/dev/null || true; done; wait "$@" 2>/dev/null || true; }
# pair <id> <host> <port>: owner must reach it (control); ${CI_USER} must not.
pair() {
  local id=$1 h=$2 p=$3
  if ! as_owner nc "$(fam_of "$h")" -z -G 3 "$h" "$p" >/dev/null 2>&1; then skip "$id" "control failed: owner cannot reach $h:$p"; return; fi
  if as_ci nc "$(fam_of "$h")" -z -G 3 "$h" "$p" >/dev/null 2>&1; then fail "$id" "${CI_USER} reaches $h:$p"
  else pass "$id" "$h:$p reachable for owner, refused for ${CI_USER}"; fi
}
# udp_pair <id> <server>: a DNS query over UDP must work for owner and fail for ${CI_USER}.
udp_pair() {
  local id=$1 h=$2
  if ! as_owner dig +time=2 +tries=1 +short "@$h" github.com A >/dev/null 2>&1; then skip "$id" "control failed: owner gets no UDP DNS answer from $h"; return; fi
  if as_ci dig +time=2 +tries=1 +short "@$h" github.com A 2>/dev/null | has -E '^[0-9]'; then fail "$id" "${CI_USER} gets a UDP DNS answer from $h"
  else pass "$id" "UDP DNS to $h answers owner, refused for ${CI_USER}"; fi
}

# hook: run the real job-started hook as ${CI_USER} inside its GUI session, as the runner would.
hook() { launchctl asuser $CI_UID sudo -u $CI_USER -H /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME="$CI_HOME" \
           DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer /bin/bash --noprofile --norc "$SUPPORT/hooks/job-started.sh" 2>&1; }
# ci_gui <command...>: run a command as ${CI_USER} inside its GUI session with the runner's job environment.
ci_gui() { launchctl asuser $CI_UID sudo -u $CI_USER -H /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME="$CI_HOME" \
             DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer TMPDIR="$CI_HOME/tmp" "$@"; }

pf_checks() {
  local f want have ent
  hdr "pf"
  yes_ pf.enabled "pf Status: Enabled" sh -c "pfctl -s info 2>/dev/null | grep '^Status: Enabled' >/dev/null"
  yes_ pf.token "enable token file present" test -s /var/run/${LABEL_PREFIX}.pf.token
  printf 'info  references: %s\n' "$(pfctl -s References 2>/dev/null | tr '\n' ' ' | cut -c1-200)"
  for f in "$PF_CI_ANCHOR=$PF_CI_FILE" "$PF_SS_ANCHOR=$PF_SS_FILE"; do
    want=$(pfctl -n -v -f "${f#*=}" 2>/dev/null | grep -cE '^(block|pass)')
    have=$(pfctl -a "${f%%=*}" -s rules 2>/dev/null | grep -cE '^(block|pass)')
    if [ "$want" -gt 0 ] && [ "$want" = "$have" ]; then pass "pf.rules.${f%%=*}" "$have rules loaded, as parsed from ${f#*=}"
    else fail "pf.rules.${f%%=*}" "loaded $have rules, file parses to $want"; fi
    is "pf.state.${f%%=*}" "pf-assert recorded the current file" "$(awk -v a="${f%%=*}" '$1 == a {print $2}' "$PF_STATE_FILE" 2>/dev/null)" "$(shasum -a 256 "${f#*=}" | cut -d' ' -f1)"
    pfctl -a "${f%%=*}" -s rules 2>/dev/null | sed 's/^/      loaded: /'
  done
  ent=$(pfctl -a "$PF_CI_ANCHOR" -t ci_block4 -T show 2>/dev/null | wc -l | tr -d ' ')
  is pf.table "ci_block4 entries" "$ent" 11
  is pf.confirmed "confirmed hash equals the current pf files" "$(cut -d' ' -f1 "$SUPPORT/etc/pf-confirmed" 2>/dev/null)" "$(cfg_hash)"
  if [ ! -s "$SUPPORT/etc/pf-confirmed" ]; then fail pf.deadman "pf was never confirmed"
  elif [ -e "$DEADMAN_PLIST" ] || launchctl print system/${LABEL_PREFIX}.pf-deadman >/dev/null 2>&1; then fail pf.deadman "the dead-man is still armed"
  else pass pf.deadman "confirmed, no dead-man armed"; fi
}

net_pairs() {
  local gw p
  hdr "network: owner (control) vs ${CI_USER}"
  pair net.loopback4 127.0.0.1 22
  pair net.loopback6 ::1 22
  pair net.tailnet-quad100 100.100.100.100 53
  if [ -n "$TAILNET_PEER_IP" ]; then pair net.tailnet-peer "$TAILNET_PEER_IP" 22; else skip net.tailnet-peer "TAILNET_PEER_IP not configured"; fi
  gw=$(gateway); p=""
  for p in 80 443 53; do if as_owner nc -4 -z -G 3 "$gw" "$p" >/dev/null 2>&1; then break; fi; p=""; done
  if [ -n "$p" ]; then pair net.lan "$gw" "$p"; else skip net.lan "no TCP port on the gateway ${gw:-?} answers owner"; fi
  udp_pair net.udp.lan-dns "$gw"
  udp_pair net.udp.tailnet-dns 100.100.100.100
}

mode_root() {
  need_root
  local out f l code ownerpid ipid lpid smb mi mc e
  pf_checks

  hdr "accounts and SSH"
  out=$(sysadminctl -secureTokenStatus $CI_USER 2>&1)
  case "$out" in *DISABLED*) pass acct.securetoken "${CI_USER} secure token DISABLED" ;; *) fail acct.securetoken "$out" ;; esac
  is acct.fdesetup "FileVault unlock users" "$(fdesetup list 2>/dev/null | cut -d, -f1 | sort | tr '\n' ' ')" "$OWNER_USER "
  out=$(sudo -l -U $CI_USER 2>&1)
  case "$out" in *"not allowed to run sudo"*) pass acct.sudo "sudo -l -U ${CI_USER}: not allowed to run sudo" ;; *) fail acct.sudo "sudo -l -U ${CI_USER}: $out" ;; esac
  is acct.crontab "${CI_USER} crontab" "$(lmeta /private/var/at/tabs/$CI_USER)" missing
  is sshd.denyusers "sshd -T denyusers" "$(sshd_value DenyUsers)" "$CI_USER"
  is sshd.rootlogin "sshd -T permitrootlogin" "$(sshd_value PermitRootLogin)" no
  is acct.root-keys "root authorized_keys" "$(lmeta /var/root/.ssh/authorized_keys | cut -d'|' -f1)" missing

  net_pairs
  code=$(as_ci curl -sS -o /dev/null -m 20 -w '%{http_code}' https://github.com 2>/dev/null || true)
  is net.ci.github "${CI_USER} HTTPS to github.com" "$code" 200
  code=$(as_ci curl -sSL -o /dev/null -r 0-0 -m 30 -w '%{http_code}' \
    "https://github.com/actions/runner/releases/download/v$RUNNER_VERSION/actions-runner-osx-arm64-$RUNNER_VERSION.tar.gz" 2>/dev/null || true)
  case "$code" in 200|206) pass net.ci.release-assets "${CI_USER} fetches a GitHub release asset (HTTP $code)" ;; *) fail net.ci.release-assets "release asset HTTP '$code'" ;; esac
  if as_owner curl -6 -sS -o /dev/null -m 8 https://www.google.com >/dev/null 2>&1; then
    if as_ci curl -6 -sS -o /dev/null -m 8 https://www.google.com >/dev/null 2>&1; then fail net.ipv6 "${CI_USER} reaches the IPv6 Internet"
    else pass net.ipv6 "IPv6 Internet reachable for owner, refused for ${CI_USER}"; fi
  else skip net.ipv6 "control failed: owner has no global IPv6 connectivity"; fi
  as_owner nc -l 127.0.0.1 18081 >/dev/null 2>&1 & ipid=$!
  as_ci nc -l 127.0.0.1 18080 >/dev/null 2>&1 & lpid=$!
  sleep 1
  if as_owner nc -4 -z -G 3 127.0.0.1 18081 >/dev/null 2>&1; then
    if as_owner nc -4 -z -G 3 127.0.0.1 18080 >/dev/null 2>&1; then fail net.inbound-local "owner connects to a ${CI_USER} listener"
    else pass net.inbound-local "owner listener reachable (control); ${CI_USER} listener refused"; fi
  else skip net.inbound-local "control failed: owner cannot reach its own listener"; fi
  stop_bg "$ipid" "$lpid"
  smb=$ARG2
  if [ -n "$smb" ]; then
    # One mountpoint per user, each owned by that user, so an ownership refusal cannot pass for a network block.
    mi=$(mktemp -d /private/tmp/qualify-smb-owner.XXXXXX); chown "$OWNER_USER" "$mi"; chmod 0700 "$mi"
    mc=$(mktemp -d /private/tmp/qualify-smb-ci.XXXXXX); chown "$CI_USER" "$mc"; chmod 0700 "$mc"
    if as_owner /sbin/mount_smbfs -N "//guest@$smb/IPC\$" "$mi" >/dev/null 2>&1; then
      umount "$mi" 2>/dev/null
      if as_ci /sbin/mount_smbfs -N "//guest@$smb/IPC\$" "$mc" >/dev/null 2>&1; then umount "$mc" 2>/dev/null; fail net.smb-mount "${CI_USER} mounts SMB from $smb"
      else pass net.smb-mount "SMB guest mount from $smb works for owner, refused for ${CI_USER} (own mountpoints)"; fi
    else skip net.smb-mount "control failed: owner cannot guest-mount SMB from $smb"; fi
    rmdir "$mi" "$mc" 2>/dev/null
  else skip net.smb-mount "no SMB host given (root <smb-host>): kernel SMB mounts are a residual (references/DESIGN.md)"; fi

  hdr "channels pf does not cover (accepted residuals pending the owner's decision, references/DESIGN.md)"
  for e in /private/var/run/*.sock /private/var/run/usbmuxd; do
    [ -S "$e" ] || continue
    case "$(stat -f %Lp "$e")" in *[2367]) ;; *) continue ;; esac
    if ! as_owner nc -U -z "$e" >/dev/null 2>&1; then skip "root-socket.${e##*/}" "control failed: owner cannot connect to $e either"
    elif as_ci nc -U -z "$e" >/dev/null 2>&1; then resid "root-socket.${e##*/}" "world-writable root socket $e accepts ${CI_USER} connections"
    else pass "root-socket.${e##*/}" "$e accepts owner (control), refuses ${CI_USER}"; fi
  done
  out=$(find /private/var/db/lockdown -maxdepth 1 -name '*.plist' ! -name SystemConfiguration.plist 2>/dev/null | wc -l | tr -d ' ')
  if [ "$out" = 0 ]; then pass usbmux.pairings "no iPhone/iPad is paired with the CI host"
  else resid usbmux.pairings "$out device pairing record(s): usbmuxd lets ${CI_USER} reach paired devices; unpair personal devices"; fi

  hdr "isolation as ${CI_USER}"
  yes_ iso.own-home "${CI_USER} lists its own home (control)" as_ci ls "$CI_HOME"
  denied iso.owner-home "${CI_USER} lists /Users/$OWNER_USER" as_ci ls "/Users/$OWNER_USER"
  denied iso.owner-zshrc "${CI_USER} reads /Users/$OWNER_USER/.zshrc" as_ci cat /Users/$OWNER_USER/.zshrc
  if as_ci test -e "$CI_HOME/.ssh/authorized_keys"; then fail iso.ssh "~${CI_USER}/.ssh/authorized_keys exists"; else pass iso.ssh "no ~/.ssh/authorized_keys"; fi
  ownerpid=$(pgrep -u "$OWNER_USER" -x Finder | head -1)
  if [ -n "$ownerpid" ]; then
    yes_ iso.signal-control "owner may signal its own Finder (control)" as_owner kill -0 "$ownerpid"
    denied iso.signal "${CI_USER} signals owner's Finder" as_ci kill -0 "$ownerpid"
  else skip iso.signal "no Finder process of owner to probe"; fi
  out=$(launchctl asuser $CI_UID sudo -u $CI_USER security list-keychains -d user 2>/dev/null)
  if [ -z "$out" ]; then skip iso.keychains "empty keychain search list (${CI_USER} never logged in?)"
  else is iso.keychains "keychain search list entries outside the CI home" "$(printf '%s\n' "$out" | grep -vc "$CI_HOME" | tr -d ' ')" 0; fi

  hdr "prevention: what a job cannot change (each refusal paired with a write that must work)"
  yes_ prev.diag-control "${CI_USER} creates and removes its own file in _diag (control)" as_ci sh -c ": > $RUNNER_DIR/_diag/qualify-probe && rm $RUNNER_DIR/_diag/qualify-probe"
  denied prev.runner-bin "${CI_USER} renames the root-owned runner bin" as_ci mv "$RUNNER_DIR/bin" "$RUNNER_DIR/bin.q"
  denied prev.runner-env "${CI_USER} truncates the root-owned .env" as_ci sh -c ": > $RUNNER_DIR/.env"
  denied prev.runner-runsvc "${CI_USER} removes runsvc.sh" as_ci rm -f "$RUNNER_DIR/runsvc.sh"
  yes_ prev.home-control "${CI_USER} creates and removes a file under ~/tmp (control)" as_ci sh -c ": > $CI_HOME/tmp/qualify-probe && rm $CI_HOME/tmp/qualify-probe"
  denied prev.launchagent "${CI_USER} plants a LaunchAgent" as_ci sh -c ": > $CI_HOME/Library/LaunchAgents/qualify.plist"
  denied prev.runner-plist "${CI_USER} edits the runner LaunchAgent" as_ci sh -c "echo x >> $RUNNER_PLIST"
  denied prev.zshenv "${CI_USER} writes ~/.zshenv" as_ci sh -c "echo x >> $CI_HOME/.zshenv"
  denied prev.gitconfig "${CI_USER} renames ~/.gitconfig" as_ci mv "$CI_HOME/.gitconfig" "$CI_HOME/.gitconfig.q"
  denied prev.library "${CI_USER} renames ~/Library" as_ci mv "$CI_HOME/Library" "$CI_HOME/Library.q"
  denied prev.ssh "${CI_USER} creates ~/.ssh/authorized_keys" as_ci sh -c ": > $CI_HOME/.ssh/authorized_keys"
  out=$(as_ci git config --global user.name qualify 2>&1 || true)
  case "$out" in *"could not lock"*) pass prev.git-global "git config --global fails at the lock placeholder ($(printf '%s' "$out" | head -1))" ;;
    *) fail prev.git-global "git config --global as ${CI_USER}: $out" ;; esac
  out=$(as_ci crontab -l 2>&1 || true)
  case "$out" in *"not allowed"*) pass prev.crontab "${CI_USER} may not use crontab (cron.deny)" ;; *) fail prev.crontab "crontab -l as ${CI_USER}: $out" ;; esac

  hdr "runner service"
  is runner.plist "LaunchAgent plist" "$(lmeta "$RUNNER_PLIST")" "Regular File|${CI_USER}:${CI_USER}|644|schg"
  is runner.launchagents "LaunchAgents directory" "$(lmeta "$CI_HOME/Library/LaunchAgents" | cut -d'|' -f4)" schg
  is runner.state "launchd state" "$(launchctl print "gui/$CI_UID/$RUNNER_LABEL" 2>/dev/null | awk '$1 == "state" && !seen++ {print $3}')" running
  for f in /Library/LaunchAgents/*.plist; do
    [ -f "$f" ] || continue
    l=$(plutil -extract Label raw -o - "$f" 2>/dev/null); case "$l" in ""|com.apple.*) continue ;; esac
    yes_ "ci-session.disabled.$l" "$l disabled in gui/$CI_UID" sh -c 'launchctl print-disabled "gui/$1" | grep -F "\"$2\" => disabled" >/dev/null' _ "$CI_UID" "$l"
  done

  hdr "the real job-started hook as ${CI_USER} (clean, then a planted change, then clean again)"
  out=$(hook); case "$out" in *"host guard: ok"*) pass hook.clean "start hook passes on the clean account" ;;
    *) fail hook.clean "start hook on the clean account: $(printf '%s' "$out" | tail -3 | tr '\n' ' ' | cut -c1-400)" ;; esac
  as_ci sh -c "mkdir -p $CI_HOME/Library/org.swift.swiftpm/configuration && echo '{}' > $CI_HOME/Library/org.swift.swiftpm/configuration/mirrors.json"
  out=$(hook); case "$out" in *"persistence baseline changed"*) pass hook.planted "planted SwiftPM mirrors.json fails the start hook" ;;
    *) fail hook.planted "start hook with a planted mirrors.json: $(printf '%s' "$out" | tail -2 | tr '\n' ' ' | cut -c1-300)" ;; esac
  as_ci rm -f "$CI_HOME/Library/org.swift.swiftpm/configuration/mirrors.json"
  out=$(hook); case "$out" in *"host guard: ok"*) pass hook.reverted "start hook passes again after the removal" ;;
    *) fail hook.reverted "start hook after removal: $(printf '%s' "$out" | tail -2 | tr '\n' ' ' | cut -c1-300)" ;; esac
  printf 'info  quarantine (root-only, delete after review): %s\n' "$(ls ${VOL_MOUNT}/.ci-quarantine 2>/dev/null | tr '\n' ' ')"
}

mode_root_postbuild() {
  need_root
  local w="$CI_HOME/tmp/qualify-postbuild" out
  hdr "start hook after one simulator boot and one xcodebuild as ${CI_USER} (run before admitting the first real job)"
  launchctl print "gui/$CI_UID" >/dev/null 2>&1 || { fail postbuild.session "${CI_USER} is not logged in"; finish; }
  yes_ postbuild.sim-boot "$SIMULATOR_NAME boots" ci_gui sh -c 'xcrun simctl boot "$1" && xcrun simctl bootstatus "$1" -b' _ "$SIMULATOR_NAME"
  yes_ postbuild.build "xcodebuild builds a fresh Swift package for the iOS Simulator" ci_gui sh -c \
    "rm -rf $w && mkdir -p $w/Probe && cd $w/Probe && swift package init --type library --name Probe >/dev/null && xcodebuild -quiet -scheme Probe -destination 'platform=iOS Simulator,name=$SIMULATOR_NAME' -derivedDataPath $w/dd build"
  ci_gui xcrun simctl shutdown all >/dev/null 2>&1 || true
  sleep 10
  out=$(hook)
  case "$out" in
    *"host guard: ok"*) pass postbuild.hook "start hook passes after a simulator boot and a build" ;;
    *) fail postbuild.hook "start hook refuses after a simulator boot and a build (full list below)"
       printf '%s\n' "$out" | tr ' ' '\n' | grep -E '^(job|proc|env|getenv):' | sed 's/^/      refused: /' || true
       printf '%s\n' "$out" | grep -v -E '^(job|proc):' | tail -3 | sed 's/^/      /' || true ;;
  esac
  ci_gui rm -rf "$w" >/dev/null 2>&1 || true
}

mode_root_inbound() {
  need_root
  local ipid lpid
  hdr "holding listeners for 180 s: owner on *:18081 (control), ${CI_USER} on *:18080. Run 'bash qualify.sh remote-inbound' on the admin workstation now"
  as_owner nc -lk 18081 >/dev/null 2>&1 & ipid=$!
  as_ci nc -lk 18080 >/dev/null 2>&1 & lpid=$!
  sleep 180
  stop_bg "$ipid" "$lpid"
  pass inbound.listeners "listeners held for 180 s and stopped (pids $ipid, $lpid)"
}

mode_root_boot() {
  need_root
  hdr "after a reboot, before the ${CI_USER} login"
  is boot.ci-processes "${CI_USER} processes (none before its login)" "$(ps -U $CI_UID -o pid= 2>/dev/null | wc -l | tr -d ' ')" 0
  yes_ boot.pf-daemon "pf LaunchDaemon loaded at boot" launchctl print system/${LABEL_PREFIX}.pf
  pf_checks
  net_pairs
  printf 'info  %s: %s\n' "$VOL_NAME" "$(mp=$(diskutil info -plist "$(cat "$SUPPORT/etc/volume-uuid" 2>/dev/null)" 2>/dev/null | plv MountPoint || true); printf '%s' "${mp:-not mounted (locked?)}")"
  printf 'info  runner: offline until the %s login (expected; check with remote mode)\n' "$CI_USER"
}

# ---------------------------------------------------------------------------------------------------------------
# ci: as ${CI_USER}, no sudo (inside a job on the runner, or a ${CI_USER} Terminal)
# ---------------------------------------------------------------------------------------------------------------
mode_ci() {
  local g out code t
  hdr "identity (the root mode proved the network controls as owner)"
  is ci.uid "uid" "$(id -u)" "$CI_UID"
  is ci.home "HOME" "${HOME:-}" "$CI_HOME"
  for g in $(id -Gn); do case "$g" in admin|staff|wheel|_developer|com.apple.access_ssh|com.apple.access_screensharing) fail ci.groups "member of $g" ;; esac; done
  printf 'info  groups: %s\n' "$(id -Gn)"
  is ci.session "launchd session type" "$(launchctl managername 2>/dev/null)" Aqua
  hdr "network"
  for t in "127.0.0.1 22" "::1 22" "100.100.100.100 53" "${TAILNET_PEER_IP:+$TAILNET_PEER_IP 22}"; do
    [ -n "$t" ] || { skip ci.blocked.tailnet-peer "TAILNET_PEER_IP not configured"; continue; }
    set -- $t
    if tcp "$1" "$2"; then fail "ci.blocked.$1:$2" "reachable as ${CI_USER}"; else pass "ci.blocked.$1:$2" "refused as ${CI_USER}"; fi
  done
  code=$(curl -sS -o /dev/null -m 20 -w '%{http_code}' https://github.com 2>/dev/null || true)
  is ci.github "HTTPS to github.com" "$code" 200
  hdr "isolation"
  yes_ ci.own-home "list own home (control)" ls "$CI_HOME"
  denied ci.owner-home "list /Users/$OWNER_USER" ls "/Users/$OWNER_USER"
  out=$(ssh-add -l 2>&1); case "$out" in *"no identities"*|*"Could not open"*|*"Error connecting"*) pass ci.ssh-agent "no SSH identities ($out)" ;; *) fail ci.ssh-agent "$out" ;; esac
  hdr "toolchain and job environment"
  is ci.developer-dir "DEVELOPER_DIR" "${DEVELOPER_DIR:-unset}" /Applications/Xcode.app/Contents/Developer
  yes_ ci.first-launch "xcodebuild -checkFirstLaunchStatus" xcodebuild -checkFirstLaunchStatus
  yes_ ci.simulator "simulator '$SIMULATOR_NAME' exists" sh -c 'xcrun simctl list devices | grep -F "$1 (" >/dev/null' _ "$SIMULATOR_NAME"
  is ci.tuist "tuist version" "$(TUIST_CONFIG_STATS_OPT_OUT=1 "$TOOLS_DIR/tuist/$TUIST_VERSION/tuist" version 2>/dev/null | tail -1)" "$TUIST_VERSION"
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    is ci.job.tmpdir "TMPDIR in the job" "${TMPDIR%/}" "$CI_HOME/tmp"
    is ci.job.git-nosystem "GIT_CONFIG_NOSYSTEM in the job" "${GIT_CONFIG_NOSYSTEM:-unset}" 1
    is ci.job.tuist-optout "TUIST_CONFIG_STATS_OPT_OUT in the job" "${TUIST_CONFIG_STATS_OPT_OUT:-unset}" 1
    is ci.job.bash-env "BASH_ENV in the job" "${BASH_ENV:-unset}" unset
    is ci.job.credential-helper "effective credential.helper" "$(git config --get-all credential.helper | tr '\n' '|')" "|"
  else skip ci.job "not inside a GitHub Actions job: job environment not checked"; fi
}

# ---------------------------------------------------------------------------------------------------------------
# quota-fixture: the CI host with sudo (the owner). Writes to an isolated 1 GiB test volume and deletes it again.
# ---------------------------------------------------------------------------------------------------------------
mode_quota_fixture() {
  need_root
  local name=${VOL_NAME}QuotaTest q=1073741824 c uuid mp d before after real_before real_after out
  echo "quota-fixture creates a 1 GiB APFS test volume $name, fills it as ${CI_USER} and deletes it again."
  printf 'Type YES to continue: '; read -r out; [ "$out" = YES ] || { echo "aborted"; exit 2; }
  c=$(diskutil info -plist /System/Volumes/Data | plv APFSContainerReference)
  diskutil info "$name" >/dev/null 2>&1 && { fail quota.fixture "a volume named $name already exists; not touching it"; finish; }
  real_before=$(df -k "$VOL_MOUNT" | awk 'NR == 2 {print $3}')
  diskutil apfs addVolume "$c" APFS "$name" -quota "$q" >/dev/null || { fail quota.fixture "addVolume failed"; finish; }
  uuid=$(diskutil info -plist "$name" | plv VolumeUUID); mp=$(diskutil info -plist "$uuid" | plv MountPoint)
  [ -n "$uuid" ] && [ "$mp" = "/Volumes/$name" ] || { fail quota.fixture "fixture not mounted at /Volumes/$name"; finish; }
  diskutil enableOwnership "$mp" >/dev/null
  d="$mp/ci"; mkdir "$d"; chown "$CI_USER:$CI_USER" "$d"
  before=$(df -k /System/Volumes/Data | awk 'NR == 2 {print $4}')
  if as_ci dd if=/dev/zero of="$d/a" bs=1048576 count=900 2>/dev/null; then pass quota.within "${CI_USER} writes 900 MiB inside a 1 GiB quota (control)"
  else fail quota.within "900 MiB write inside the quota failed"; fi
  out=$(as_ci dd if=/dev/zero of="$d/b" bs=1048576 count=300 2>&1)
  case "$out" in *"No space left on device"*|*"quota exceeded"*|*"Disc quota"*) pass quota.beyond "writing past the quota fails with ENOSPC" ;; *) fail quota.beyond "write past the quota: $(printf '%s' "$out" | tail -1)" ;; esac
  after=$(df -k /System/Volumes/Data | awk 'NR == 2 {print $4}')
  if [ $(( (before - after) / 1024 )) -le 1200 ]; then pass quota.container "container free space fell by at most the quota ($(( (before - after) / 1024 )) MiB)"
  else fail quota.container "container free space fell by $(( (before - after) / 1024 )) MiB"; fi
  real_after=$(df -k "$VOL_MOUNT" | awk 'NR == 2 {print $3}')
  if [ $((real_after - real_before)) -lt 65536 ]; then pass quota.real-volume "${VOL_NAME} usage moved by $((real_after - real_before)) KiB (< 64 MiB: the fixture never wrote there)"
  else fail quota.real-volume "${VOL_NAME} usage grew by $((real_after - real_before)) KiB during the fixture"; fi
  [ "$(diskutil info -plist "$uuid" | plv VolumeName)" = "$name" ] && diskutil apfs deleteVolume "$uuid" >/dev/null \
    && pass quota.cleanup "fixture volume $uuid deleted" || fail quota.cleanup "fixture $uuid NOT deleted; remove it by hand"
}

case "$MODE" in
  owner) mode_owner ;;
  remote) mode_remote ;;
  remote-inbound) mode_remote_inbound ;;
  root) mode_root ;;
  root-inbound) mode_root_inbound ;;
  root-postbuild) mode_root_postbuild ;;
  root-boot) mode_root_boot ;;
  ci) mode_ci ;;
  quota-fixture) mode_quota_fixture ;;
  *) echo "usage: bash qualify.sh owner|remote|remote-inbound|root [smb-host]|root-postbuild|root-inbound|root-boot|ci|quota-fixture" >&2; exit 2 ;;
esac
finish
