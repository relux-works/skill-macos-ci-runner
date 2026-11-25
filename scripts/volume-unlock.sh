#!/bin/bash
# volume-unlock.sh SUPPORT_ROOT KEYCHAIN_SERVICE VOL_MOUNT: OPTIONAL boot-time unlock of the CI volume
# (references/RUNBOOK.md, "Optional: unlock the CI volume at boot").
#
# Run as root by a LaunchDaemon at boot, before any login. Reads the volume UUID from SUPPORT_ROOT/etc/volume-uuid
# (written by host-prep.sh) and the volume passphrase from the System keychain item KEYCHAIN_SERVICE (account
# "volume") into a shell variable, and hands it to diskutil on stdin with the printf builtin: it never appears in
# argv, the environment, a file or a log. A missing item or an empty passphrase never reaches diskutil: the run
# fails with "no passphrase item" instead (references/PITFALLS.md 18). Success means: the volume is mounted
# exactly at VOL_MOUNT and VOL_MOUNT/home exists.
#
# Trade-off (owner decision): with this installed, the volume's own passphrase no longer protects anything beyond
# FileVault, because root can read it at every boot. FileVault stays the at-rest guard. Without it, the owner unlocks
# the volume by hand after every reboot, before the CI account logs in.
#
# Idempotent: does nothing when the volume is already mounted where expected. Refuses malformed arguments first,
# then a non-root caller, then a support tree that is not root-owned or is writable by group or others.
set -euo pipefail
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH LC_ALL=C

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
fail() { log "FAILED: $*"; exit 1; }

# volume_mounted <uuid> <expected mount point>: true only when `diskutil info -plist` reports Locked = false and a
# non-empty MountPoint equal to the expected path, and the CI home tree is present there. A locked or unmounted
# volume has an empty MountPoint; a volume mounted elsewhere (for example "<VOL_MOUNT> 1") is not success either.
# A missing Locked or MountPoint key fails closed.
volume_mounted() {
  local info locked mp
  info=$(diskutil info -plist "$1" 2>/dev/null) || return 1
  locked=$(printf '%s' "$info" | plutil -extract Locked raw -o - - 2>/dev/null) || return 1
  mp=$(printf '%s' "$info" | plutil -extract MountPoint raw -o - - 2>/dev/null) || return 1
  [ "$locked" = false ] && [ -n "$mp" ] && [ "$mp" = "$2" ] && [ -d "$2/home" ]
}

# trusted <path>: root:wheel, not a symlink, and no write bit for group or others (digits 0, 1, 4 or 5 only).
trusted() {
  [ ! -L "$1" ] || return 1
  case "$(stat -f '%Su:%Sg %Mp%03Lp' "$1" 2>/dev/null)" in root:wheel\ 0[0-7][0145][0145]) return 0 ;; esac
  return 1
}

# unlock_volume <uuid> <service>: up to 6 attempts, 10 s apart (the keychain may not be ready early at boot). Each
# attempt reads the passphrase from /Library/Keychains/System.keychain and calls diskutil only when it is
# non-empty. Returns 0 after a successful unlockVolume, 1 when every unlockVolume failed, and 3 when no attempt found
# a passphrase (diskutil was never called). A failed unlockVolume is logged with diskutil's exit status and first
# output line (a wrong passphrase, a volume that is already unlocked, or another error), never the passphrase.
unlock_volume() {
  local n pass out st found=0
  for n in 1 2 3 4 5 6; do
    pass=$(security find-generic-password -s "$2" -a volume -w /Library/Keychains/System.keychain 2>/dev/null) || pass=""
    if [ -z "$pass" ]; then
      log "attempt $n: no passphrase item '$2' (account volume) in /Library/Keychains/System.keychain"
    else
      found=1
      # The same bytes `security -w` prints: the passphrase and one newline.
      if out=$(printf '%s\n' "$pass" | diskutil apfs unlockVolume "$1" -stdinpassphrase 2>&1); then pass=""; return 0; else st=$?; fi
      log "attempt $n: diskutil apfs unlockVolume failed (exit $st): $(printf '%s\n' "$out" | grep -v '^[[:space:]]*$' | head -1 | cut -c1-200)"
    fi
    pass=""
    [ "$n" = 6 ] || sleep 10
  done
  [ "$found" = 0 ] && return 3
  return 1
}

main() {
  local support=${1:-} service=${2:-} expect=${3:-} uuid p rc
  [[ $support =~ ^/opt/[a-z0-9][a-z0-9._-]{0,40}$ ]] || fail "SUPPORT_ROOT '$support' is not /opt/<name>"
  [[ $service =~ ^[a-z0-9-]+(\.[a-z0-9-]+){2,6}$ ]] || fail "keychain service '$service' is not a reverse-DNS name"
  [[ $expect =~ ^/Volumes/[A-Za-z][A-Za-z0-9]{1,30}$ ]] || fail "VOL_MOUNT '$expect' is not /Volumes/<VOL_NAME>"
  [ "$(id -u)" = 0 ] || fail "must run as root"
  for p in "$support" "$support/etc" "$support/etc/volume-uuid"; do
    trusted "$p" || fail "$p must be root:wheel, not a symlink, and not group/other-writable"
  done
  uuid=$(tr -d '[:space:]' <"$support/etc/volume-uuid")
  [[ $uuid =~ ^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$ ]] || fail "volume-uuid is not an APFS volume UUID"

  if volume_mounted "$uuid" "$expect"; then log "already mounted at $expect"; exit 0; fi
  rc=0; unlock_volume "$uuid" "$service" || rc=$?
  [ "$rc" != 3 ] || fail "no passphrase item '$service' (account volume) in /Library/Keychains/System.keychain; diskutil was not called. Store it as in references/RUNBOOK.md 10 (PITFALLS.md 18)"
  if volume_mounted "$uuid" "$expect"; then log "unlocked and mounted at $expect"; exit 0; fi
  fail "$uuid is not mounted at $expect with a home directory after the unlock attempts"
}

main "$@"
