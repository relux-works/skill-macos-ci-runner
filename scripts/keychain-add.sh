#!/bin/bash
# keychain-add.sh KEYCHAIN_SERVICE [--update]: store the CI volume passphrase in the System keychain for the optional
# boot unlock (scripts/volume-unlock.sh; references/RUNBOOK.md 10). Run by the owner in a terminal; it calls sudo.
#
# Root has no default keychain, and `security add-generic-password ... -w` prompts only when -w is the last argument,
# so it cannot both prompt and name a keychain (references/PITFALLS.md 18). This script names
# /Library/Keychains/System.keychain explicitly: it reads the passphrase silently, hex-encodes it, and sends
# `add-generic-password ... -X <hex> /Library/Keychains/System.keychain` to `sudo security -i` on stdin, so the
# passphrase never appears in argv, the environment, a file or the terminal. It then requires find-generic-password
# to find the item there.
#
# Re-runs: an existing item is reported and left alone (exit 0), so a repeated run cannot silently replace a working
# passphrase. --update replaces it (add-generic-password -U); use it when diskutil refuses the stored passphrase.
set -euo pipefail
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH LC_ALL=C
readonly KC=/Library/Keychains/System.keychain ACCOUNT=volume LABEL=CI-volume

say() { printf '%s\n' "$*"; }
need_tty() { [ -t 0 ]; }
die() { printf 'keychain-add: %s\n' "$*" >&2; exit 1; }

# item_exists <service>: the item is in the System keychain (attributes only, never the secret).
item_exists() { sudo -H security find-generic-password -a "$ACCOUNT" -s "$1" "$KC" >/dev/null 2>&1; }

# store <service> <update: 0|1>: read the passphrase twice from stdin and store it. Returns non-zero, with nothing
# sent to security, on an empty passphrase or two different entries.
store() {
  local service=$1 update=$2 p q hex upd="" err
  IFS= read -r -s -p "Volume passphrase: " p || p=""; printf '\n' >&2
  IFS= read -r -s -p "Again: " q || q=""; printf '\n' >&2
  [ -n "$p" ] || die "empty passphrase refused; nothing changed"
  [ "$p" = "$q" ] || die "the two entries differ; nothing changed"
  hex=$(printf '%s' "$p" | od -An -v -tx1 | tr -d ' \n'); p=""; q=""
  [[ $hex =~ ^([0-9a-f]{2})+$ ]] || die "hex encoding failed; nothing changed"
  [ "$update" = 1 ] && upd=" -U"
  sudo -v
  err=$(printf 'add-generic-password -a %s -s %s -l %s -T /usr/bin/security%s -X %s %s\n' \
          "$ACCOUNT" "$service" "$LABEL" "$upd" "$hex" "$KC" | sudo -H security -i 2>&1 >/dev/null) || true
  hex=""
  [ -z "$err" ] || die "security refused the item: $(printf '%s' "$err" | head -1 | cut -c1-200)"
  item_exists "$service" || die "the item is not in $KC after the add"
  say "stored in the System keychain: ok"
}

main() {
  local service=${1:-} mode=${2:-} update=0
  [[ $service =~ ^[a-z0-9-]+(\.[a-z0-9-]+){2,6}$ ]] || die "usage: keychain-add.sh <LABEL_PREFIX>.volume [--update]"
  case "$mode" in "") ;; --update) update=1 ;; *) die "usage: keychain-add.sh <LABEL_PREFIX>.volume [--update]" ;; esac
  need_tty || die "needs a terminal: the passphrase is read silently from it"
  sudo -v
  if item_exists "$service"; then
    if [ "$update" = 0 ]; then
      say "an item for $service (account $ACCOUNT) already exists in the System keychain; nothing changed (--update replaces it)"
      exit 0
    fi
  else
    update=0
  fi
  store "$service" "$update"
}

main "$@"
