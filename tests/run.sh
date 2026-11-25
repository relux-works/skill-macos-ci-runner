#!/bin/bash
# Offline unit tests for the helpers of scripts/host-prep.sh, scripts/qualify.sh and scripts/volume-unlock.sh.
# They never touch the host: each test extracts one helper (or the config loader) from the scripts and runs it
# against fixtures, with system commands such as id, stat and diskutil replaced by stubs where needed.
# Works with macOS /bin/bash 3.2 and Linux bash; tests that need BSD stat are SKIPPED elsewhere, never PASSED.
set -u
cd "$(dirname "$0")/.." || exit 2
HP=scripts/host-prep.sh
Q=scripts/qualify.sh
P=0; F=0; S=0
pass() { P=$((P + 1)); printf 'PASS  %s\n' "$*"; }
fail() { F=$((F + 1)); printf 'FAIL  %s\n' "$*"; }
skip() { S=$((S + 1)); printf 'SKIP  %s\n' "$*"; }
TMP=$(mktemp -d "${TMPDIR:-/tmp}/macos-ci-tests.XXXXXX") || exit 2
trap 'rm -rf "$TMP"' EXIT

# fn <file> <name>: print the definition of shell function <name> (one-line or multi-line) from <file>.
fn() {
  python3 -I - "$1" "$2" <<'PY'
import re, sys
lines = open(sys.argv[1]).read().split("\n"); name = sys.argv[2]; out = []
for i, l in enumerate(lines):
    if re.match(r"^%s\(\) \{" % re.escape(name), l):
        out.append(l)
        if not l.rstrip().endswith("}"):
            for m in lines[i + 1:]:
                out.append(m)
                if m == "}":
                    break
        break
if not out:
    sys.exit("no function %s in %s" % (name, sys.argv[1]))
print("\n".join(out))
PY
}
# loader <file>: the config-loader block between its markers.
loader() { sed -n '/^# >>> config-loader/,/^# <<< config-loader/p' "$1"; }

# run_conf <config file>: load the config with the host-prep loader in a fresh non-root shell; print the values.
run_conf() {
  bash -c "$(loader "$HP")
load_config \"\$1\"
printf '%s|%s|%s|%s|%s\n' \"\$CI_USER\" \"\$CI_UID\" \"\$CI_FULLNAME\" \"\$EXPECTED_MODEL\" \"\$SUPPORT_ROOT\"" _ "$1" 2>&1
}
# conf_with <sed expression>: a copy of the example config edited by sed, as a file path.
conf_with() { local f; f=$(mktemp "$TMP/conf.XXXXXX"); sed -e "$1" examples/ci-runner.conf >"$f"; echo "$f"; }
# expect_refused <id> <config file> <message part>: the loader must exit 2 with that message.
expect_refused() {
  local out rc
  out=$(run_conf "$2"); rc=$?
  if [ "$rc" = 2 ] && printf '%s' "$out" | grep -qF "$3"; then pass "$1: refused ($3)"
  else fail "$1: rc=$rc out=$(printf '%s' "$out" | head -2 | tr '\n' ' ')"; fi
}

# --- config loader ------------------------------------------------------------------------------------------
# Claim: both scripts carry the same loader, so a fix in one cannot silently miss the other.
if diff <(loader "$HP") <(loader "$Q") >/dev/null && [ -n "$(loader "$HP")" ]; then pass "loader.identical"
else fail "loader.identical: the config-loader blocks differ or are missing"; fi

# Claim (positive control for every refusal below): the documented example loads and yields its values,
# including a value with a space and an empty optional key.
out=$(run_conf examples/ci-runner.conf); rc=$?
if [ "$rc" = 0 ] && [ "$out" = "ci-runner|550|CI Runner||/opt/macos-ci" ]; then pass "loader.example: $out"
else fail "loader.example: rc=$rc out=$out"; fi

# Claims (negative): the loader refuses each malformed config with exit 2 and a specific message, before any
# value is used: unknown keys, duplicates, shell metacharacters, missing keys, unsafe UIDs and inconsistent sizes.
expect_refused loader.unknown-key "$(conf_with '$a\
EVIL=1')" "unknown key 'EVIL'"
expect_refused loader.duplicate "$(conf_with '$a\
CI_UID=551')" "'CI_UID' is set twice"
expect_refused loader.metachar "$(conf_with 's/^CI_USER=.*/CI_USER=ci;touch \/tmp\/x/')" "CI_USER='ci;touch"
expect_refused loader.cmdsubst "$(conf_with 's/^SUPPORT_ROOT=.*/SUPPORT_ROOT=\/opt\/$(id)/')" "SUPPORT_ROOT="
expect_refused loader.missing "$(conf_with '/^RUNNER_SHA256=/d')" "required key RUNNER_SHA256 is missing"
expect_refused loader.low-uid "$(conf_with 's/^CI_UID=.*/CI_UID=499/')" "must be above 500"
expect_refused loader.owner-uid "$(conf_with 's/^CI_UID=.*/CI_UID=501/')" "must differ from the owner"
expect_refused loader.reserve "$(conf_with 's/^VOL_RESERVE_BYTES=.*/VOL_RESERVE_BYTES=207374182400/')" "exceeds VOL_QUOTA_BYTES"
expect_refused loader.no-equals "$(conf_with '$a\
CI_USER')" "is not KEY=VALUE"
expect_refused loader.bad-sha "$(conf_with 's/^TUIST_SHA256=.*/TUIST_SHA256=ABC/')" "TUIST_SHA256='ABC'"
expect_refused loader.support-outside-opt "$(conf_with 's/^SUPPORT_ROOT=.*/SUPPORT_ROOT=\/Users\/x/')" "SUPPORT_ROOT='/Users/x'"
expect_refused loader.missing-file "$TMP/does-not-exist" "is missing or not a regular file"
expect_refused loader.key-name "$(conf_with '$a\
HOST_TAILNET_IP TAILNET_PEER_IP=10.0.0.1')" "is not a key name"
expect_refused loader.uid-leading-zero "$(conf_with 's/^CI_UID=.*/CI_UID=0550/')" "CI_UID='0550'"
expect_refused loader.small-quota "$(conf_with 's/^VOL_QUOTA_BYTES=.*/VOL_QUOTA_BYTES=21474836480/;s/^VOL_RESERVE_BYTES=.*/VOL_RESERVE_BYTES=10737418240/')" "at least 34359738368"

# --- root trust predicates ----------------------------------------------------------------------------------
# id and stat are stubs here: the claims concern the predicates, not the host. The group and other digits of an
# accepted mode may only be 0, 1, 4 or 5 (no write bit); each refused mode carries exactly one such write bit
# somewhere, so a predicate that only looks at one digit, or only at 6 and 7, fails at least one case.
TRUST_OK="0600 0644 0755 0700 0511 0400"
TRUST_BAD="0602 0622 0724 0620 0720 0633 0646 0664 0612 0603 0777"
# trust_conf <file meta> <dir meta> <parent meta> [path] [uid]: exit status of the loader's conf_trusted.
trust_conf() {
  FM=$1 DM=$2 PM=$3 TUID=${5:-0} bash -c "$(fn "$HP" conf_die)
$(fn "$HP" conf_trusted)
id() { echo \"\$TUID\"; }
stat() { local p; for p; do :; done; case \$p in */etc/conf) echo \"\$FM\" ;; */etc) echo \"\$DM\" ;; *) echo \"\$PM\" ;; esac; }
conf_trusted \"\$1\"" _ "${4:-/fx/etc/conf}" >/dev/null 2>&1
}
# trust_vu <meta> [path]: exit status of volume-unlock.sh's trusted.
trust_vu() {
  M=$1 bash -c "$(fn scripts/volume-unlock.sh trusted)
stat() { echo \"\$M\"; }
trusted \"\$1\"" _ "${2:-/fx/x}" >/dev/null 2>&1
}
# Claim (positive control): root:wheel files without a group/other write bit pass, under a 0755 directory and parent.
bad=""; for m in $TRUST_OK; do trust_conf "root:wheel $m" "root:wheel 0755" "root:wheel 0755" || bad="$bad $m"; done
if [ -z "$bad" ]; then pass "trust.conf.accepts: $TRUST_OK"; else fail "trust.conf.accepts: refused$bad"; fi
# Claim (negative): any group or other write bit on the file is refused (0602, 0622, 0724 and neighbours).
bad=""; for m in $TRUST_BAD; do trust_conf "root:wheel $m" "root:wheel 0755" "root:wheel 0755" && bad="$bad $m"; done
if [ -z "$bad" ]; then pass "trust.conf.refuses-file: $TRUST_BAD"; else fail "trust.conf.refuses-file: accepted$bad"; fi
# Claim (negative): a writable directory or support root, a non-root owner or group, and a symlinked file are refused.
bad=""
trust_conf "root:wheel 0644" "root:wheel 0775" "root:wheel 0755" && bad="$bad dir-0775"
trust_conf "root:wheel 0644" "root:wheel 0755" "root:wheel 0757" && bad="$bad parent-0757"
trust_conf "admin:wheel 0644" "root:wheel 0755" "root:wheel 0755" && bad="$bad owner-admin"
trust_conf "root:staff 0644" "root:wheel 0755" "root:wheel 0755" && bad="$bad group-staff"
mkdir -p "$TMP/tr/etc"; ln -s /dev/null "$TMP/tr/etc/conf"
trust_conf "root:wheel 0644" "root:wheel 0755" "root:wheel 0755" "$TMP/tr/etc/conf" && bad="$bad symlink"
mkdir -p "$TMP/tr2/real" "$TMP/tr3/real/etc"; ln -s "$TMP/tr2/real" "$TMP/tr2/etc"; : >"$TMP/tr2/real/conf"
ln -s "$TMP/tr3/real" "$TMP/tr3/sup"; : >"$TMP/tr3/real/etc/conf"
trust_conf "root:wheel 0644" "root:wheel 0755" "root:wheel 0755" "$TMP/tr2/etc/conf" && bad="$bad symlinked-dir"
trust_conf "root:wheel 0644" "root:wheel 0755" "root:wheel 0755" "$TMP/tr3/sup/etc/conf" && bad="$bad symlinked-parent"
if [ -z "$bad" ]; then pass "trust.conf.refuses-tree: dir, parent, owner, group, symlinked file, dir and parent"; else fail "trust.conf.refuses-tree: accepted$bad"; fi
# Claim: an unprivileged run skips the check (it cannot alter anything a root run trusts).
if trust_conf "admin:staff 0666" "admin:staff 0777" "admin:staff 0777" /fx/etc/conf 501; then pass "trust.conf.non-root-skips"
else fail "trust.conf.non-root-skips: refused"; fi
# Claims: volume-unlock.sh applies the same rule to its support tree, and refuses symlinks and other owners.
bad=""; for m in $TRUST_OK; do trust_vu "root:wheel $m" || bad="$bad $m"; done
if [ -z "$bad" ]; then pass "trust.vu.accepts: $TRUST_OK"; else fail "trust.vu.accepts: refused$bad"; fi
bad=""; for m in $TRUST_BAD; do trust_vu "root:wheel $m" && bad="$bad $m"; done
trust_vu "admin:wheel 0644" && bad="$bad owner-admin"
trust_vu "root:wheel 0644" "$TMP/tr/etc/conf" && bad="$bad symlink"
if [ -z "$bad" ]; then pass "trust.vu.refuses: $TRUST_BAD, other owner, symlink"; else fail "trust.vu.refuses: accepted$bad"; fi

# --- preflight --ioc site lists -----------------------------------------------------------------------------
# lmeta is a stub; the file exists for real. Claim: an optional site list (root-home-allow, indicator-paths) is used
# only when it is a root:wheel regular file without group/other write; any other state is a FINDING and the list is
# ignored, so a list the CI account could write can never suppress a finding. An absent list is silent.
site_rc() {  # <lmeta string> <path>: prints "<exit status> <finding count>"
  LM=$1 bash -c "$(fn "$HP" site_list)
n=0; finding() { n=\$((n + 1)); }
lmeta() { echo \"\$LM\"; }
site_list \"\$1\"; echo \"\$? \$n\"" _ "$2"
}
: >"$TMP/site-list"; bad=""
[ "$(site_rc 'Regular File|root:wheel|644|-' "$TMP/site-list")" = "0 0" ] || bad="$bad ok-644"
[ "$(site_rc 'Regular File|root:wheel|600|-' "$TMP/site-list")" = "0 0" ] || bad="$bad ok-600"
[ "$(site_rc 'Regular File|root:wheel|664|-' "$TMP/site-list")" = "1 1" ] || bad="$bad group-write"
[ "$(site_rc 'Regular File|root:wheel|646|-' "$TMP/site-list")" = "1 1" ] || bad="$bad other-write"
[ "$(site_rc 'Regular File|root:wheel|4644|-' "$TMP/site-list")" = "1 1" ] || bad="$bad setuid"
[ "$(site_rc 'Regular File|ci-runner:staff|644|-' "$TMP/site-list")" = "1 1" ] || bad="$bad owner"
[ "$(site_rc 'Symbolic Link|root:wheel|755|-' "$TMP/site-list")" = "1 1" ] || bad="$bad symlink"
[ "$(site_rc 'Directory|root:wheel|755|-' "$TMP/site-list")" = "1 1" ] || bad="$bad directory"
[ "$(site_rc 'missing' "$TMP/no-such-list")" = "1 0" ] || bad="$bad absent"
if [ -z "$bad" ]; then pass "ioc.site-list: trusted lists used; writable, setuid, foreign, symlink and directory refused; absent silent"
else fail "ioc.site-list:$bad"; fi

# --- render -------------------------------------------------------------------------------------------------
render_env='CI_USER=ci-runner CI_UID=550 CI_HOME=/Volumes/CIVolume/home/ci-runner SUPPORT=/opt/macos-ci
VOL_MOUNT=/Volumes/CIVolume VOL_NAME=CIVolume RUNNER_LABEL=actions.runner.example-org.mac-ci-1
RUNNER_PLIST=/x/y.plist LABEL_PREFIX=org.example.macos-ci PF_ANCHOR_NAME=MacOSCI CI_FULLNAME="CI Runner" RUNNER_NAME=mac-ci-1'
# Claim: render replaces every placeholder with the configured value (pf rule, label, path).
out=$(bash -c "$render_env
$(fn "$HP" render)
printf '%s\n' 'block in all user __CI_UID__' '<string>__LABEL_PREFIX__.pf</string>' '__SUPPORT__/sbin/x' | render")
want=$'block in all user 550\n<string>org.example.macos-ci.pf</string>\n/opt/macos-ci/sbin/x'
if [ "$out" = "$want" ]; then pass "render.fills"; else fail "render.fills: got $(printf '%s' "$out" | tr '\n' '|')"; fi
# Claim (negative): render fails on a placeholder it does not know, so a template typo cannot install a broken file.
if bash -c "$render_env
$(fn "$HP" render)
printf '%s\n' 'x __NOT_A_KEY__ y' | render" >/dev/null 2>&1; then fail "render.unknown-token: accepted"
else pass "render.unknown-token: refused"; fi
# Claim (negative): render fails on empty input instead of installing an empty file.
if bash -c "$render_env
$(fn "$HP" render)
printf '' | render" >/dev/null 2>&1; then fail "render.empty: accepted"; else pass "render.empty: refused"; fi

# Claim: every template host-prep.sh installs (hooks, pf anchors, LaunchDaemons, sshd drop-in, runner .env,
# .gitconfig) renders with the example config and keeps no placeholder, so no generated file can carry one.
tpl_dir="$TMP/templates"; mkdir -p "$tpl_dir"
python3 -I - "$HP" "$tpl_dir" <<'PY'
import re, sys
lines = open(sys.argv[1]).read().split("\n"); n = 0; body = None
for l in lines:
    if body is not None:
        if l == end:
            open("%s/%02d-%s" % (sys.argv[2], n, end), "w").write("\n".join(body) + "\n"); body = None; continue
        body.append(l); continue
    m = re.match(r"^\s*with_render .* <<'([A-Z_]+)'$", l)
    if m:
        n += 1; end = m.group(1); body = []
PY
ntpl=$(ls "$tpl_dir" | wc -l | tr -d ' ')
bad=0; nsh=0; npl=0; mkdir -p "$TMP/rendered"
for t in "$tpl_dir"/*; do
  r="$TMP/rendered/${t##*/}"
  if ! bash -c "$(loader "$HP")
load_config examples/ci-runner.conf
readonly VOL_MOUNT=/Volumes/\$VOL_NAME; CI_HOME=\$VOL_MOUNT/home/\$CI_USER; SUPPORT=\$SUPPORT_ROOT
RUNNER_LABEL=actions.runner.\$RUNNER_ORG.\$RUNNER_NAME; RUNNER_PLIST=\$CI_HOME/Library/LaunchAgents/\$RUNNER_LABEL.plist
$(fn "$HP" render)
render <\"$t\" >\"$r\"" 2>/dev/null; then bad=$((bad + 1)); printf '      unrendered: %s\n' "${t##*/}"; continue; fi
  # Rendered shell scripts must parse; rendered plists must lint (plutil exists only on macOS).
  case "$(head -1 "$r")" in
    '#!'*) nsh=$((nsh + 1)); bash -n "$r" 2>/dev/null || { bad=$((bad + 1)); printf '      bash -n failed: %s\n' "${t##*/}"; } ;;
    '<?xml'*) if command -v plutil >/dev/null 2>&1; then npl=$((npl + 1))
                plutil -lint "$r" >/dev/null 2>&1 || { bad=$((bad + 1)); printf '      plutil -lint failed: %s\n' "${t##*/}"; }; fi ;;
  esac
done
if [ "$ntpl" -ge 12 ] && [ "$nsh" -ge 4 ] && [ "$bad" = 0 ]; then pass "render.all-templates: $ntpl templates, $nsh parse as bash, $npl plists lint"
else fail "render.all-templates: $ntpl templates ($nsh shell, $npl plists), $bad failed"; fi

# --- sshd -T parsing ----------------------------------------------------------------------------------------
# Claim: sshd_value reads the effective value whatever the key case: OpenSSH 10.x prints CamelCase, older releases
# lower case. Both helpers (host-prep and qualify) are tested; a missing key yields an empty value.
for script in "$HP" "$Q"; do
  for style in camel lower; do
    out=$(bash -c "sshd() { if [ $style = camel ]; then printf 'Port 22\nPermitRootLogin no\nDenyUsers ci-runner\n'; else printf 'port 22\npermitrootlogin no\ndenyusers ci-runner\n'; fi; }
$(fn "$script" sshd_value)
printf '%s|%s|%s' \"\$(sshd_value DenyUsers)\" \"\$(sshd_value PermitRootLogin)\" \"\$(sshd_value AllowUsers)\"")
    if [ "$out" = "ci-runner|no|" ]; then pass "sshd_value.$style ($script)"; else fail "sshd_value.$style ($script): $out"; fi
  done
done

# --- BSD stat mode readback ---------------------------------------------------------------------------------
if stat -f '%Mp%03Lp' / >/dev/null 2>&1; then
  d="$TMP/modes"; mkdir -p "$d"
  for m in 1775 0755 1077 0177 0700; do mkdir "$d/d$m"; chmod "$m" "$d/d$m"; done
  for script in "$HP" "$Q"; do
    defs="$(fn "$script" lmeta)
$(fn "$script" perm_of)"
    # Claim: lmeta shows the sticky digit (1775), drops only a leading zero (755, 700), and keeps 1077 and 0177
    # apart; plain %Lp printed 775 for a 1775 directory, so the readback check could never pass.
    out=$(bash -c "$defs
for m in 1775 0755 1077 0177 0700; do lmeta \"$d/d\$m\" | cut -d'|' -f3; done" | tr '\n' ' ')
    if [ "$out" = "1775 755 1077 177 700 " ]; then pass "lmeta.modes ($script): $out"; else fail "lmeta.modes ($script): $out"; fi
    # Claim: perm_of agrees with lmeta on the mode field.
    out=$(bash -c "$defs
perm_of \"$d/d1775\" | awk '{print \$2}'")
    if [ "$out" = 1775 ]; then pass "perm_of.sticky ($script)"; else fail "perm_of.sticky ($script): $out"; fi
    # Claim (negative): a missing path reads as 'missing', never as a mode.
    out=$(bash -c "$defs
lmeta \"$d/nope\"")
    if [ "$out" = missing ]; then pass "lmeta.missing ($script)"; else fail "lmeta.missing ($script): $out"; fi
  done
else
  skip "lmeta/perm_of: BSD stat (-f) not available on this system; these helpers run only on macOS"
fi

# --- stop_bg ------------------------------------------------------------------------------------------------
# A wrapper that does not pass its TERM on to its child stands in for sudo, which does not relay a signal sent
# from its own process group.
wrapper() { bash -c 'sleep 300 & wait' & }
child_of() { pgrep -P "$1" 2>/dev/null | head -1; }
# Claim (control): killing only the wrapper leaves the child running, which is the leak stop_bg exists for.
wrapper; w=$!; sleep 0.5; c=$(child_of "$w")
kill "$w" 2>/dev/null; wait "$w" 2>/dev/null; sleep 0.3
if [ -n "$c" ] && kill -0 "$c" 2>/dev/null; then pass "stop_bg.control: the child outlives a plain kill"; kill "$c" 2>/dev/null
else fail "stop_bg.control: could not reproduce the leaked child (child=${c:-none})"; fi
# Claim: stop_bg ends the child by its parent PID and then the wrapper.
eval "$(fn "$Q" stop_bg)"
wrapper; w=$!; sleep 0.5; c=$(child_of "$w")
stop_bg "$w"; sleep 0.3
if [ -n "$c" ] && ! kill -0 "$c" 2>/dev/null && ! kill -0 "$w" 2>/dev/null; then pass "stop_bg.kills-child"
else fail "stop_bg.kills-child: child=${c:-none} still alive or wrapper alive"; [ -n "$c" ] && kill "$c" 2>/dev/null; fi

# --- volume-unlock argument guard ---------------------------------------------------------------------------
# Claims (negative): the boot unlock refuses a support path outside /opt, a malformed keychain service and a mount
# point other than /Volumes/<name> before anything else, and refuses an unprivileged caller next. The valid call
# (last case) is the positive control: it gets past the argument checks and stops only at the root check.
vu_case() {  # <id> <message part> <args...>
  local id=$1 want=$2 out rc; shift 2
  out=$(bash scripts/volume-unlock.sh "$@" 2>&1); rc=$?
  if [ "$rc" != 0 ] && printf '%s' "$out" | grep -qF "$want"; then pass "volume-unlock.$id: refused ($want)"
  else fail "volume-unlock.$id: rc=$rc $out"; fi
}
vu_case support-outside-opt "is not /opt/<name>" /Users/x org.example.macos-ci.volume /Volumes/CIVolume
vu_case support-traversal "is not /opt/<name>" /opt/../etc org.example.macos-ci.volume /Volumes/CIVolume
vu_case bad-service "is not a reverse-DNS name" /opt/macos-ci 'org example' /Volumes/CIVolume
vu_case bad-mount "is not /Volumes/<VOL_NAME>" /opt/macos-ci org.example.macos-ci.volume /tmp/x
vu_case mount-duplicate "is not /Volumes/<VOL_NAME>" /opt/macos-ci org.example.macos-ci.volume "/Volumes/CIVolume 1"
vu_case missing-mount "is not /Volumes/<VOL_NAME>" /opt/macos-ci org.example.macos-ci.volume
if [ "$(id -u)" != 0 ]; then vu_case non-root "must run as root" /opt/macos-ci org.example.macos-ci.volume /Volumes/CIVolume
else skip "volume-unlock.non-root: the tests run as root"; fi

# --- volume-unlock mount state ------------------------------------------------------------------------------
# diskutil is a stub that prints a plist fixture; plutil is the real one, so these run only on macOS.
if command -v plutil >/dev/null 2>&1; then
  mnt="$TMP/vol/CIVolume"; mkdir -p "$mnt/home" "$TMP/vol/NoHome"
  # fixture <name> <Locked: true|false|-> <MountPoint>: write a `diskutil info -plist`-shaped fixture.
  fixture() {
    python3 -I - "$TMP/fx-$1.plist" "$2" "$3" <<'PY'
import plistlib, sys
d = {"FileVault": True, "Encryption": True, "MountPoint": sys.argv[3], "VolumeName": "CIVolume"}
if sys.argv[2] != "-":
    d["Locked"] = sys.argv[2] == "true"
open(sys.argv[1], "wb").write(plistlib.dumps(d))
PY
  }
  mounted_rc() {  # <fixture name> <expected mount point>: exit status of volume_mounted
    FIX="$TMP/fx-$1.plist" bash -c "$(fn scripts/volume-unlock.sh volume_mounted)
diskutil() { cat \"\$FIX\"; }
volume_mounted 00000000-0000-0000-0000-000000000000 \"\$1\"" _ "$2" >/dev/null 2>&1
  }
  fixture locked true ""; fixture unlocked false ""; fixture mounted false "$mnt"; fixture elsewhere false "$mnt 1"
  fixture nohome false "$TMP/vol/NoHome"; fixture nolockkey - "$mnt"; fixture inconsistent true "$mnt"
  # Claim (control): the locked fixture has an empty MountPoint that plutil extracts with exit 0, so a check of
  # plutil's exit status alone would call a locked volume mounted.
  if plutil -extract MountPoint raw -o - - <"$TMP/fx-locked.plist" >/dev/null 2>&1; then
    pass "volume-unlock.mounted.control: an empty MountPoint extracts with exit 0"
  else fail "volume-unlock.mounted.control: plutil refused the empty MountPoint; the fixture no longer exercises an empty MountPoint"; fi
  # Claim (positive): unlocked, mounted at the expected path, with the home tree present, counts as mounted.
  if mounted_rc mounted "$mnt"; then pass "volume-unlock.mounted.ok"; else fail "volume-unlock.mounted.ok: refused"; fi
  # Claims (negative): locked, unlocked but unmounted, mounted at "<VOL_MOUNT> 1", mounted without the home tree,
  # no Locked key, and Locked with a MountPoint are all "not mounted", so the daemon tries to unlock and then fails
  # loudly instead of logging success.
  bad=""
  mounted_rc locked "$mnt" && bad="$bad locked"
  mounted_rc unlocked "$mnt" && bad="$bad unlocked-unmounted"
  mounted_rc elsewhere "$mnt" && bad="$bad elsewhere"
  mounted_rc nohome "$TMP/vol/NoHome" && bad="$bad no-home"
  mounted_rc nolockkey "$mnt" && bad="$bad no-locked-key"
  mounted_rc inconsistent "$mnt" && bad="$bad locked-with-mountpoint"
  if [ -z "$bad" ]; then pass "volume-unlock.mounted.refuses: locked, unmounted, elsewhere, no home, no Locked key, inconsistent"
  else fail "volume-unlock.mounted.refuses: accepted$bad"; fi
else
  skip "volume-unlock mount state: plutil not available (macOS only)"
fi

# --- volume-unlock passphrase handling -----------------------------------------------------------------------
# security, diskutil and sleep are stubs; diskutil records each call and the bytes it got on stdin.
# unlock_case <security mode: missing|empty|ok> <diskutil mode: ok|refuse>: prints "<rc> <diskutil calls>"; the
# log lines go to $TMP/unlock.log.
unlock_case() {
  rm -f "$TMP/diskutil.calls" "$TMP/diskutil.stdin"
  SEC=$1 DU=$2 CALLS="$TMP/diskutil.calls" STDIN="$TMP/diskutil.stdin" LOGF="$TMP/unlock.log" bash -c "$(fn scripts/volume-unlock.sh log)
$(fn scripts/volume-unlock.sh unlock_volume)
security() { case \$SEC in missing) echo 'SecKeychainSearchCopyNext: The specified item could not be found in the keychain.' >&2; return 44 ;; empty) echo ;; ok) echo 'test-passphrase' ;; esac; }
diskutil() { echo \"\$*\" >>\"\$CALLS\"; cat >>\"\$STDIN\"; [ \"\$DU\" = ok ] && return 0; echo 'Error unlocking APFS Volume (stub message)'; return 1; }
sleep() { :; }
rc=0; unlock_volume 00000000-0000-0000-0000-000000000000 org.example.macos-ci.volume >\"\$LOGF\" 2>&1 || rc=\$?
echo \"\$rc \$( [ -f \"\$CALLS\" ] && wc -l <\"\$CALLS\" | tr -d ' ' || echo 0)\""
}
# Claim (negative): with no keychain item, or an item with an empty passphrase, diskutil is
# never called (no zero-length passphrase reaches it), the result is 3 ("no passphrase item"), and every attempt
# logs that the item is missing.
bad=""
for sec in missing empty; do
  out=$(unlock_case "$sec" ok)
  [ "$out" = "3 0" ] || bad="$bad $sec:$out"
  [ ! -e "$TMP/diskutil.calls" ] || bad="$bad $sec:diskutil-called"
  [ "$(grep -c 'no passphrase item' "$TMP/unlock.log")" = 6 ] || bad="$bad $sec:log"
done
if [ -z "$bad" ]; then pass "volume-unlock.passphrase.missing-or-empty: diskutil not called, rc 3"
else fail "volume-unlock.passphrase.missing-or-empty:$bad"; fi
# Claim (positive control): with a stored passphrase, diskutil is called once and gets exactly the passphrase and
# one newline on stdin, and the passphrase never appears in the log.
out=$(unlock_case ok ok 2>/dev/null)
got=$(od -An -c "$TMP/diskutil.stdin" 2>/dev/null | tr -s ' ' | sed 's/^ //')
if [ "$out" = "0 1" ] && [ "$(cat "$TMP/diskutil.stdin")" = test-passphrase ] && [ "$(wc -c <"$TMP/diskutil.stdin" | tr -d ' ')" = 16 ] \
   && ! grep -q test-passphrase "$TMP/unlock.log"; then pass "volume-unlock.passphrase.ok: one diskutil call, passphrase on stdin only"
else fail "volume-unlock.passphrase.ok: out=$out stdin=$got"; fi
# Claim (negative): when every unlockVolume fails, all 6 attempts run, the result is 1, not 0, and each attempt logs
# diskutil's exit status and message (neutral wording, no passphrase).
out=$(unlock_case ok refuse)
if [ "$out" = "1 6" ] && [ "$(grep -c 'unlockVolume failed (exit 1): Error unlocking APFS Volume (stub message)' "$TMP/unlock.log")" = 6 ] \
   && ! grep -q test-passphrase "$TMP/unlock.log"; then pass "volume-unlock.passphrase.refused: 6 attempts, rc 1, diskutil's message logged"
else fail "volume-unlock.passphrase.refused: $out; $(head -2 "$TMP/unlock.log" | tr '\n' ' ')"; fi

# --- keychain-add.sh -----------------------------------------------------------------------------------------
# sudo and security are stubs. The stub keychain is a state file; every stub call's argv goes to argv.log and the
# stdin of `security -i` to cmds.log. need_tty is stubbed so main can run without a terminal.
KA=scripts/keychain-add.sh
ka_run() {  # <item state: none|exists> <sec -i mode: ok|err|nostore> <stdin text> <call: main args... | store ...>
  local state=$1 imode=$2 input=$3; shift 3
  rm -f "$TMP/ka.state" "$TMP/ka.argv" "$TMP/ka.cmds"; [ "$state" = exists ] && : >"$TMP/ka.state"
  printf '%b' "$input" | ST="$TMP/ka.state" AV="$TMP/ka.argv" CM="$TMP/ka.cmds" IM=$imode bash -c "set -euo pipefail
readonly KC=/Library/Keychains/System.keychain ACCOUNT=volume LABEL=CI-volume
$(for f in say need_tty die item_exists store main; do fn "$KA" "$f"; done)
need_tty() { :; }
sudo() { echo \"sudo \$*\" >>\"\$AV\"; case \$1 in -v) return 0 ;; -H) shift ;; esac; \"\$@\"; }
security() {
  echo \"security \$*\" >>\"\$AV\"
  case \$1 in
    find-generic-password) [ -f \"\$ST\" ] ;;
    -i) cat >>\"\$CM\"; case \$IM in ok) : >\"\$ST\" ;; err) echo 'security: SecKeychainItemCreateFromContent: stub error' >&2 ;; nostore) ;; esac ;;
    *) return 9 ;;
  esac
}
\"\$@\"" _ "$@" >"$TMP/ka.out" 2>&1
}
ka_hex() { printf '%s' "$1" | od -An -v -tx1 | tr -d ' \n'; }
pp='  p@ss word "q" \\ $(x) `y`  '
want="add-generic-password -a volume -s org.example.macos-ci.volume -l CI-volume -T /usr/bin/security -X $(ka_hex "$pp") /Library/Keychains/System.keychain"
# Claim (positive): a new item is sent to `security -i` on stdin as exactly one add-generic-password line naming the
# System keychain explicitly, with the passphrase hex-encoded byte for byte (leading and trailing spaces, quotes,
# backslash, $() and backticks kept), then found there; neither the passphrase nor its hex is in any argv or in the
# output.
ppin=$(printf '%s' "$pp" | sed 's/\\/\\\\/g')
ka_run none ok "$ppin\n$ppin\n" main org.example.macos-ci.volume; rc=$?
if [ "$rc" = 0 ] && [ "$(cat "$TMP/ka.cmds")" = "$want" ] && grep -q 'stored in the System keychain: ok' "$TMP/ka.out" \
   && ! grep -qF -e "$(ka_hex "$pp")" -e 'p@ss' "$TMP/ka.argv" "$TMP/ka.out"; then pass "keychain-add.new: hex line on stdin, System keychain named, nothing in argv"
else fail "keychain-add.new: rc=$rc cmds=$(cat "$TMP/ka.cmds" 2>/dev/null | cut -c1-120) out=$(tr '\n' ' ' <"$TMP/ka.out")"; fi
# Claim (positive control for the decoding): the hex in that line decodes to the exact passphrase bytes.
got=$(sed -n 's/.* -X \([0-9a-f]*\) .*/\1/p' "$TMP/ka.cmds" | python3 -I -c 'import sys; sys.stdout.write(bytes.fromhex(sys.stdin.read().strip()).decode())')
if [ "$got" = "$pp" ]; then pass "keychain-add.hex-roundtrip"; else fail "keychain-add.hex-roundtrip: [$got]"; fi
# Claim: a re-run with an existing item reports it, sends nothing to security -i and exits 0.
ka_run exists ok "x\nx\n" main org.example.macos-ci.volume; rc=$?
if [ "$rc" = 0 ] && [ ! -e "$TMP/ka.cmds" ] && grep -q 'already exists' "$TMP/ka.out"; then pass "keychain-add.exists: reported, unchanged, exit 0"
else fail "keychain-add.exists: rc=$rc $(tr '\n' ' ' <"$TMP/ka.out")"; fi
# Claim: --update on an existing item replaces it with -U; --update without an item adds it without -U.
ka_run exists ok "new\nnew\n" main org.example.macos-ci.volume --update; rc=$?
ka_run none ok "new\nnew\n" main org.example.macos-ci.volume --update; rc2=$?; c2=$(cat "$TMP/ka.cmds" 2>/dev/null)
if [ "$rc" = 0 ] && [ "$rc2" = 0 ] && [ "${c2#* -U }" = "$c2" ]; then
  ka_run exists ok "new\nnew\n" main org.example.macos-ci.volume --update
  if grep -q -- ' -T /usr/bin/security -U -X ' "$TMP/ka.cmds"; then pass "keychain-add.update: -U only with --update and an existing item"
  else fail "keychain-add.update: no -U in $(cut -c1-100 "$TMP/ka.cmds")"; fi
else fail "keychain-add.update: rc=$rc rc2=$rc2 c2=$c2"; fi
# Claims (negative): an empty passphrase, two different entries, a security -i error, an item missing after the add,
# and malformed arguments all fail non-zero; the first two and the arguments send nothing to security -i.
bad=""
ka_run none ok "\n\n" main org.example.macos-ci.volume && bad="$bad empty"; [ ! -e "$TMP/ka.cmds" ] || bad="$bad empty-sent"
ka_run none ok "aaa\nbbb\n" main org.example.macos-ci.volume && bad="$bad mismatch"; [ ! -e "$TMP/ka.cmds" ] || bad="$bad mismatch-sent"
ka_run none err "aaa\naaa\n" main org.example.macos-ci.volume && bad="$bad sec-error"; grep -q 'security refused the item' "$TMP/ka.out" || bad="$bad sec-error-msg"
ka_run none nostore "aaa\naaa\n" main org.example.macos-ci.volume && bad="$bad not-found"; grep -q 'is not in /Library/Keychains/System.keychain' "$TMP/ka.out" || bad="$bad not-found-msg"
ka_run none ok "aaa\naaa\n" main 'org example' && bad="$bad bad-service"; [ ! -e "$TMP/ka.cmds" ] || bad="$bad bad-service-sent"
ka_run none ok "aaa\naaa\n" main org.example.macos-ci.volume --force && bad="$bad bad-flag"
if [ -z "$bad" ]; then pass "keychain-add.refuses: empty, mismatch, security error, not stored, bad service, bad flag"
else fail "keychain-add.refuses:$bad"; fi
# Claim (negative): without a terminal the real script refuses before sudo or security run.
out=$(bash "$KA" org.example.macos-ci.volume </dev/null 2>&1); rc=$?
if [ "$rc" != 0 ] && printf '%s' "$out" | grep -q 'needs a terminal'; then pass "keychain-add.no-tty: refused"
else fail "keychain-add.no-tty: rc=$rc $out"; fi

printf '\nRESULT pass=%s fail=%s skip=%s\n' "$P" "$F" "$S"
[ "$F" = 0 ]
