# Runbook: from a clean Mac to a qualified runner

## Roles
- **Owner:** the admin account of the Mac. Types every sudo password and every secret (volume passphrase, CI-account
  password, the token paste). Runs the root commands.
- **Operator:** an agent or engineer on the admin workstation. Prepares the config and hashes, runs the read-only
  checks, manages the GitHub side and reads the logs. Never types a secret and never needs sudo on the CI host.

## Placeholders used below
- `<host>`: the owner's SSH alias for the CI Mac, set as `ADMIN_SSH_ALIAS` in the config. Use it over a tailnet
  or LAN, never the public Internet.
- `<support>`: `SUPPORT_ROOT`, for example `/opt/macos-ci`.
- `<H_HP>`, `<H_Q>`, `<H_CONF>`: the SHA-256 of `scripts/host-prep.sh`, `scripts/qualify.sh` and your
  `ci-runner.conf`. The operator computes them with `shasum -a 256` and gives them to the owner.
- `<H_VU>`, `<H_KA>`, `<H_VU_PLIST>`: only for the optional boot unlock (step 10): the SHA-256 of
  `scripts/volume-unlock.sh`, `scripts/keychain-add.sh` and the rendered LaunchDaemon plist.
- `<stage>`: a private staging directory in the owner's home on the CI host, printed by step 1.

## Rules for every root command
- Call `/usr/bin/sudo` and `/usr/bin/shasum` by absolute path.
- Start the script with `/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /bin/bash` and its absolute, root-owned
  path. The scripts read `ci-runner.conf` from their own root-owned directory.
- **Every root command starts with the same pin**: the SHA-256 of both scripts **and** of `ci-runner.conf`, checked
  on the root-owned copies, so nothing a non-root account controls can be swapped in between check and run. Set
  these two variables once per terminal, on the admin workstation (and in Terminal at the Mac for step 3):
  ```bash
  pin='printf "%s  %s\n" <H_HP> <support>/setup/host-prep.sh <H_Q> <support>/setup/qualify.sh <H_CONF> <support>/setup/ci-runner.conf | /usr/bin/shasum -a 256 -c -'
  root='/usr/bin/sudo /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /bin/bash <support>/setup'
  ```
  Every root command below has the shape `ssh -t <host> "$pin && $root/<script> <mode>"`. Expect three `OK` lines
  before the script's own output; any other line stops the command before root runs anything.
- **Never stage a file for root in a shared directory** such as `/tmp`, `/var/tmp` or `/Users/Shared`: the CI
  account can pre-create or replace files there. Copy into a fresh `mktemp -d` directory in the owner's home (mode
  0700), `install` into the root-owned destination, and check the hashes of the installed root-owned copies
  before anything runs or loads them.
- The scripts are idempotent and fail-closed. After a failure, fix the cause and re-run the same command; finished
  steps are only re-checked.

## 0. Prepare (operator)
1. Copy `examples/ci-runner.conf` and fill every key. Pick a free UID and GID above 500.
2. Take `RUNNER_SHA256` from the actions/runner release page, and `TUIST_SHA256` from the Tuist release's
   `SHASUMS256.txt`. Check each against a second source. `TUIST_TEAM_ID` comes from
   `codesign -dv` of the Tuist binary.
3. Record `STOCK_PF_CONF_SHA256` and `STOCK_PF_APPLE_SHA256` from a known-clean host of the same macOS release.
4. Run the offline tests: `/bin/bash tests/run.sh`.
5. Compute the hashes `<H_HP>`, `<H_Q>` and `<H_CONF>`.
6. On the CI host, turn App Store automatic updates off before step 3 (PITFALLS.md 6): an in-place Xcode update
   during preparation or a job breaks the root-owned toolchain.

## 1. Copy and pin (owner, from the admin workstation)
Make a private staging directory on the host and note the path it prints as `<stage>`:
```bash
ssh <host> '/usr/bin/mktemp -d "$HOME/.macos-ci-stage.XXXXXX"'
```
Copy the files into it. The config must arrive as `ci-runner.conf`:
```bash
D=<this skill checkout>
scp "$D/scripts/host-prep.sh" "$D/scripts/qualify.sh" <host>:<stage>/ && scp <your ci-runner.conf> <host>:<stage>/ci-runner.conf
```
Install as root and check the installed copies. The first test refuses an existing `<support>` that is not already
a root:wheel 755 directory, so a third-party tree is never re-owned:
```bash
ssh -t <host> '{ [ ! -e <support> ] || [ "$(/usr/bin/stat -f "%Su:%Sg %Mp%03Lp" <support>)" = "root:wheel 0755" ] || { echo "<support> exists and is not root:wheel 755: choose another SUPPORT_ROOT"; exit 1; }; } && /usr/bin/sudo /usr/bin/install -d -o root -g wheel -m 0755 <support> <support>/setup && /usr/bin/sudo /usr/bin/install -o root -g wheel -m 0644 <stage>/host-prep.sh <stage>/qualify.sh <stage>/ci-runner.conf <support>/setup/ && /bin/rm -rf <stage> && printf "%s  %s\n" <H_HP> <support>/setup/host-prep.sh <H_Q> <support>/setup/qualify.sh <H_CONF> <support>/setup/ci-runner.conf | /usr/bin/shasum -a 256 -c -'
```
Expect three `OK`. Repeat this step whenever a script or the config changes, with the new hashes.

## 2. Read-only checks
- **Operator, no sudo:**
  ```bash
  ssh <host> 'MACOS_CI_CONF=<support>/setup/ci-runner.conf bash -s -- preflight' < scripts/host-prep.sh
  ```
- **Owner, root, read-only.** Review the output before step 3. The TCC check needs Terminal at the Mac with Full
  Disk Access.
  ```bash
  ssh -t <host> "$pin && $root/host-prep.sh preflight --ioc"
  ```
  Optional site lists (DESIGN.md, I1), root:wheel 0644: `<support>/etc/root-home-allow` names extra expected entries
  in `/var/root`, and `<support>/etc/indicator-paths` lists absolute paths that must be absent. Keep the latter out of
  any public repository.

## 3. Host preparation (owner, about 20 minutes)
**Where:** in Terminal at the Mac, or through the tunnelled Screen Sharing. Give Terminal Full Disk Access first:
account creation over SSH fails (PITFALLS.md 3). Never run this through a direct, untunnelled VNC session,
because the last step closes port 5900 to the network.

**Before you start:** put two new secrets in a password manager, the volume passphrase and the CI-account
password. The script asks for them in that order, each twice.

Set `pin` and `root` in this Terminal as in the rules above, then:
```bash
/bin/sh -c "$pin && $root/host-prep.sh host"
```
**What it does:**
- creates the encrypted volume and the account;
- makes Xcode root-owned and runs its first launch;
- installs the hooks;
- sets up the firewall, sshd, SMB, Screen Sharing, updates, power and AirPlay;
- **arms pf last, with a 10-minute dead-man switch.**

If it stops, see PITFALLS.md: `/opt` hidden flag (1), Full Disk Access (3), leftover per-user daemons (4), App
Management for the Xcode `chown` (10), the Xcode license, AirPlay (7).

## 4. Confirm pf within 10 minutes (owner, from a NEW terminal on the admin workstation)
```bash
ssh -t <host> "$pin && $root/host-prep.sh confirm-pf"
```
The fresh SSH login is the proof that pf did not cut SSH off. Without it, pf rolls back by itself, even across a
reboot; re-run step 3 to arm it again.

From now on, use Screen Sharing only through the tunnel: run `ssh -N -L 5901:127.0.0.1:5900 <host>`, then
`open vnc://localhost:5901`.

## 5. Runner group (operator)
```bash
RID=$(gh api repos/<RUNNER_REPO> --jq .id)
gh api -X POST orgs/<RUNNER_ORG>/actions/runner-groups -f name=<RUNNER_GROUP> -f visibility=selected \
  -F allows_public_repositories=false -F "selected_repository_ids[]=$RID"
```
The test lane holds no secrets, so the group gets no workflow restriction (DESIGN.md).

## 6. First CI login and registration (owner in the CI account's GUI session; operator for the token)
1. Fast user switching to the CI account. In Setup Assistant decline everything: no Apple ID, Siri, Screen Time,
   location, analytics or Touch ID.
2. In the CI account's Terminal, check the identity and turn AirPlay off:
   ```zsh
   id; echo "HOME=$HOME"; ls -ld "$HOME"; sudo -n true 2>&1 | head -1
   defaults -currentHost write com.apple.controlcenter AirplayRecieverEnabled -bool false
   lsof -nP -a -u "$(id -un)" -iTCP -sTCP:LISTEN | grep -E ':(5000|7000) ' || echo "no AirPlay listener: ok"
   ```
   Expect: the configured UID and group, no `admin` or `staff`, home `drwx------`, sudo refused, and the last line
   `no AirPlay listener: ok`. If a listener is still there, the `defaults` key was not enough on this release:
   turn AirPlay Receiver off in System Settings in this account (PITFALLS.md 7), log out and in, and check again.
3. Download the runner. This copy is used only to run `config.sh`; `harden-runner` later replaces it with its own
   verified copy.
   ```zsh
   cd <VOL_MOUNT>/runner/actions-runner && ls -A | wc -l    # expect 0
   curl -fL --proto '=https' --tlsv1.2 -o ~/tmp/runner.tar.gz https://github.com/actions/runner/releases/download/v<RUNNER_VERSION>/actions-runner-osx-arm64-<RUNNER_VERSION>.tar.gz
   echo "<RUNNER_SHA256>  $HOME/tmp/runner.tar.gz" | shasum -a 256 -c - && tar -xzmf ~/tmp/runner.tar.gz -C <VOL_MOUNT>/runner/actions-runner && rm ~/tmp/runner.tar.gz
   ```
4. **Token (operator).**
   - Check the admin workstation first:
     ```bash
     pgrep -il 'maccy|paste|copyclip|flycut|pastebot|clipy|clipboard|alfred|raycast' || echo "no clipboard manager"
     defaults -currentHost read com.apple.coreservices.useractivityd ActivityAdvertisingAllowed 2>/dev/null || echo "Handoff: default (on)"
     ```
   - The owner pauses any clipboard history and turns Handoff off for the minute.
   - Mint the token straight into the clipboard:
     ```bash
     gh api -X POST orgs/<RUNNER_ORG>/actions/runners/registration-token --jq .token | tr -d '\n' | pbcopy
     ```
5. In the CI account's Terminal, run `config.sh` and paste the token at its masked prompt:
   ```zsh
   ./config.sh --url https://github.com/<RUNNER_ORG> --runnergroup <RUNNER_GROUP> --name <RUNNER_NAME> \
     --labels <RUNNER_EXTRA_LABEL> --work <VOL_MOUNT>/home/<CI_USER>/work --disableupdate
   ```
   Expect `Runner successfully added`, then `Settings Saved`. Do **not** run `./svc.sh install`.
6. Clear the clipboards: `pbcopy </dev/null` in the CI account, and the operator does the same on the workstation.
   Turn Handoff back on.
7. **Simulator, once.** If macOS asks for Developer Tools Access, do not approve it with an admin password; tell the
   operator.
   ```zsh
   xcrun simctl list devices | grep -F "<SIMULATOR_NAME>" || xcrun simctl create "<SIMULATOR_NAME>" com.apple.CoreSimulator.SimDeviceType.iPhone-16 <runtime id from: xcrun simctl list runtimes>
   xcrun simctl boot "<SIMULATOR_NAME>" && xcrun simctl bootstatus "<SIMULATOR_NAME>" -b && xcrun simctl shutdown "<SIMULATOR_NAME>"
   xcodebuild -checkFirstLaunchStatus; echo "first-launch exit $?"
   ```
8. Quit Terminal, then log the CI account out (Apple menu, then Log Out).

## 7. Harden (owner, CI account logged out)
If `harden-runner` lists leftover processes, run `sudo launchctl bootout user/<CI_UID>` first (PITFALLS.md 4).
```bash
ssh -t <host> "$pin && $root/host-prep.sh harden-runner"
```
Expect the last line `harden-runner complete`.

## 8. Start (owner)
1. Log the CI account in through the tunnelled Screen Sharing. The runner starts from the root-generated
   LaunchAgent. **Do not open Terminal in this session from now on:** the start hook fails jobs while a shell runs
   there.
2. If step 7 reported deferred agents, with the CI account logged in:
   ```bash
   ssh -t <host> "$pin && $root/host-prep.sh ci-session-agents"
   ```
3. Switch back to the owner. The CI account stays logged in.

## 9. Qualify
- **Operator:** check the runner is in the group:
  ```bash
  gh api orgs/<RUNNER_ORG>/actions/runner-groups/<id>/runners --jq '.runners[] | {name,status,labels:[.labels[].name]}'
  ```
  Then run the owner-side checks on the host, and the remote checks from the workstation with a local copy of the
  config:
  ```bash
  ssh <host> 'MACOS_CI_CONF=<support>/setup/ci-runner.conf bash -s -- owner' < scripts/qualify.sh
  MACOS_CI_CONF=<local ci-runner.conf> bash scripts/qualify.sh remote
  ```
- **Owner, root, CI account logged in:**
  ```bash
  ssh -t <host> "$pin && $root/qualify.sh root"
  ssh -t <host> "$pin && $root/qualify.sh root-postbuild"
  ```
  `root-postbuild` boots the simulator, builds a fresh package with `xcodebuild` as the CI account, then runs the
  real start hook. **It must PASS before the first real job.** If a job then fails with a refused process, extend
  the start hook's allowlist only through a reviewed change to `host-prep.sh`.
- **Inbound isolation (optional), two terminals:** start `ssh -t <host> "$pin && $root/qualify.sh root-inbound"`,
  and within its 180 seconds run `MACOS_CI_CONF=<local ci-runner.conf> bash scripts/qualify.sh remote-inbound` on
  the workstation.
- **Quota (optional; writes a 1 GiB test volume and deletes it, asks first):**
  `ssh -t <host> "$pin && $root/qualify.sh quota-fixture"`.
- **Cross-repository isolation, once:** dispatch a job that targets the group's labels from a disposable private
  repository that the group does not list. It must stay queued; then delete that repository.
- **First real job, then a second one straight after.** The second job's start hook is the proof that the first
  left nothing behind.

## 10. After every reboot
1. Unlock FileVault at the Mac, or plan the reboot with `sudo fdesetup authrestart`.
2. Optional, as proof that pf is up before any login:
   ```bash
   ssh -t <host> "$pin && $root/qualify.sh root-boot"
   ```
3. Unlock the CI volume **before** the CI account logs in. Either run
   `sudo diskutil apfs unlockVolume $(cat <support>/etc/volume-uuid)` over SSH, or use the optional boot unlock
   below. If the CI account logs in while the volume is locked, macOS creates a stray home on the Data volume and
   the real volume mounts as `<VOL_MOUNT> 1`; the start hook and pf-assert both report it (PITFALLS.md 9).
4. Log the CI account in through the tunnelled Screen Sharing, then switch back.

### Optional: unlock the CI volume at boot
Trade-off: DESIGN.md. Once, with the CI account logged out.

1. **Operator, on the workstation:** render the plist in a private directory, refuse any leftover placeholder,
   lint it, and compute `<H_VU>`, `<H_KA>` and `<H_VU_PLIST>`:
   ```bash
   W=$(mktemp -d)
   sed -e 's|__LABEL_PREFIX__|<LABEL_PREFIX>|g' -e 's|__SUPPORT__|<support>|g' -e 's|__VOL_MOUNT__|/Volumes/<VOL_NAME>|g' \
     examples/volume-unlock.plist.template >"$W/volume-unlock.plist"
   ! grep -n '__[A-Z_]*__' "$W/volume-unlock.plist" && plutil -lint "$W/volume-unlock.plist" && shasum -a 256 scripts/volume-unlock.sh scripts/keychain-add.sh "$W/volume-unlock.plist"
   ```
2. **Owner:** make a new `<stage>` as in step 1, copy the three files there, install them as root, and check the
   installed copies. Set the boot-unlock pin once per terminal:
   ```bash
   vupin='printf "%s  %s\n" <H_VU> <support>/sbin/volume-unlock.sh <H_KA> <support>/sbin/keychain-add.sh <H_VU_PLIST> /Library/LaunchDaemons/<LABEL_PREFIX>.volume-unlock.plist | /usr/bin/shasum -a 256 -c -'
   scp scripts/volume-unlock.sh scripts/keychain-add.sh "$W/volume-unlock.plist" <host>:<stage>/
   ssh -t <host> "/usr/bin/sudo /usr/bin/install -o root -g wheel -m 0755 <stage>/volume-unlock.sh <stage>/keychain-add.sh <support>/sbin/ && /usr/bin/sudo /usr/bin/install -o root -g wheel -m 0644 <stage>/volume-unlock.plist /Library/LaunchDaemons/<LABEL_PREFIX>.volume-unlock.plist && /bin/rm -rf <stage> && $vupin"
   ```
   Expect three `OK`.
3. **Owner:** store the passphrase in the System keychain with the installed `keychain-add.sh`. Root has no default
   keychain, and `security add-generic-password -w` prompts only as the last argument, so it cannot name the
   keychain (PITFALLS.md 18). The helper names `/Library/Keychains/System.keychain` explicitly. It reads the
   passphrase twice without echo, hex-encodes it, and sends the add command to `sudo security -i` on stdin, so the
   passphrase is never in argv or a file. It then requires `find-generic-password` to find the item there:
   ```bash
   ssh -t <host> "$vupin && /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /bin/bash <support>/sbin/keychain-add.sh <LABEL_PREFIX>.volume"
   ```
   Expect the sudo prompt, the two passphrase prompts, then `stored in the System keychain: ok`. Anything else: do
   not continue to step 4.
   - **Re-runs** are safe. If an item already exists, the helper reports it, changes nothing and exits 0, so a
     repeated run cannot silently replace a working passphrase.
   - **To replace a stored passphrase that diskutil refuses** (step 4 logs `unlockVolume failed`), run the same
     command with `--update` after the service name. That uses `add-generic-password -U`.
4. **Owner: prove it unlocks.** Lock the volume, check that it is locked, run the installed script, then check
   that the volume is unlocked, mounted at `/Volumes/<VOL_NAME>` and holds the home tree. Bootstrap the daemon only
   after all of that holds:
   ```bash
   ssh -t <host> "$vupin && U=\$(cat <support>/etc/volume-uuid) && /usr/bin/sudo /usr/sbin/diskutil apfs lockVolume \$U && [ \"\$(/usr/sbin/diskutil info -plist \$U | /usr/bin/plutil -extract Locked raw -o - -)\" = true ] && echo 'locked: ok' && /usr/bin/sudo /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /bin/bash <support>/sbin/volume-unlock.sh <support> <LABEL_PREFIX>.volume /Volumes/<VOL_NAME> && [ \"\$(/usr/sbin/diskutil info -plist \$U | /usr/bin/plutil -extract Locked raw -o - -)\" = false ] && [ \"\$(/usr/sbin/diskutil info -plist \$U | /usr/bin/plutil -extract MountPoint raw -o - -)\" = /Volumes/<VOL_NAME> ] && [ -d /Volumes/<VOL_NAME>/home ] && echo 'unlocked by the script: ok'"
   ssh -t <host> "$vupin && /usr/bin/sudo /bin/launchctl bootstrap system /Library/LaunchDaemons/<LABEL_PREFIX>.volume-unlock.plist"
   ```
   Expect `locked: ok`, the script's `unlocked and mounted at /Volumes/<VOL_NAME>`, then `unlocked by the script: ok`.
   A `no passphrase item` failure means step 3 did not store the item in the System keychain: repeat step 3, and
   unlock this time by hand (step 10.3). An `unlockVolume failed` line carries diskutil's own message: for a wrong
   passphrase, re-run step 3 with `--update`.
5. After the next reboot, check `/var/log/<LABEL_PREFIX>.volume-unlock.log` for `unlocked and mounted at` before
   the CI account logs in. A `FAILED` line means: unlock by hand (step 10.3); `no passphrase item` means: repeat
   step 3 (PITFALLS.md 18).

## 11. Changing versions
- **Xcode:** App Store auto-update stays off (step 0). Update on purpose, accept the license as root, and
  re-run `host` (step 3); it re-owns the bundle and runs the first launch.
- **Runner or Tuist:**
  1. Change the version and SHA-256 in the config, compute the new `<H_CONF>`, install the new config with step 1
     and update `pin` with the new hash.
  2. Run `harden-runner` (step 7) with the CI account logged out; the old copy is quarantined.
  3. Review the baseline diff, then accept it with `harden-runner --rebaseline`, which asks for a typed confirmation.
