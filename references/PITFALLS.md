# Pitfalls seen on a real install (macOS 27, Apple silicon, OpenSSH 10.x)

Each entry gives the symptom, the cause, the fix, and how the scripts in this skill handle it now.

## Host preparation

### 1. `/opt` carries the BSD `hidden` flag
- **Symptom:** `host` stops at the support tree with `/opt must be a root:wheel 755 directory ..., is Directory|root:wheel|755|hidden`.
- **Cause:** some installers set the `hidden` flag on `/opt` so Finder hides it. The script refuses any flag on a
  system path it builds on, because immutable or append-only flags there would be tampering.
- **Fix:** `sudo chflags nohidden /opt`, then re-run `host`. The flag is cosmetic. Do not set it again, because later runs
  check `/opt` the same way.
- **Now:** the failure message names the fix.

### 2. `stat -f %Lp` drops the sticky, setuid and setgid digit
- **Symptom:** `.../runner/actions-runner reads back as Directory|root:wheel|775|-, expected ...|1775|-`. The
  directory really is 1775.
- **Cause:** in BSD `stat`, `%Lp` is only the low (rwx) part of the mode. The special-bits digit is `%Mp`. Without
  zero padding, `%Mp%Lp` would also print 1077 and 0177 both as `177`.
- **Fix:** read modes with `stat -f '%Mp%03Lp'` and strip one leading zero.
- **Now:** `lmeta` and `perm_of` do exactly that, and `tests/run.sh` covers 1775, 0755, 1077, 0177 and 0700.

### 3. Account creation over SSH: `eDSPermissionError`, wrong UID, no password
- **Symptom:** `sysadminctl -addUser ... -UID 550` prints `Assigning UID: 550`, then
  `DS Error: -14120 (eDSPermissionError)`. The account is created with the **next free UID** (for example 502),
  often without a password (no `AuthenticationAuthority`). `sudo dscl . -create /Users/<ci> UniqueID 550` over SSH
  fails with the same error.
- **Cause:** TCC. Writes to the local directory need Full Disk Access for the responsible process. An SSH session
  (`sshd-keygen-wrapper`) does not have it unless Remote Login's "Allow full disk access for remote users" is on.
  `root` alone is not enough.
- **Fix:**
  - Run `host` from **Terminal at the Mac** (or through Screen Sharing), with Full Disk Access granted to Terminal.
  - If the account already exists with a wrong UID and owns no files, run `sudo dscl . -create /Users/<ci> UniqueID <uid>`
    from that Terminal, then re-run.
  - `host` verifies the password and re-sets it with `passwd` if needed.
  - Remove Terminal's Full Disk Access when setup is done.
- **Now:** `host` warns before creating the account, refuses a wrong UID, and its message includes the repair command.

### 4. Per-user daemons outlive a logout
- **Symptom:** `host` or `harden-runner` refuses with "the CI account still runs the processes listed above". The
  list holds `distnoted`, `cfprefsd`, `trustd`, CoreSimulator services and similar, even after a logout.
- **Cause:** launchd keeps the user's background domain (`user/<uid>`) alive after the GUI session ends. A first
  password check or home creation can also start these daemons without any login.
- **Fix:** `sudo launchctl bootout user/<uid>` (after `gui/<uid>` if a session is still open), then re-run. If they
  stay, reboot.
- **Now:** the scripts still kill nothing themselves, by design; the refusal message names the command.

### 5. OpenSSH 10.x prints `sshd -T` keys in CamelCase
- **Symptom:** `sshd -T reports denyusers '', expected '<ci>'`, although the drop-in is in place and `sshd -t` accepts it.
- **Cause:** older OpenSSH printed `denyusers ci-runner`. OpenSSH 10.x on macOS prints `DenyUsers ...` and `PermitRootLogin no`.
- **Fix:** match keys case-insensitively.
- **Now:** `sshd_value` (in both scripts) uses `tolower()`, and the tests cover both styles.

### 6. App Store updates Xcode in place, even when the bundle is root-owned
- **Symptom:** between two runs, preflight shows a newer Xcode owned by the owner account again. Then
  `xcodebuild -runFirstLaunch` exits 77: "You have not agreed to the Xcode license agreements".
- **Cause:** App Store auto-update (`/Library/Preferences/com.apple.commerce AutoUpdate`) replaces the bundle
  through `installd`, which runs as root. Root ownership stops non-root tampering, not Apple's updater.
- **Fix:**
  - The owner accepts the new license (`sudo xcodebuild -license`) and re-runs `host`, which re-owns the bundle
    and runs the first launch.
  - On a CI host, turn app auto-update off: `sudo defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool false`.
  - Update Xcode on purpose instead.
- **Note:** a newer Xcode SDK builds and tests fine on an older installed simulator runtime (for example the iOS 27
  SDK on an iOS 26.5 runtime), as long as the deployment target is not above the runtime.

### 7. AirPlay Receiver listens on 5000/7000 in every account
- **Symptom:** `host` stops: "the owner's session still listens on 5000/7000".
- **Cause:** AirPlay Receiver is on by default per account. Writing the preference is not enough while Control
  Center runs, and `launchctl kickstart -k gui/<uid>/com.apple.controlcenter` fails with
  "Operation not permitted while System Integrity Protection is engaged".
- **Fix:** System Settings, then General, then AirDrop & Handoff, then AirPlay Receiver: off, in **each** account (owner and CI),
  then re-run.
- **Why off:** it accepts network connections without login, and has a history of remote code execution bugs.

### 8. Virtual-display tools can wedge fast user switching
- **Symptom:** after adding virtual displays in the owner session, the CI account shows a check mark in the user
  menu, but switching to it hangs or never shows its desktop.
- **Cause:** a display-configuration change made by a third-party tool in one session leaves the window server
  unable to bring up the other session's display set. Seen on one host; the exact trigger is not isolated.
- **Fix:**
  1. Log the CI account out from SSH: `sudo launchctl bootout gui/<uid>`, then `sudo launchctl bootout user/<uid>`.
  2. Reboot with `sudo fdesetup authrestart`, which skips the FileVault screen once.
  3. Unlock the CI volume, or let the optional boot unlock do it.
  4. Log the CI account in again before touching display tools.

### 9. Logging the CI account in before its volume is unlocked
- **Symptom:** after a reboot the runner never comes online. The start hook and pf-assert report a stray home or
  a volume at `<VOL_MOUNT> 1`.
- **Cause:** loginwindow creates a fresh home on the Data volume when the configured home path does not exist.
  When the real volume mounts later, its mount point is taken, so it mounts as `<VOL_MOUNT> 1`.
- **Fix:**
  1. Log the CI account out.
  2. Have the owner review and move the stray home aside.
  3. Unmount the volume and mount it again (`diskutil unmount`, then `diskutil mount <uuid>`) so that it mounts at
     `<VOL_MOUNT>`, then log the CI account in.
- **Prevention:** always unlock first (RUNBOOK.md 10).

### 10. `chown -R` of Xcode is refused by App Management
- **Symptom:** `host` stops at the Xcode step with "Operation not permitted" from `chown -R /Applications/Xcode.app`.
- **Cause:** macOS App Management protection: only processes allowed to manage apps may change application bundles.
- **Fix:** run `host` from Terminal at the Mac, with Terminal allowed under System Settings, Privacy & Security,
  App Management (as well as Full Disk Access).

### 11. Developer Tools Access prompt for UI tests
- **Symptom:** the first simulator or UI-test run as the CI account shows a "Developer Tools Access" dialog that
  asks for an administrator password.
- **Cause:** debugging or UI automation services ask for membership of `_developer`, which a standard account lacks.
- **Practice:** do not type an admin password into it, which would grant more than the lane needs. Note the exact
  dialog and the step that raised it, and tell the operator (RUNBOOK.md 6). Add the CI account to `_developer` only
  as a deliberate, reviewed decision.

### 12. The owner's home is 750 on a stock Mac
- **Symptom:** none by itself, but `qualify.sh owner` reports the mode.
- **Cause:** macOS creates homes `drwxr-x---` with group `staff`.
- **Why it is fine:** the CI account has its own primary group and is not in `staff`, so it cannot enter.
  `qualify.sh owner` accepts 700 or 750, and `qualify.sh root` proves that the CI account cannot list the home.

## Runner registration and GitHub

### 13. The registration token and Universal Clipboard
- **Symptom:** none visible. That is the problem.
- **Cause:** the registration token can add runners to **any** group of the organization for one hour. Copied on a
  Mac with Handoff on, it also lands in the clipboards of the user's other Apple devices.
- **Practice:**
  - Check the admin workstation for clipboard managers and Handoff before minting (RUNBOOK.md).
  - Turn Handoff off for the minute.
  - Mint straight into the clipboard (`gh api ... --jq .token | pbcopy`).
  - Paste through the tunnelled Screen Sharing into the masked prompt.
  - Clear both clipboards afterwards.

### 14. Runner-group workflow allowlists silently queue new repositories
- **Symptom:** a job sits in `queued` for a long time, and the runner is online and idle.
- **Cause:** the runner group has `restricted_to_workflows: true`, and the new repository or workflow file is not in
  `selected_workflows`. GitHub gives no error, the job just never gets a runner.
- **Fix:** add `owner/repo/.github/workflows/<file>.yml@refs/heads/<branch>` to the group's selected workflows,
  or use an unrestricted, repository-scoped group for test lanes.

### 15. A queued job is not picked up after you fix the group
- **Symptom:** a job queued before you fixed the group stays queued afterwards.
- **Cause:** the job was evaluated against the old group settings when it was queued.
- **Fix:** cancel it and dispatch a new run after the fix.

## Workflows on the host

### 16. macOS ships GNU make 3.81, without `--eval`
- **Symptom:** `make -s --eval '...' target` prints make's usage text and exits 2.
- **Cause:** macOS still ships GNU make 3.81 (2006), which predates `--eval`.
- **Fix:** put the extra target in a second makefile: `make -s -f Makefile -f "$RUNNER_TEMP/print.mk" target`.

### 17. UI tests are flaky on an 8 GB Apple-silicon laptop
- **Symptom:** the same commit passes in one run and fails a UI test in the next (timeouts waiting for an element).
- **Cause:** memory pressure: Xcode, the simulator and the app under test together exceed 8 GB, the host swaps,
  and UI waits time out.
- **Practice:** plan a retry for UI tests (`-retry-tests-on-failure -test-iterations 2`), or quarantine them in a
  separate job. Do not retry unit tests.

## Boot-time volume unlock

### 18. Root has no default keychain: the passphrase item is never stored
- **Symptom:**
  - `sudo security add-generic-password ... -w` (or `sudo security default-keychain`) fails with
    `A default keychain could not be found`, or appears to work, but the item is not in
    `/Library/Keychains/System.keychain`.
  - After a reboot the CI volume stays locked. `/var/log/<LABEL_PREFIX>.volume-unlock.log` shows
    `attempt n: no passphrase item '<LABEL_PREFIX>.volume' (account volume) in /Library/Keychains/System.keychain`
    for every attempt, then `FAILED: no passphrase item ... diskutil was not called`.
  - Before the script refused an empty passphrase, diskutil said `A zero-length passphrase is not supported`.
- **Cause:** root has no default keychain (confirmed on a real host). `add-generic-password` without a keychain
  argument has nowhere to store the item. It prompts only when `-w` is the last argument, so the prompting form
  cannot name the System keychain either. `sudo -H` does not help.
- **Fix:**
  1. Unlock by hand for now (RUNBOOK.md 10.3).
  2. Store the item with `scripts/keychain-add.sh` (RUNBOOK.md 10, "Optional: unlock the CI volume at boot",
     step 3). It names `/Library/Keychains/System.keychain` explicitly, reads the passphrase without echo, sends it
     hex-encoded to `sudo security -i` on stdin (`add-generic-password ... -X <hex> <keychain>`), and then requires
     `find-generic-password` to find it there.
  3. Repeat step 4 (lock, unlock by the script, check).
  4. If diskutil later refuses the stored passphrase, re-run the helper with `--update`.

## Job hygiene

### 19. Leftover processes fail the next job
- **Symptom:** the start hook refuses a job and names a process.
- **Cause:** a previous job, or a probe, left a process behind.
- **Fix:** shut simulators down at the end of every job (`xcrun simctl shutdown all`, `if: always()`).
- **Probes started through `sudo`:**
  - Signal the probe itself, not the `sudo` wrapper. `sudo` does not relay a signal sent from its own process
    group, so `kill $!` leaves the child running.
  - `qualify.sh` uses `stop_bg` (pkill by parent PID first), and the tests reproduce the leak.

### 20. Long, temporary `TMPDIR` paths break UNIX sockets
- **Symptom:** tools that open UNIX sockets under `TMPDIR` fail with "path too long" or bind errors.
- **Cause:** socket paths are limited to about 104 bytes, and a long `TMPDIR` under the runner's work tree exceeds it.
- **Fix:** keep job scratch short, for example under `$RUNNER_TEMP/ci`.

## Cosmetic

### 21. `failed to install terminfo` warnings on SSH
- **Symptom:** a warning about installing terminfo at every SSH login.
- **Cause:** some terminal emulators try to install their own terminfo entry on the remote host, and macOS's ncurses
  cannot compile it.
- **Fix:** none needed: the session falls back to a stock terminal type. Turn the terminal's SSH terminfo
  integration off to silence it.
