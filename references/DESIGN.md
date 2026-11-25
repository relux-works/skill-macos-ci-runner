# Design: an isolated self-hosted macOS runner for iOS test jobs

## Scope and threat model

- **What the host runs.** GitHub Actions jobs that build and test an iOS/macOS app: package tests, Debug/Release
  simulator builds, unit and UI tests on a simulator. These jobs run **untrusted code**: whatever a pull request
  puts in the repository, its build scripts, its package plugins and its tests.
- **What must survive a hostile job:**
  - the owner's account, files, keychain and sessions on the same Mac;
  - the toolchain that later jobs use (Xcode, the runner, Tuist);
  - the host's network neighbours: LAN, tailnet, loopback services;
  - the next job's integrity, so no persistence carries across jobs;
  - the disk the owner needs.
- **Out of scope for the test lane:**
  - Signing identities and App Store Connect keys. A release lane needs its own account or an off-host service.
    It never shares an account, cache, keychain or runner with the test lane.
  - Defending against a root compromise. Root-compromise indicators are checked before setup (I1-I5 below), and
    every control here assumes a clean root.

## Layers

| Layer | Control |
| --- | --- |
| Account | Standard user `CI_USER` with its own primary group, not `staff`, not `admin`, `_developer`, `com.apple.access_ssh` or `com.apple.access_screensharing`. No secure token, so it cannot unlock FileVault. No sudo, cron or at. sshd denies it. |
| Storage | Its own encrypted APFS volume with its own passphrase, a **quota** (hard cap, at least 32 GiB) and a **reserve** (guaranteed space). The CI home, runner and tools live there. Spotlight is off and ownership is enabled. The job-started hook refuses a job below 15 GiB free on the volume or 40 GiB on the Data volume, and pf-assert keeps the runner off below 25 GiB on the Data volume; these floors are fixed in host-prep.sh. |
| Toolchain | Xcode is root-owned with no group/other write, and first launch and license are done by root. The runner and Tuist are downloaded by root, checked by SHA-256 (Tuist also by team ID), and installed root-owned. The CI account's own copies are quarantined, never adopted. |
| Runner home | The LaunchAgent plist, `~/.gitconfig` and the shell startup files are root-written and `schg`. `~/Library/LaunchAgents` is `schg`, and the home is `sappnd` (append-only), so entries cannot be renamed away. Placeholders make `git config --global` fail fast. |
| Job admission | A root-owned **job-started hook** re-executes itself with a clean environment. It refuses the job if: an injection variable is set; a launchd job does not come from an Apple definition and is not the runner; a CI process outside the runner tree is a shell or interpreter; or the account's files differ from the root-recorded baseline. A **job-completed hook** wipes the workspace and temp directories without following symlinks. |
| Network | A pf anchor for the CI UID allows TCP/UDP only to the public IPv4 Internet. It blocks private, CGNAT, link-local and multicast IPv4 and all IPv6, and drops inbound to the CI account's sockets. A root LaunchDaemon (`pf-assert`) keeps it loaded every 30 s and never touches a ruleset it does not own. |
| Remote access | sshd: `DenyUsers CI_USER`, `PermitRootLogin no`. Screen Sharing answers only on loopback, so it is reachable only through an SSH tunnel, and the stored legacy VNC password is removed. SMB is off. The AirPlay Receiver is off. The application firewall runs in stealth mode. |
| Updates and power | Automatic security responses stay on; macOS updates install manually. No sleep on AC. App Store app auto-update must be off on a CI host, because it replaces Xcode in place. |

## Decisions that matter

1. **No root operation follows a path the CI account controls.**
   - `host` re-runs and `harden-runner` refuse while any CI process or crontab exists.
   - Root writes into CI trees are staged in a root-only directory on the same volume and moved into place with
     `rename(2)`.
   - Metadata changes use `-h` and are re-verified with `lstat`.
   - A symlink or wrong file type at a root-managed path stops the run as suspected tampering.
2. **The runner directory is root-owned and sticky (1775) from the start.** `harden-runner` installs the runner from
   its own verified download and generates `.env`, `.path`, `runsvc.sh`, `svc.sh` and the plist itself. The `.env`
   clears `BASH_ENV`, `ENV`, `ZDOTDIR` and the `DYLD_*` injection variables.
3. **The LaunchAgent belongs to the CI account but is immutable.** launchd requires an agent in
   `~/Library/LaunchAgents` to be owned by the loading user. So root writes the content, gives the file to the
   account and sets `schg`, which only root can clear.
4. **pf is enabled only over a stock pf state, with a dead-man switch.**
   - Before any change the full pf state is dumped.
   - The run stops on anything that is neither stock macOS nor ours, for example a VPN kill switch.
   - Arming starts a 10-minute dead-man (a RunAtLoad LaunchDaemon, so it survives a dropped session and a reboot).
     It rolls pf back unless `confirm-pf` runs from a **fresh SSH login** made after the arming. That login is
     the proof that pf did not cut SSH off.
5. **Screen Sharing stays, loopback-only.** Someone must log the CI account in after every reboot, and the owner
   sometimes needs a GUI. Direct VNC from the network is a historically exploited surface; through an SSH tunnel
   it inherits SSH's authentication.
6. **Persistent runner, not ephemeral.** The single-repository group, the start hook, the baseline and the
   completion cleanup bound what a job can leave behind. An ephemeral VM per job would be stronger, but Apple
   silicon virtualization caps concurrent macOS VMs, and a laptop-class host has no headroom for it.
7. **The registration token has one route.** It goes from the admin workstation's clipboard, through the
   tunnelled Screen Sharing session, into the masked `config.sh` prompt. Check the workstation for clipboard
   history tools and Universal Clipboard (Handoff) first. The token can register runners into any group of the
   organization for one hour.

## GitHub configuration

- **Runner group.** One group with `visibility: selected` that lists exactly one private repository and does not
  allow public repositories. The test lane holds no secrets, so the group has no workflow restriction: a
  ref-bound restriction would block pull-request runs.
- **Restricted groups elsewhere.** Groups that carry secrets should use selected-workflow restrictions. Remember
  that those allowlists silently leave jobs from newly added repositories or workflows **queued**
  (PITFALLS.md).
- **Workflow rules:** WORKFLOW.md.

## Root-compromise indicators (preflight --ioc)

| ID | Check |
| --- | --- |
| I1 | root has no `authorized_keys`; root's home holds only stock entries plus the names in the optional `<support>/etc/root-home-allow`; the optional site-specific paths in `<support>/etc/indicator-paths` (one absolute path per line, kept out of any public repository) are absent. Both lists count only as root:wheel regular files without group/other write; any other state is itself a finding |
| I2 | no login or background item (BTM) runs an interpreter or lives in a shared temp path |
| I3 | no `NOPASSWD: ALL` rule in sudoers |
| I4 | no crontab or at job; no periodic(8) script newer than the installed macOS release (an mtime heuristic: root can backdate a file, and an OS update can leave newer stock scripts, so a finding asks for review, and a clean result proves little) |
| I5 | the TCC grants for screen capture, accessibility, Full Disk Access and post-event are listed for review; the pf state is stock |

## Accepted residuals

- **Kernel SMB mounts.** pf cannot attribute them to the CI UID. Probe them with `qualify.sh root <smb-host>`
  when the network has SMB servers.
- **World-writable root helper sockets** of third-party software, such as VPN or USB multiplexer helpers. `qualify.sh
  root` lists every socket that the CI account can connect to, so the owner can decide on each.
- **A persistent runner shares state across jobs within the bounds above.** UI tests also share one simulator
  device.

## Optional: unlock the CI volume at boot

By default the owner unlocks the CI volume by hand after every reboot, before the CI account logs in. The
optional `volume-unlock.sh` LaunchDaemon reads the passphrase from the System keychain and unlocks the volume at
boot, so a planned `fdesetup authrestart` brings the host back with no one at the Mac. **Trade-off:** root can
then read the passphrase at every boot, so the volume's own key adds nothing beyond FileVault. FileVault stays the
at-rest guard. The quota, the reserve and the account isolation are unaffected.

The daemon counts as successful only when `diskutil info -plist` reports `Locked` false and a `MountPoint` equal to
`/Volumes/<VOL_NAME>`, and the home tree exists there. An empty mount point, a missing key or a mount at
`/Volumes/<VOL_NAME> 1` is a failure, logged as `FAILED`. A missing keychain item or an empty passphrase never
reaches diskutil: the run fails with `no passphrase item` (PITFALLS.md 18). Root has no default keychain, so the
item is stored by `scripts/keychain-add.sh`, which names the System keychain explicitly and passes the passphrase
hex-encoded on `security -i`'s stdin. Its inputs (the support root, `etc` and `volume-uuid`) must
be root:wheel, not symlinks, and carry no group or other write bit. The installed script and plist are hash-pinned
like the setup scripts (RUNBOOK.md 10).
