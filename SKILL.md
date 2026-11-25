---
name: macos-ci-runner
description: >
  Turn a Mac into an isolated self-hosted GitHub Actions runner for iOS/macOS test jobs, and keep it healthy.
  It covers a standard CI account on its own encrypted, quota-capped APFS volume, a root-owned Xcode and runner,
  a pf egress guard with a dead-man switch, sshd and Screen Sharing hardening, a job-started hook with a persistence
  baseline, qualification with paired controls, the safe reboot and unlock order, and the macOS pitfalls of a real
  install.
  Use when preparing or repairing a Mac CI host, registering its runner, writing workflows for it, rebooting it, or
  debugging stuck or refused jobs.
  Triggers: self-hosted macOS runner, iOS CI runner on a Mac, runner group, registration token, job-started hook,
  pf anchor, eDSPermissionError, sysadminctl UID, launchctl bootout, fdesetup authrestart, Xcode license on CI,
  queued job never starts; ru: раннер на маке, macOS CI, iOS CI раннер, подготовить мак под CI, перезагрузить CI мак.
---

# macOS CI runner

**What this is:** a host design and tooling for running **untrusted** iOS/macOS test jobs on a Mac that also has an
owner account. The jobs run as a standard CI user with no secrets. The owner's account, the toolchain, the
network neighbours and the disk must survive a hostile job.

- **Design and threat model:** [references/DESIGN.md](references/DESIGN.md)
- **Exact commands, step by step:** [references/RUNBOOK.md](references/RUNBOOK.md)
- **Known macOS pitfalls with fixes:** [references/PITFALLS.md](references/PITFALLS.md)
- **Workflow rules and an example:** [references/WORKFLOW.md](references/WORKFLOW.md), [examples/ios-ci.yml](examples/ios-ci.yml)

## Hard rules
- **Roles.** Root commands and every secret belong to the owner. The volume passphrase, the CI-account password
  and the registration-token paste are typed by the owner; an agent never types, reads, prints or stores them. The
  agent prepares the config and hashes, runs the read-only checks, manages the GitHub side and reads logs.
- **Hash-pin every root run.** The owner runs `host-prep.sh` and `qualify.sh` by absolute path from the root-owned
  setup directory. Every root command starts with one pin that checks the SHA-256 of both scripts **and** of
  `ci-runner.conf` on those root-owned copies (RUNBOOK.md, "Rules for every root command"). The start form is
  `/usr/bin/sudo /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /bin/bash <path> <mode>`.
- **Never stage root inputs in a shared directory** (`/tmp`, `/var/tmp`, `/Users/Shared`). Copy into a fresh
  0700 `mktemp -d` directory in the owner's home, `install` as root, and check the installed copies' hashes before
  anything runs or loads them.
- **One config file.** Every site value lives in `ci-runner.conf` (examples/ci-runner.conf). The file is parsed,
  never sourced; unknown keys and unsafe characters are refused. A change to it is a design change: review it and
  re-pin its hash.
- **Never weaken a refusal to get past it.** The scripts are fail-closed and idempotent. Fix the cause, re-run the
  same command, and look the message up in PITFALLS.md first.
- **The scripts kill nothing and follow no path the CI account controls.** Do not "help" by killing processes
  yourself. End a leftover CI session with `launchctl bootout` (PITFALLS.md 4).
- **pf must be confirmed from a fresh SSH login within 10 minutes**, or it rolls back by itself.
- **Never log the CI account in while its volume is locked** (RUNBOOK.md 10).
- **Test lane only.** No signing identities or App Store Connect keys on this account or runner.

## Phases (RUNBOOK.md has the commands)
| # | Phase | Who |
| --- | --- | --- |
| 0 | Fill `ci-runner.conf`, pin versions and hashes, run `bash tests/run.sh` | agent |
| 1 | Copy the scripts and config to `<support>/setup`, check all three hashes | owner |
| 2 | `preflight` (no sudo) and `preflight --ioc` (root, read-only) | agent, owner |
| 3 | `host`: volume, account, Xcode, hooks, services, pf armed. Run from Terminal at the Mac with Full Disk Access | owner |
| 4 | `confirm-pf` from a new SSH login within 10 minutes | owner |
| 5 | Runner group: one private repository, no public repositories | agent |
| 6 | First CI login, AirPlay off, `config.sh` with the token pasted through the tunnelled Screen Sharing, simulator, logout | owner, agent (token) |
| 7 | `harden-runner` with the CI account logged out | owner |
| 8 | Log the CI account in, run `ci-session-agents` if asked | owner |
| 9 | Qualify: `owner`, `remote`, `root`, `root-postbuild` (must PASS before the first job), cross-repository check, then two jobs in a row | agent, owner |

## Safe reboot (the CI account's GUI session is wedged, or maintenance)
1. Let the running job finish. Cancel queued runs and re-run them later.
2. From SSH: `sudo launchctl bootout gui/<CI_UID>`, then `sudo launchctl bootout user/<CI_UID>`.
3. `sudo fdesetup authrestart` skips the FileVault screen once. A plain reboot needs the owner at the Mac.
4. Unlock the CI volume by hand (`sudo diskutil apfs unlockVolume $(cat <support>/etc/volume-uuid)`), or let the
   optional boot unlock do it.
5. Log the CI account in through the tunnel (`ssh -N -L 5901:127.0.0.1:5900 <host>`, then `vnc://localhost:5901`).
6. Check that the runner is online in the group, then re-run the cancelled jobs.

## Pitfalls in one line each (details and fixes: PITFALLS.md)
- `/opt` with the `hidden` flag is refused: `sudo chflags nohidden /opt`.
- `stat %Lp` hides the sticky digit; the scripts read `%Mp%03Lp`.
- Account creation over SSH without Full Disk Access gives `eDSPermissionError`, the wrong UID and no password.
- Per-user daemons survive a logout and block root work: `launchctl bootout user/<uid>`.
- OpenSSH 10.x prints `sshd -T` keys in CamelCase.
- App Store updates Xcode in place and needs a new license: turn app auto-update off on CI hosts.
- AirPlay Receiver listens on 5000/7000 in every account; turn it off in System Settings.
- Registration token plus Handoff means the token is in every Apple device's clipboard. Turn Handoff off and clear
  the clipboards.
- Runner groups with selected workflows silently queue jobs from new repositories or workflows.
- macOS make is 3.81, without `--eval`.
- `sudo` does not relay signals from its own process group: stop probes by parent PID.
- UI tests are flaky on 8 GB machines: retry them, not unit tests.
- Root has no default keychain ("A default keychain could not be found"), so `sudo security add-generic-password -w`
  cannot store the boot-unlock item. Use `scripts/keychain-add.sh`: it names the System keychain and checks the item
  is there (PITFALLS.md 18). The unlock script refuses to give diskutil an empty passphrase.

## Tools
| Tool | Use | Who runs it |
| --- | --- | --- |
| `scripts/host-prep.sh` | `preflight`, `preflight --ioc`, `host`, `confirm-pf`, `harden-runner [--rebaseline]`, `ci-session-agents` | owner (root modes), agent (`preflight`) |
| `scripts/qualify.sh` | `owner`, `remote`, `remote-inbound`, `root [smb-host]`, `root-postbuild`, `root-inbound`, `root-boot`, `ci`, `quota-fixture` | agent (non-root), owner (root) |
| `scripts/volume-unlock.sh` | optional boot-time unlock of the CI volume from the System keychain | a LaunchDaemon |
| `scripts/keychain-add.sh` | stores the volume passphrase in the System keychain for the boot unlock (`--update` replaces it) | owner, in a terminal |
| `tests/run.sh` | offline unit tests of the helpers, with negative controls | agent, CI |
