# skill-macos-ci-runner

Make a Mac an isolated self-hosted GitHub Actions runner for iOS/macOS test jobs:
- a standard CI account on its own encrypted, quota-capped APFS volume;
- a root-owned toolchain;
- a pf egress guard with a dead-man switch;
- a job-started hook with a persistence baseline;
- qualification with paired controls.

Includes the macOS pitfalls from a real install.

- Instructions for agents: [SKILL.md](SKILL.md)
- Design and threat model: [references/DESIGN.md](references/DESIGN.md)
- Step-by-step commands (owner and operator): [references/RUNBOOK.md](references/RUNBOOK.md)
- Pitfalls with fixes: [references/PITFALLS.md](references/PITFALLS.md)
- Workflow rules and an example: [references/WORKFLOW.md](references/WORKFLOW.md), [examples/ios-ci.yml](examples/ios-ci.yml)

## Tools

| Tool | Use | Run | Output |
| --- | --- | --- | --- |
| `scripts/host-prep.sh` | prepare the host, confirm pf, harden the runner | owner, see RUNBOOK.md (root, hash-pinned) | `/var/log/<LABEL_PREFIX>.setup.log` on the host |
| `scripts/qualify.sh` | qualification with paired controls | RUNBOOK.md step 9 | PASS/FAIL/SKIP/RESID lines, `RESULT` |
| `scripts/volume-unlock.sh` | optional boot-time volume unlock | LaunchDaemon from `examples/volume-unlock.plist.template` | `/var/log/<LABEL_PREFIX>.volume-unlock.log` |
| `scripts/keychain-add.sh` | stores the volume passphrase in the System keychain (re-runnable; `--update` replaces) | `ssh -t <host> ... keychain-add.sh <LABEL_PREFIX>.volume` (RUNBOOK.md 10) | the System keychain item only |
| `tests/run.sh` | offline unit tests with stubs and negative controls: config loader, root trust predicates, `--ioc` site lists, render and rendered templates, sshd parsing, mode readback, stop_bg, volume-unlock arguments, mount state and passphrase handling, keychain-add | `/bin/bash tests/run.sh` | none (scratch removed) |

Requirements on the host: macOS 27 or newer on Apple silicon, Xcode in `/Applications/Xcode.app`, FileVault on, an
owner account with sudo, and SSH from an admin workstation (a tailnet or LAN, not the public Internet).

License: Apache-2.0.
