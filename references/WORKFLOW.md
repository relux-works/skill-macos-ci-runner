# Workflow rules for jobs on this host

`examples/ios-ci.yml` is a complete example for a Tuist/Xcode iOS project, qualified on a real host. Adapt the
names, but keep these rules.

## Hard rules
- **Self-hosted only, with the exact group and labels:**
  ```yaml
  runs-on:
    group: <RUNNER_GROUP>
    labels: [self-hosted, macOS, ARM64, <RUNNER_EXTRA_LABEL>]
  ```
- **No secrets** in the test lane: `permissions: contents: read`; `actions/checkout` pinned by commit SHA, with
  `persist-credentials: false`.
- **Same-repository pull requests only:**
  ```yaml
  if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository
  ```
- **One job at a time per ref:** use `concurrency` with `cancel-in-progress: true` for pull requests.
- **Nothing global:**
  - Never run `git config --global`. It fails by design at the `~/.gitconfig.lock` placeholder.
  - Never create new entries at the top of `$HOME`. The home is append-only, and a new top-level entry is a baseline
    change that fails the next job.
  - Put DerivedData, SwiftPM and Tuist caches (`XDG_CACHE_HOME`), result bundles and logs under `$RUNNER_TEMP`
    (keep the path short: UNIX sockets have a ~104-byte limit).
- **No installs:** no Homebrew, no `sudo`. The toolchain is the root-owned Xcode and the root-installed Tuist on the
  runner's PATH.
- **Leave nothing running:** shut simulators down in an `if: always()` step (`xcrun simctl shutdown all`). The next
  job's start hook refuses leftover processes.

## Practical notes
- Builds: `CODE_SIGNING_ALLOWED=NO` for simulator builds. Tests use the simulator's ad hoc signing; UI tests that
  touch keychain sharing need the entitlements, so do not disable signing there.
- UI tests on a small machine are flaky. Use `-retry-tests-on-failure -test-iterations 2` for the UI test step
  only, or run UI tests in a separate job.
- `make` on macOS is GNU make 3.81 (no `--eval`). Print Makefile variables with a second makefile:
  `make -s -f Makefile -f "$RUNNER_TEMP/print.mk" print-target`.
- Upload logs always, and result bundles only on failure. Artifact storage for private repositories is limited.
- `workflow_dispatch` works only once the workflow file is on the default branch. The first run is the pull
  request's own run.
- A newer Xcode SDK runs tests on an older installed simulator runtime, as long as the deployment target allows it.
