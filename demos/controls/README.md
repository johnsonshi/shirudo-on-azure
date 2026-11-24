# Replaying and Running the Five Upstream Shirudo Controls

This directory (`demos/controls/`) provides two ways to inspect or run the five defensive controls from upstream Shirudo (`ff5dd643ac0b3d68310450a2cb9b668416eac036`):

1. **Offline replay on your laptop (free, \$0, no Azure account required):** Five shell scripts (`basic.sh`, `java-base64.sh`, `app-sandbox.sh`, `java-sql-inj.sh`, and `af-alg.sh`) read the committed JSON measurement receipts recorded from our Azure runs and print what happened before the shield loaded, while it was active, after it was unloaded, and what normal work continued succeeding throughout.
2. **Live execution on a prepared two-VM Azure lab (`demos/controls/run.sh`):** Orchestrates all five controls on your dedicated Azure operator and target VMs over Azure RBAC VM Run Command (without opening any inbound TCP application or database port), verifies fresh hardware quotes before and after the run, and restores the target VM's initial shield set.

Measured receipts committed in this repository:
- **Real Ubuntu PHP-FPM and H2 JDBC runtimes:** [`docs/results/azure-controls-real-runtimes.json`](../../docs/results/azure-controls-real-runtimes.json) (uses Ubuntu's real `php8.5-fpm` over a private local Unix socket and Ubuntu's `libh2-java` H2 database engine in memory).
- **Minimal fixed fixtures:** [`docs/results/azure-controls.json`](../../docs/results/azure-controls.json) (uses a `php-fpm`-named Python fixture and a mock SQLite JDBC `Statement`).

---

### Replay a single recorded control (offline)

From the repository root, run any of the five commands below. By default, each script reads the fixed-fixture receipt (`docs/results/azure-controls.json`); pass `--receipt docs/results/azure-controls-real-runtimes.json` to replay the real Ubuntu PHP-FPM and H2 run:

```sh
demos/controls/app-sandbox.sh --receipt docs/results/azure-controls-real-runtimes.json
demos/controls/java-sql-inj.sh --receipt docs/results/azure-controls-real-runtimes.json
demos/controls/af-alg.sh --receipt docs/results/azure-controls-real-runtimes.json
demos/controls/java-base64.sh --receipt docs/results/azure-controls-real-runtimes.json
demos/controls/basic.sh --receipt docs/results/azure-controls-real-runtimes.json
```

For example, running `demos/controls/app-sandbox.sh --receipt docs/results/azure-controls-real-runtimes.json` prints:

```text
Recorded evidence (offline replay): app-sandbox, one row from the full suite; no guest contacted.
Upstream: https://github.com/shirudo-dev/shirudo/tree/ff5dd643ac0b3d68310450a2cb9b668416eac036/upatches/app-sandbox
Before: Ubuntu PHP-FPM worker (private Unix socket): both canaries written
Active: .php denied (EACCES); .txt written
Restored: both canaries written after unload
Positive control: inert .txt write succeeded in all three phases
```

**How to read the output and exit codes:**
- `Before`: What happened on the target VM before the shield was loaded.
- `Active`: What was blocked (or verified) while the signed shield was active.
- `Restored`: What happened after the matching signed unload removed the shield (or, for `java-base64`, confirmation that the pre-existing shield was retained).
- `Positive control`: Which normal side-by-side operation kept succeeding across all phases.
- Exit status `0` means the selected recorded control and the receipt's suite-level attestation and cleanup fields match all expected invariants. Exit status `3` means the control was recorded as `unsupported` in that receipt, and any other nonzero exit code means missing, malformed, or contradictory evidence. These offline scripts do not contact Azure or re-run cryptographic quote verification; to collect new live evidence, run the full suite once as described below.

| Control | What it tests and what to look for (across both receipts) |
|---|---|
| [Application sandbox (`app-sandbox`)](https://github.com/shirudo-dev/shirudo/tree/ff5dd643ac0b3d68310450a2cb9b668416eac036/upatches/app-sandbox) | **Why:** Prevents a compromised web worker from dropping new `.php` program files ("webshells") while allowing ordinary data writes. **Real-runtime receipt:** An unprivileged single-worker Ubuntu `php-fpm` (`8.5.4-0ubuntu1.6`) pool over a private mode-`0600` Unix socket. **Fixture receipt:** A temporary copy of distro Python matching the unchanged upstream `php-fpm` binary path selector in a private mount namespace. **Result:** A fresh worker `exec` after load cannot create `canary.php` (`EACCES`) but can still create `canary.txt` (`written`). Both files succeed before load and after unload. Temporary containment only; does not fix a bug inside PHP. |
| [Java JDBC SQL guard (`java-sql-inj`)](https://github.com/shirudo-dev/shirudo/tree/ff5dd643ac0b3d68310450a2cb9b668416eac036/upatches/java-sql-inj/agent) | **Why:** Startup Java agent (`Premain-Class`) that inspects SQL strings in `java.sql.Statement` and blocks queries matching suspicious lexical patterns. **Real-runtime receipt:** Ubuntu's H2 database engine (`libh2-java` `2.2.220-1build1`) against a fresh, empty in-memory database. **Fixture receipt:** A mock `java.sql.Statement` backed by empty in-memory SQLite. **Result:** Runs two fixed, harmless read queries (never a multi-statement break-in attempt). The normal query `SELECT 7` returns `7` in all three phases. A separate harmless query containing a false arithmetic comparison returns zero rows (`empty`) before load, is rejected with the agent's `SecurityException` (`policy-exception`) in a newly started JVM while active, and returns zero rows (`empty`) again after unload. |
| [AF_ALG socket block (`cve-2026-31431-af-alg-block`)](https://github.com/shirudo-dev/shirudo/blob/ff5dd643ac0b3d68310450a2cb9b668416eac036/upatches/kernel-cve/sources/cve-2026-31431-crypto-algif-aead-copy-fail/mitigation/cve-2026-31431-af-alg-block.bpf.c) | **Why:** Blocks unprivileged creation of Linux kernel `AF_ALG` cryptography sockets to mitigate kernel `AF_ALG` vulnerabilities without rebooting. **Result:** An unprivileged process creates and closes unbound sockets (`15` measured attempts after `3` warmups per phase). `AF_ALG` succeeds (`allowed`), is blocked with `EPERM` while active, and succeeds again after unload. Normal `AF_UNIX` local sockets succeed throughout. No cipher is bound and no crypto payload is sent. If the OS already denies `AF_ALG` at baseline, the runner records the control as unsupported rather than relaxing the OS. |
| [Java Base64 (`java-base64`)](https://github.com/shirudo-dev/shirudo/tree/ff5dd643ac0b3d68310450a2cb9b668416eac036/upatches/java-base64) | **Why:** Verifies running-JVM continuity across live agent attachment (**continuity only, not an exploit demo**). **Result:** One unprivileged JVM decodes `Y29udHJvbA==` to `control` before and after explicit attach of the pre-existing sealed JAR (`initial_count = 1`). The JVM's PID and start timestamp remain identical and the upstream install diagnostic is emitted. The pre-existing shield is preserved, not unloaded. |
| [Quickstart `basic`](https://github.com/shirudo-dev/shirudo/blob/ff5dd643ac0b3d68310450a2cb9b668416eac036/testing/fixtures/basic.bpf.c) | **Why:** End-to-end check of signed BPF loading, vTPM measurement, and digest-bound unloading. **Result:** The signed no-op shield is `absent` before load, `loaded_and_measured` while active, and `absent` after its digest-bound unload. Both transitions extend the certified vTPM measurement register. |

---

## Running the suite live on a prepared two-VM Azure lab

If you do not have a prepared two-VM Azure lab yet, follow the [**Azure Two-VM Lab Runbook (`docs/azure-lab-runbook.md`)**](../../docs/azure-lab-runbook.md) to provision and boot one first. Remember that a loaded upstream shield applies to the target guest VM as a whole, so always use a dedicated lab VM.

### Prerequisites before running

- Use a trusted Azure CLI login (`az`) with `Microsoft.Compute/virtualMachines/runCommand/action` permission on both lab VMs, Python 3.9+ on your workstation, and the kernel, runtime, operator certificates, and signed configuration built from this repository.
- The runner accesses only the **explicitly named resource group** in the **explicitly selected subscription**. A fresh lab created by `infra/azure/lab.py` requires the initializer's private `.state/owner.json` receipt and matching `shirudoLab` ownership tags on the resource group and both VMs. (Only when targeting the original historical lab created before ownership tokens were introduced, set `SHIRUDO_HISTORICAL_LAB=1` and name its `purpose=shirudo-demo` resource group explicitly; that mode never overrides a mismatched receipt or adopts a token-tagged group.)
- Prepare the signed shield pairs on the operator VM from the **pinned upstream commit (`ff5dd643ac0b3d68310450a2cb9b668416eac036`)** using `python3 infra/azure/lab.py build-controls` and `python3 infra/azure/lab.py stage-controls` (see [`docs/azure-lab-runbook.md`](../../docs/azure-lab-runbook.md#phase-3-build-stage-and-run-the-five-upstream-controls)). On the operator VM, `shirudo image verify` must accept `~/build/target-bundle/initial` against its config certificate.
- Stage **only the ten named signed files below** onto the target VM at `/var/tmp/shields` (override with `SHIRUDO_TARGET_SHIELDS`), keeping the originals on the operator at `~/build/shields`. Never copy private signing keys, full build directories, or upstream demo web apps onto the target VM. Each row below represents a `<basename>.upatch` load file and a digest-bound `<basename>.unload.upatch` unload file:

  | Directory | Basename |
  |---|---|
  | `walkthrough` | `basic` |
  | `java4shell` | `java-base64` |
  | `php2shell` | `app-sandbox` |
  | `sqli` | `java-sql-inj` |
  | `copy-fail` | `cve-2026-31431-af-alg-block` |

- The Java controls require Ubuntu's current headless OpenJDK 25 JDK and JRE packages (`openjdk-25-jdk-headless` and `openjdk-25-jre-headless`) and a signed local APT security index updated within the past three days (`stage-controls` installs these automatically on a fresh lab). The default fixture run uses distro Python's built-in `sqlite3` module and requires no external database package.

## Run the live control suite

Export `AZ_SUBSCRIPTION` and `AZ_RESOURCE_GROUP` in your workstation shell (never commit them). `TARGET_VM`, `OPERATOR_VM`, `ADMIN_USER`, `TARGET_SIZE`, and `OPERATOR_SIZE` default to the values in `.env.example`; export any custom overrides you used when creating your lab. Choose a **new private directory outside the repository checkout** to hold the pinned attestation key and private failure diagnostics:

```sh
export SHIRUDO_CONTROL_STATE="$HOME/.local/state/shirudo-controls/lab"
demos/controls/run.sh enroll                      # once, separately, through authenticated Azure RBAC
demos/controls/run.sh run --receipt /tmp/controls-1.json
demos/controls/run.sh run --receipt /tmp/controls-2.json
```

### Optional: real PHP-FPM and an H2 JDBC driver

To run the suite against Ubuntu's real `php8.5-fpm` worker and H2 JDBC driver (`libh2-java`) instead of the default Python/SQLite fixtures, first stage the three verified Ubuntu candidate `.deb` archives on the **target VM**. This downloads the signed packages using `apt-get download` without installing them system-wide, running package maintainer scripts, or starting a host daemon:

```sh
sudo bash <<'STAGE'
set -euo pipefail
umask 077
export LC_ALL=C
/usr/bin/python3 -I -c 'import apt'
apt-get -o APT::Update::Error-Mode=any update -q
stage=$(mktemp -d /var/tmp/shirudo-runtime-debs.XXXXXXXX)
cd "$stage"
for pkg in php8.5-fpm libargon2-1 libh2-java; do
    version=$(apt-cache policy "$pkg" | awk '$1 == "Candidate:" {print $2}')
    [[ -n "$version" && "$version" != '(none)' ]]
    apt-get download "$pkg=$version"
    files=("${pkg}"_*.deb)
    [[ ${#files[@]} == 1 && -f "${files[0]}" ]]
    mv -- "${files[0]}" "$pkg.deb"
done
printf 'Target staging directory: %s\n' "$stage"
STAGE
```

Then, from your **workstation**, pass that printed absolute **target VM** directory path to `--distro-debs` (default fixture runs never need these packages or upload `distro.py`):

```sh
demos/controls/run.sh run --distro-debs /path/to/private/package-staging \
  --receipt "$SHIRUDO_CONTROL_STATE/real-runtimes.json"
```

When `--distro-debs` is supplied, the runner fails closed rather than falling back to the synthetic fixtures. It verifies each `.deb` file's full SHA-256 digest, package name, and version against the target VM's trusted Ubuntu APT candidate cache and extracts only the `php-fpm` binary, its `libargon2` shared library, and the H2 JAR into a temporary working directory:
- The real `php-fpm` master and its single worker run unprivileged inside a private network namespace, communicating only over a private mode-`0600` Unix socket via fixed FastCGI requests. A fresh worker pool executes the labeled `php-fpm` binary in each phase (`Before`, `Active`, `Restored`), testing `canary.php` and `canary.txt` outside the script directory.
- The real H2 JDBC `Statement` runs the same two fixed, harmless reads (`SELECT 7` and the harmless false comparison) against a fresh, empty in-memory H2 database with no network listener.

After the run finishes, clean up the staging directory on the target VM by removing only those three named `.deb` files (`php8.5-fpm.deb`, `libargon2-1.deb`, `libh2-java.deb`) and removing the empty directory with `rmdir`.

## How verification, cleanup, and timing work

- **Attestation and fresh nonces:** `enroll` pins the target VM identity and its vTPM attestation key (AK) `Name` once, refusing to overwrite an existing pin. `run` generates independent random 32-byte nonces before and after the five controls and never trusts a key self-reported inside the quotes under test. Both evidence documents are verified offline **on the operator VM** (`shirudo attest verify`), checking initrd binding, the operator-signed configuration root in `PCR 13`, and explicit rejection of a wrong nonce. Finally, the runner verifies that the target's post-run measurement register equals the verified pre-run baseline extended by the exact planned sequence of signed loads and unloads. As noted in the root `README.md`, this is authenticated-channel first-use enrollment (TOFU) with Secure Boot **off** on the target VM and the RSA-2048 NV-writer compatibility patch; it is not Endorsement Key (EK) certificate validation or Azure Guest Attestation.
- **Run Command output paging:** Azure VM Run Command caps standard output at 4 KiB per invocation. The first evidence collection pages the full quote and firmware boot logs across multiple chunks; subsequent quotes on the same boot can reuse an identical boot-log suffix cached in your private state directory, and the workstation verifies the SHA-256 of the **entire byte-for-byte reconstructed document** before passing it to `shirudo attest verify`.
- **State restoration and exit codes:** Each run snapshots and compares the full shield inventory, boot ID, TCP listeners, and `crypto.af_alg_restrict` setting before and after execution. It never unloads a pre-existing shield (using the pre-existing signed `java-base64` agent for live-attach continuity only) and always unloads its own loaded shields in a `finally` block. Exit `0` means every control and final attestation check passed; exit `3` writes a partial receipt with `unsupported` leaves only if final attestation and state restoration succeeded. The wrapper never overwrites an existing receipt file.
- **Timing and `crypto.af_alg_restrict` provenance:** All timings use the guest monotonic clock. Each signed CLI load/unload (`operation_ms`) is timed once per run and includes synchronous vTPM `NV_Extend` work. Socket timings record the median of `15` unbound socket create/close calls (or synchronous `EPERM` refusals) after `3` warmups per socket family and phase. Both committed receipts measured `AF_ALG` while the lab's pre-existing `crypto.af_alg_restrict` was `0` (neither suite changed it). Afterward, [separate housekeeping (`docs/results/azure-af-alg-restoration.json`)](../../docs/results/azure-af-alg-restoration.json) verified that our pinned kernel source initializes `crypto.af_alg_restrict` to `1` and restored the setting to `1` without re-running the socket probe. Never lower an OS security setting on a host just to make `AF_ALG` pass.

