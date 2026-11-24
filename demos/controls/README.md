# Live upstream Shirudo controls

This runs five fixed, defensive controls on the existing two-role Azure lab. It uses Azure RBAC Run Command, not SSH. No test opens an IP listener. There is no package downgrade, sysctl change, system service start, reboot, network-rule change, registry, or backend. Run it on a dedicated lab: a loaded upstream shield applies to the guest, not just to the fixture.

Measured receipts: [fixed fixtures](../../docs/results/azure-controls.json) and [real PHP-FPM and H2 JDBC](../../docs/results/azure-controls-real-runtimes.json). The latter used a private Unix socket, never an IP listener.

| Control | What to look for |
|---|---|
| [Quickstart `basic`](https://github.com/shirudo-dev/shirudo/blob/ff5dd643ac0b3d68310450a2cb9b668416eac036/testing/fixtures/basic.bpf.c) | The signed no-op is absent, present, then absent. Both events advance the certified register. |
| [Java Base64](https://github.com/shirudo-dev/shirudo/tree/ff5dd643ac0b3d68310450a2cb9b668416eac036/upatches/java-base64) | One unprivileged JVM decodes `Y29udHJvbA==` to `control` before and after explicit attach. PID and JVM start time stay the same; the sealed JAR emits its upstream install diagnostic. **Continuity, not exploit prevention.** |
| [Application sandbox](https://github.com/shirudo-dev/shirudo/tree/ff5dd643ac0b3d68310450a2cb9b668416eac036/upatches/app-sandbox) | A temporary copy of distro Python matches the **unchanged upstream PHP-FPM executable selector** in a private mount namespace. A fresh exec after load cannot create `canary.php` (`EACCES`) but can still create `canary.txt`. Both succeed before load and after unload. These are new, inert files outside any web root. **Not a real PHP server or an in-place restriction of an already running process.** |
| [Java JDBC guard](https://github.com/shirudo-dev/shirudo/tree/ff5dd643ac0b3d68310450a2cb9b668416eac036/upatches/java-sql-inj/agent) | A mock `java.sql.Statement` executes two fixed reads against empty, in-memory SQLite. In a fresh JVM given the sealed agent, the normal `SELECT 7` returns `7`, and a harmless false arithmetic predicate matches the upstream lexical policy and throws the agent's `SecurityException`. No application input or injection attempt. |
| [AF_ALG family policy](https://github.com/shirudo-dev/shirudo/blob/ff5dd643ac0b3d68310450a2cb9b668416eac036/upatches/kernel-cve/sources/cve-2026-31431-crypto-algif-aead-copy-fail/mitigation/cve-2026-31431-af-alg-block.bpf.c) | An unprivileged process creates and closes unbound sockets. `AF_ALG` succeeds, fails with `EPERM`, then succeeds again. `AF_UNIX` succeeds throughout. The policy covers the **whole family**. No algorithm, bind, send, or crypto operation is used. If the OS already denies the baseline, this control is unsupported; do not relax the OS. |

## Before running

- Use a trusted Azure CLI login with Run Command permission on the intended VMs, Python 3.9+ on the workstation, and the image, kernel, runtime, operator certificates and signed config from this repository. The runner reads only the **explicitly named group** in the **explicitly selected subscription**. A fresh lab requires the initializer's private `.state/owner.json` and matching group and VM ownership tags. Another lab in the subscription is irrelevant. Only for the historical lab without an ownership token, set `SHIRUDO_HISTORICAL_LAB=1` and name its existing `purpose=shirudo-demo` group explicitly. This mode cannot override a mismatched receipt or adopt a newer token-tagged group. Do not retag any deployed lab.
- Prepare the signed artifacts from the **pinned upstream defensive sources** above. The operator must approve the actual binary pairs; this suite does not establish source-to-binary reproducibility. Its local upstream checkout must include `ff5dd643ac0b3d68310450a2cb9b668416eac036`, with the checked source paths unchanged. `shirudo image verify` must accept the operator's `~/build/target-bundle/initial` against its config certificate.
- Stage **only the ten named files below** through an authorized management channel. Do not copy whole build directories, signing keys or the upstream Java demo applications. The operator reads `~/build/shields`; the target reads `/var/tmp/shields` (override with `SHIRUDO_TARGET_SHIELDS`). Each row names one directory and a basename; the only suffixes are `.upatch` and `.unload.upatch`.

  | Directory | Basename |
  |---|---|
  | `walkthrough` | `basic` |
  | `java4shell` | `java-base64` |
  | `php2shell` | `app-sandbox` |
  | `sqli` | `java-sql-inj` |
  | `copy-fail` | `cve-2026-31431-af-alg-block` |

- The Java cases need the current Ubuntu OpenJDK 25 JDK and JRE headless candidates installed, and a signed local security index at most three days old. Update the lab via its normal package process beforehand; the demo never fetches packages. The SQLite fixture uses distro Python's `sqlite3` module, not a vulnerable application or a third-party JDBC driver.

## Run

Export `AZ_SUBSCRIPTION` and `AZ_RESOURCE_GROUP` privately (do not paste them into the repository). `TARGET_VM`, `OPERATOR_VM`, `ADMIN_USER`, `TARGET_SIZE` and `OPERATOR_SIZE` default to the values in `.env.example`; export any overrides you used in your deployment. Select a **new private directory outside the checkout** for the AK pin and private failure diagnostics:

```sh
export SHIRUDO_CONTROL_STATE="$HOME/.local/state/shirudo-controls/lab"
demos/controls/run.sh enroll                      # once, separately, through authenticated Azure RBAC
demos/controls/run.sh run --receipt /tmp/controls-1.json
demos/controls/run.sh run --receipt /tmp/controls-2.json
```

### Optional: real PHP-FPM and an H2 JDBC driver

On the **target**, use its configured Ubuntu archive with normal signature verification and the distribution's `python3-apt` module. Refresh the index and download only the three current candidate packages. This does not install them, run maintainer scripts, or change the system service configuration:

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

On the **workstation**, use the printed absolute **target** path (never a local directory). Default fixture runs do not need these packages or send `distro.py`:

```sh
demos/controls/run.sh run --distro-debs /path/to/private/package-staging \
  --receipt "$SHIRUDO_CONTROL_STATE/real-runtimes.json"
```

This mode fails rather than silently substituting the fixtures. It matches each package's full SHA-256, name and version to the distro APT candidate and extracts only the PHP-FPM executable, its Argon2 shared library and the H2 driver JAR. It does not install a package or enable a daemon. The real PHP-FPM master and its single worker run unprivileged in a private network namespace; the only request is fixed FastCGI over a mode-0600 Unix socket. A fresh pool executes the labeled binary in each phase. Its two files are outside the script directory. The real H2 JDBC `Statement` executes the same two fixed reads in a fresh, empty, in-memory database with no database listener. Both modes use the same operator-approved upstream shields.

After the run, on the target remove only those three named `.deb` files from the printed staging directory, then remove that empty directory with `rmdir`. Do not copy a build tree or change an APT trust setting to make a candidate pass.

`enroll` pins the target VM identity and AK name, refusing to replace an existing pin. `run` requests independent 32-byte challenges before and after the suite; it never pins a key from either of the documents under test. Each document must verify offline **on the operator**, including the approved config root in PCR 13 and an initrd binding. Each must also fail verification on a different nonce. The final register must equal the verified baseline extended by exactly the expected control events and operator-approved payloads. A previous measured history is **not** a declaration of desired state. This is authenticated-channel TOFU, not endorsement-chain validation, Azure Attestation, or an independent allowlist for every boot PCR. The application and socket outcomes come from guest probes, not directly from the TPM.

Run Command limits guest output to 4 KiB. The first run may take several minutes to page the full evidence, including firmware logs. Repeat quotes can reuse an identical boot-log suffix from the private state directory; the workstation checks the SHA-256 of the **entire, byte-for-byte reconstructed document** before offline verification. No signed field or log is discarded.

A run compares the complete shield inventory, boot identity, TCP listeners and AF_ALG sysctl before and after. It never unloads a pre-existing shield. It can use an already installed, exactly matching signed Base64 agent for **fixture attach only**. An owned load uses a matching signed, payload-bound unload in a `finally` block; expected-register checks reject interleaved state changes. Upstream Java unload can leave a sealed no-op placeholder by design. NV events remain in the measurement history. An interrupted run or unexpected digest is not a pass: inspect private diagnostics and the current measured inventory before rerunning. Do not blindly unload an existing name.

Exit `0` means every control and the final checks passed. Exit `3` writes a partial receipt with explicitly unsupported leaves **only after** successful final verification and cleanup. Other failures do not produce a passing receipt; the wrapper never overwrites an existing receipt. Review a receipt before publishing. No quotes, host identifiers, VM IDs, AKs, raw logs, signatures, or private config are intended for publication.

Durations use the guest monotonic clock. Each signed CLI load/unload is timed once per run. Socket samples time only creation and close, or the synchronous errno: 3 warmups and 15 measured samples per family per phase. These are not application throughput, asynchronous detection latency, or Azure orchestration durations.

The example on this lab uses the repository's Azure vTPM NV-writer compatibility build (RSA-2048). The target has Secure Boot **off**: a verified initrd measurement is not Secure Boot enforcement. Treat the receipt's `af_alg_restrict_unchanged` as a pre-existing lab setting, not a recommended or stock distribution default. For a previously modified throwaway lab, use the project's normal clean boot into its existing measured UKI and re-check health, separately from a demo; do not lower a setting to manufacture an allowed baseline.
