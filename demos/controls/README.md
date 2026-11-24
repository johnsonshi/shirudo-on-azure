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

- Use a trusted Azure CLI login with Run Command permission on the intended existing VMs, Python 3.9+ on the workstation, and the image, kernel, runtime, operator certificates and signed config from this repository. The explicit subscription must contain exactly one group tagged `purpose=shirudo-demo`, with just the configured target and operator roles and the expected SKUs.
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

Export `AZ_SUBSCRIPTION` and `AZ_RESOURCE_GROUP` privately (do not paste them into the repository). `TARGET_VM`, `OPERATOR_VM`, and `ADMIN_USER` default to the roles in `.env.example`. Select a **new private directory outside the checkout** for the AK pin and private failure diagnostics:

```sh
export SHIRUDO_CONTROL_STATE="$HOME/.local/state/shirudo-controls/lab"
demos/controls/run.sh enroll                      # once, separately, through authenticated Azure RBAC
demos/controls/run.sh run --receipt /tmp/controls-1.json
demos/controls/run.sh run --receipt /tmp/controls-2.json
```

### Optional: real PHP-FPM and an H2 JDBC driver

Stage three current Ubuntu candidate `.deb` files in a root-owned directory on the target using the lab's approved package or management channel. Use exactly `php8.5-fpm.deb`, `libargon2-1.deb` and `libh2-java.deb` as filenames. Run:

```sh
demos/controls/run.sh run --distro-debs /path/to/private/package-staging \
  --receipt /tmp/controls-real-runtimes.json
```

This mode fails rather than silently substituting the fixtures. It matches each package's full SHA-256, name and version to the distro APT candidate and extracts only the PHP-FPM executable, its Argon2 shared library and the H2 driver JAR. It does not install a package or enable a daemon. The real PHP-FPM master and its single worker run unprivileged in a private network namespace; the only request is fixed FastCGI over a mode-0600 Unix socket. A fresh pool executes the labeled binary in each phase. Its two files are outside the script directory. The real H2 JDBC `Statement` executes the same two fixed reads in a fresh, empty, in-memory database with no database listener. Both modes use the same operator-approved upstream shields.

`enroll` pins the target VM identity and AK name, refusing to replace an existing pin. `run` requests independent 32-byte challenges before and after the suite; it never pins a key from either of the documents under test. Each document must verify offline **on the operator**, including the approved config root in PCR 13 and an initrd binding. Each must also fail verification on a different nonce. The final register must equal the verified baseline extended by exactly the expected control events and operator-approved payloads. A previous measured history is **not** a declaration of desired state. This is authenticated-channel TOFU, not endorsement-chain validation, Azure Attestation, or an independent allowlist for every boot PCR. The application and socket outcomes come from guest probes, not directly from the TPM.

Run Command limits guest output to 4 KiB. The first run may take several minutes to page the full evidence, including firmware logs. Repeat quotes can reuse an identical boot-log suffix from the private state directory; the workstation checks the SHA-256 of the **entire, byte-for-byte reconstructed document** before offline verification. No signed field or log is discarded.

A run compares the complete shield inventory, boot identity, TCP listeners and AF_ALG sysctl before and after. It never unloads a pre-existing shield. It can use an already installed, exactly matching signed Base64 agent for **fixture attach only**. An owned load uses a matching signed, payload-bound unload in a `finally` block; expected-register checks reject interleaved state changes. Upstream Java unload can leave a sealed no-op placeholder by design. NV events remain in the measurement history. An interrupted run or unexpected digest is not a pass: inspect private diagnostics and the current measured inventory before rerunning. Do not blindly unload an existing name.

Exit `0` means every control and the final checks passed. Exit `3` writes a partial receipt with explicitly unsupported leaves **only after** successful final verification and cleanup. Other failures do not produce a passing receipt; the wrapper never overwrites an existing receipt. Review a receipt before publishing. No quotes, host identifiers, VM IDs, AKs, raw logs, signatures, or private config are intended for publication.

Durations use the guest monotonic clock. Each signed CLI load/unload is timed once per run. Socket samples time only creation and close, or the synchronous errno: 3 warmups and 15 measured samples per family per phase. These are not application throughput, asynchronous detection latency, or Azure orchestration durations.

The example on this lab uses the repository's Azure vTPM NV-writer compatibility build (RSA-2048). The target has Secure Boot **off**: a verified initrd measurement is not Secure Boot enforcement.

Both receipts measured AF_ALG with the lab's pre-existing `crypto.af_alg_restrict=0`. Neither suite changed it. After the measurements, [separate housekeeping](../../docs/results/azure-af-alg-restoration.json) matched the running kernel package to its operator build, confirmed its pinned source initializes the setting to `1`, found no configured override, and restored and read back `1`. No shield or socket probe was run as part of the restoration. The earlier timings and outcomes are not measurements at the restored value or a claim about stock Ubuntu. Do not lower a restriction to reproduce them.
