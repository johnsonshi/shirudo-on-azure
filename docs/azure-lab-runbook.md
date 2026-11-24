# Azure Two-VM Lab Runbook: Building, Booting, and Tearing Down from Scratch

This runbook covers provisioning a fresh two-VM Shirudo lab on Microsoft Azure, compiling the custom Linux kernel and Shirudo packages on the **operator VM**, booting and verifying the Unified Kernel Image (UKI) on the **target VM**, staging the five upstream controls, and deleting all billable Azure resources when finished.

- If you only want to inspect the recorded results offline for \$0 with no Azure account, see [Start here in `README.md`](../README.md#replay-this-result-on-your-laptop-right-now-offline-0-no-azure-account-required).
- If you already have a prepared two-VM Azure lab and want to run the five controls, see [`demos/controls/README.md`](../demos/controls/README.md#running-the-suite-live-on-a-prepared-two-vm-azure-lab).
- For the architectural story and measured results, see [`docs/blog/shirudo-on-azure-field-notes.md`](blog/shirudo-on-azure-field-notes.md).

---

## Prerequisites and network requirements

Use a workstation with:
- Azure CLI (`az`), Python 3.9+, Git, and OpenSSH (including `ssh-keygen -Y`).
- Permission to create resources in your intended Azure subscription.
- Outbound TCP port 22 connectivity **from a single public IPv4 `/32` address**.

If your workstation's SSH traffic exits through rotating IP addresses, do not widen the Network Security Group (NSG) to a subnet, an Azure service tag, or `0.0.0.0/0`; use a workstation with a stable `/32` egress IP instead. Both Azure VMs require outbound internet access to download signed Ubuntu packages and the pinned upstream source tree.

1. Log in with `az login`. In this checkout, run `umask 077` and `cp .env.example .env`.
2. Edit `.env`:
   - Set `AZ_SUBSCRIPTION` to the explicit subscription **UUID**.
   - Set `AZ_RESOURCE_GROUP` to a **new, dedicated** resource group name.
   - Fill in `AZ_LOCATION` and `ALLOWED_SSH_CIDR` (your single public IPv4 `/32`).
   - Note that `infra/azure/lab.py` reads `.env` directly as key-value data; `.env` is never executed as a shell script.
   - Supply an existing, dedicated Ed25519 key pair at `SSH_KEY` and `SSH_KEY.pub`. To create one, run:
     ```sh
     ssh-keygen -t ed25519 -f ~/.ssh/shirudo_on_azure_ed25519
     ```
     Use `ssh-add` locally if your key is passphrase-protected. SSH agent forwarding is disabled.
3. **Review cost and quota before creation:** The default configuration in `.env.example` requests a `Standard_D32ds_v5` build VM (with a 256 GiB OS disk), a `Standard_D4ds_v5` target VM (with a 64 GiB OS disk), two Premium SSD managed disks, and two Standard public IPv4 addresses. Building a custom Linux kernel takes time, and **there is no automatic shutdown or budget cap**. Setting `UBUNTU_IMAGE` to `:latest` selects the current Ubuntu 26.04 image revision at creation time rather than a reproducible OS snapshot; you may set an exact Canonical image version in `.env`.
4. Run each phase below **separately** and stop at the first failure. Do not point the initializer at an existing lab: it refuses to adopt existing resource groups, and both guests must be fresh.

---

## Phase 1: Provision VMs, stage committed inputs, build on the operator, and relay

```sh
# Workstation. create --spend is the first command that creates billable Azure resources.
python3 infra/azure/lab.py create --spend
python3 infra/azure/lab.py stage operator
python3 infra/azure/lab.py stage target
python3 infra/azure/lab.py build
python3 infra/azure/lab.py relay
```

- **`stage`** sends only the allowlisted regular blobs from the **committed** Git tree (`HEAD`), once, into a new commit-specific directory on the remote VM (`shirudo-on-azure-<commit>`). It never syncs a working tree or uploads `.env`, keys, or `.scratch/` drafts.
- **`build`** fetches the pinned upstream revision in [`patches/shirudo/BASE`](../patches/shirudo/BASE), runs its `bpf-next` kernel builder with the [Hyper-V guest driver config](../kernel/azure.conf), and then runs upstream `make -C packaging bindeb-pkg` with that kernel's BTF and both local compatibility patches. It installs the operator package and uses upstream's image generators to build the signed config image, read-only runtime image, and UKI bootstrap. Build logs and private signing keys stay on the operator VM.
- **`relay`** streams individually named boot artifacts from the operator VM through your workstation to the target VM (never a tarball of a build directory). It pins a separate transport public key from the authenticated operator onto the target and verifies its signed SHA-256 manifest. This transport check covers the kernel and Debian packages in transit; it does **not** make the custom kernel UEFI Secure Boot-signed or replace Shirudo's own image checks. The workstation SSH client accepts new host keys on first contact (`StrictHostKeyChecking=accept-new` in `.state/known_hosts`) and rejects changed keys. For stronger first-contact assurance, pin independently verified guest host keys in `.state/known_hosts` before running `stage`.

---

## Phase 2: Two-stage boot and verification on the target VM

```sh
python3 infra/azure/lab.py install-kernel
python3 infra/azure/lab.py restart --reboot
# Wait for SSH to return. Check that the kernel release contains "shirudo-azure".
python3 infra/azure/lab.py status

python3 infra/azure/lab.py enable
python3 infra/azure/lab.py restart --reboot
# Wait for SSH, then check kernel, runtime mount, service, and upstream status.
python3 infra/azure/lab.py verify
```

### Why booting happens in two steps (unsealed first boot vs. sealed UKI second boot)
1. **First boot (`install-kernel` -> `restart --reboot`):** Boots the custom `shirudo-azure` kernel once from a regular GRUB entry before the UKI exists. That first boot creates the kernel's `.bpf` and `.dm-verity` keyrings in an unsealed (writable) state so `python3 infra/azure/lab.py enable` can run upstream's target setup, enroll the operator's public certificates, and assemble the Unified Kernel Image (UKI) containing the pinned runtime root hash, public BPF certificate, and early `systemd` TPM setup module.
2. **Second boot (`enable` -> `restart --reboot`):** Chainloads the UKI. Inside the UKI's early boot disk (`initrd`), before the root filesystem is mounted, `shirudo init` loads the operator's public certificates into the `.bpf` and `.dm-verity` keyrings and **immediately seals both keyrings** and attaches the `lsm/bpf` kernel guard. Once sealed, no further keys or unsigned BPF programs can be added during that boot.

### What `verify` checks and how GRUB fallback safety works
- **`verify`** reads upstream `shirudo status --json`: it requires an overall target verdict of `ok` and all **seven** pinned target conditions (`LsmAttached`, `KeyringSealed`, `ChainIntact`, `UpatchesMeasured`, `TpmMeasured`, `ConfigActive`, and `XdpCovered`) at `OK`. A working SSH connection, an active systemd unit, or `shirudo status` exiting `0` alone is not enough.
- **Measured boot vs. Secure Boot:** The **target VM's Secure Boot is off** because its custom kernel and UKI are not signed by a firmware-trusted UEFI certificate; its **vTPM stays on** to record boot and shield measurements. Neither a vTPM nor `verify` establishes a production UEFI Secure Boot chain or hardware-endorsed remote attestation. The operator VM keeps Secure Boot on.
- **One-shot GRUB selections:** Both `install-kernel` and `enable` arm **one-shot** GRUB boots (`grub-reboot`), keeping the distribution Ubuntu kernel as the saved default. If a new boot fails, inspect Azure boot diagnostics; running `restart --reboot` again after the one-shot entry has been consumed returns the VM to the stock Ubuntu kernel. If `verify` fails, do not claim enforcement, and never reset a target identity or wipe its state to make a check pass.
- **Optional persistent UKI default:** The previously measured historical target VM had the UKI promoted to the saved GRUB default. That is **not** the fresh-lab default. Only after `verify` succeeds, an operator who wants persistent UKI boots across reboots can run `sudo grub-set-default shirudo-uki` **on the target VM**. Keep the stock kernel and serial recovery access enabled, because after promotion an ordinary reboot no longer falls back automatically to the stock kernel.

---

## Phase 3: Build, stage, and run the five upstream controls

After the boot bundle is relayed and the target VM passes `verify`, run these two commands **from your workstation**:

```sh
python3 infra/azure/lab.py build-controls
python3 infra/azure/lab.py stage-controls
```

- **`build-controls`** builds five named signed pairs on the operator VM from the pinned upstream commit: `basic` (the no-op lifecycle fixture), `java-base64`, the `java-sql-inj` **JDBC agent module only**, the `app-sandbox` Beefile (including its generated policy), and the `cve-2026-31431-af-alg-block` socket guard. It reads only the required blobs at the pinned commit using a filtered sparse checkout; no vulnerable demo application, parent Maven reactor, or exploit input is built or run. It regenerates the BPF header from the actual Azure kernel BTF, verifies it matches the installed operator header, and runs upstream `shirudo build` to sign each load payload and its digest-bound unload file (`--java` for the two Java unloads).
- **`stage-controls`** updates the signed Ubuntu package index on the target VM, installs Ubuntu's current OpenJDK 25 headless JDK and JRE (`openjdk-25-jdk-headless` and `openjdk-25-jre-headless`), verifies the operator's signed transport manifest, and installs only the **ten named signed `.upatch` files** into a root-owned `/var/tmp/shields` directory on the target. The operator retains the originals at `~/build/shields`; neither build directories nor private keys are copied. Do not reuse artifact directories from another lab. *(Note: this five-pair packaging recipe was also verified on the Azure operator with disposable signers; those smoke-test outputs were discarded rather than loaded.)*

### Running `demos/controls/run.sh` (and why shell variables are exported explicitly)

Unlike `infra/azure/lab.py` (which reads `.env` directly), the live control runner [`demos/controls/run.sh`](../demos/controls/README.md) uses Azure VM Run Command and **deliberately does not read or source `.env`**. Requiring you to export `AZ_SUBSCRIPTION` and `AZ_RESOURCE_GROUP` explicitly in your shell ensures the test runner only contacts the exact subscription and resource group you name for this session.

From the checkout holding the fresh lab's `.state/owner.json`, export `AZ_SUBSCRIPTION` and `AZ_RESOURCE_GROUP` with the **same values** as your private `.env` (plus any VM-name, admin-user, `OPERATOR_SIZE`, or `TARGET_SIZE` overrides you changed from `.env.example`), create a private state directory **outside the checkout**, enroll the target's attestation key once, and run the controls:

```sh
umask 077
export AZ_SUBSCRIPTION="<your-subscription-uuid>"
export AZ_RESOURCE_GROUP="<your-dedicated-resource-group>"
export SHIRUDO_CONTROL_STATE="$(mktemp -d)"
demos/controls/run.sh enroll
demos/controls/run.sh run --receipt "$SHIRUDO_CONTROL_STATE/receipt.json"
```

The runner checks the selected resource group and VM ownership tags (`shirudoLab`) against `.state/owner.json` and verifies the enrolled digests before loading any shield. For full runner details and the optional `--distro-debs` mode (which tests against Ubuntu's real `php8.5-fpm` and H2 `libh2-java` packages), see [`demos/controls/README.md`](../demos/controls/README.md).

---

## Phase 4: Stop spending (`rollback --delete-owned`)

When you are finished with the lab, delete its billable Azure resources from your workstation:

```sh
python3 infra/azure/lab.py rollback --delete-owned
```

Keep the ignored `.state/owner.json` receipt and matching `.env` file until cleanup completes. `rollback --delete-owned` verifies the subscription, resource group, VM names, `shirudoLab` ownership tag, expected resource IDs, and VM disk/NIC attachment settings before deleting the named VMs, managed disks, NICs, public IPs, VNet, and NSG. It never deletes a subscription or the resource group container itself.

Do not add unrelated workloads or modify attachments inside this dedicated resource group. If provisioning was interrupted or an unexpected/untagged resource is found, `rollback` refuses so you can inspect the group and billing inventory in Azure and remove **only** confirmed lab resources. Remember that a stopped VM still incurs disk and public IP charges until deleted.

---

## The two local compatibility patches

| Change to pinned upstream (`ff5dd643ac0b`) | Why it is here | Tradeoff |
| --- | --- | --- |
| [vTPM NV writer key size (`RSA-2048`)](../patches/shirudo/0001-tpm-size-the-NV-writer-key-for-vTPMs-without-RSA-307.patch) | The tested Azure Hyper-V vTPM rejected the upstream RSA-3072 NV writer key (`TPM_RC_VALUE`) and accepted RSA-2048. | Reduces that per-boot TPM NV writer key's RSA security margin and changes the NV index evidence layout. Build operator/verifier and target from the same patched revision. Does not change the `ML-DSA-87` shield/config signing algorithm or the `ECDSA P-256` attestation key. |
| [Retry boot image teardown on `EBUSY`](../patches/shirudo/0002-init-retry-boot-image-teardown-while-udev-probes-the.patch) | Background `udev` probing of `dm-verity` devices can race temporary boot-mount teardown in a generic Ubuntu 26.04 initrd. | A busy unmount or device-mapper teardown can wait up to roughly one extra second **per operation**. Persistent busy conditions and any other errors still fail initialization; verification is never skipped. |

For the underlying trust model and boot order, see the [pinned upstream boot integration guide](https://github.com/shirudo-dev/shirudo/blob/ff5dd643ac0b3d68310450a2cb9b668416eac036/Documentation/operate/deploy/boot-integration.rst). This lab does not claim binary reproducibility: system packages, build timestamps, and the optional `:latest` base image revision can vary.

---

## Publication and privacy hygiene

In a standalone release clone, install the Git hooks and configure a GitHub `noreply` author address:

```sh
tools/install_hooks.sh
python3 tools/check_leaks.py --staged
python3 tools/check_leaks.py
```

Keep real Azure identifiers in the gitignored `.env` file and add any additional private strings (such as aliases, hostnames, or tenant names) to `PRIVATE_TERMS`. Keep personal social posts and scratch notes strictly inside the gitignored `.scratch/` directory. `python3 tools/check_leaks.py --staged` checks the entire staged Git index, and `python3 tools/check_leaks.py` checks all reachable history. Never bypass a failing hook; automated scanning supplements, rather than replaces, human review of the paths, contents, and commit messages being published.
