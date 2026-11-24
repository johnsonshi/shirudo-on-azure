# Shirudo on Azure

Boot [upstream Shirudo](https://github.com/shirudo-dev/shirudo/tree/ff5dd643ac0b3d68310450a2cb9b668416eac036) on a disposable Azure Linux VM. An **operator** builds the kernel and the upstream packages and keeps the signing keys. A **target** boots the resulting unified kernel image (UKI), runs `shirudo init` in the initrd and uses its Azure vTPM for the measurement register. These are separate machines. The repository contains integration code, not public signing keys, prebuilt shields, or a replacement enforcement engine.

Read the [Azure field notes and architecture diagrams](docs/blog/shirudo-on-azure-field-notes.md) for what was measured on the guest and what the vTPM evidence does **not** prove.

## Start here: no Azure account required

From a checkout of the commit you intend to run:

```sh
python3 infra/azure/lab.py plan
python3 infra/azure/lab.py files operator
python3 infra/azure/lab.py files target
python3 -m unittest discover -s tools/tests
```

These commands need Python 3.9+, Git and OpenSSH (including `ssh-keygen -Y` for the tests). They do not log in, provision infrastructure, or contact a guest. The kernel/UKI recipe was booted on Azure; the workstation orchestration and its failure paths are tested offline. A healthy runtime or a benign policy check is **not** evidence that a particular CVE was prevented.

## Build a new lab

Use a workstation with Azure CLI, access to create resources in the intended subscription, and a route to TCP 22 **from one public IPv4 `/32`**. If SSH exits through rotating addresses, do not open the NSG to a service tag or all Azure hosts. Use a workstation with a stable egress address. The VMs need outbound access for Ubuntu packages and pinned source downloads.

1. Log in with `az login`. In this checkout, run `umask 077` and `cp .env.example .env`. Set `AZ_SUBSCRIPTION` to the explicit subscription **UUID**, `AZ_RESOURCE_GROUP` to a **new, dedicated** group name, and fill in location and workstation CIDR. `.env` is data, not a shell script. Supply an existing, dedicated Ed25519 key pair at `SSH_KEY` and `SSH_KEY.pub`. To make one, run `ssh-keygen -t ed25519 -f ~/.ssh/shirudo_on_azure_ed25519` and use `ssh-add` locally for a passphrase-protected key. Agent forwarding is disabled.
2. Review cost and quota before creation. The example requests a D32ds v5 / 256-GiB build VM, a D4ds v5 / 64-GiB target, two Premium managed disks and two Standard public IPv4 addresses. A kernel build takes time; there is **no automatic shutdown or budget cap**. `latest` selects an Ubuntu 26.04 image revision at creation, not a reproducible OS snapshot. An exact Canonical image version may be set in `.env`.
3. Run each phase below **separately**. Stop at the first failure. Do not point the initializer at an existing lab: it refuses to adopt existing groups, and guests must be fresh.

```sh
# Workstation. This is the first command that creates billable resources.
python3 infra/azure/lab.py create --spend
python3 infra/azure/lab.py stage operator
python3 infra/azure/lab.py stage target
python3 infra/azure/lab.py build
python3 infra/azure/lab.py relay
```

`stage` sends only the listed regular blobs from the **committed** Git tree, once, into a new commit-specific directory. It never syncs a checkout. `build` fetches the revision in [`patches/shirudo/BASE`](patches/shirudo/BASE), runs its bpf-next kernel builder with [Hyper-V guest options](kernel/azure.conf), then runs upstream `make -C packaging bindeb-pkg` with that kernel's BTF and both local patches. It installs the operator package and uses the upstream image generators for the signed config image, runtime image, and UKI bootstrap. Build logs and keys stay on the operator.

`relay` streams individually named boot artifacts through the workstation, not a tar of a build directory. It pins a separate transport public key from the authenticated operator on the target and verifies its signed SHA-256 manifest. This check includes the kernel and Debian packages; it does **not** make the custom kernel UEFI-signed or replace Shirudo's own image checks. The SSH client accepts new host keys on first contact and rejects changed keys. For stronger first-contact assurance, pin independently verified guest host keys in `.state/known_hosts` before staging.

### Boot and check

```sh
python3 infra/azure/lab.py install-kernel
python3 infra/azure/lab.py restart --reboot
# Wait for SSH to return. Check that the kernel release contains "shirudo-azure".
python3 infra/azure/lab.py status

python3 infra/azure/lab.py enable
python3 infra/azure/lab.py restart --reboot
# Wait for SSH, then check kernel, runtime mount, service and upstream status.
python3 infra/azure/lab.py verify
```

`verify` reads upstream `status --json`: it requires a target verdict of `ok` and all seven pinned target conditions at `OK`. A working SSH connection, an active systemd unit, or `shirudo status` exiting zero is not enough.

The first boot exposes the two unsealed keyrings for enrollment. The second chainloads the UKI, which carries the pinned runtime root hash and the public BPF certificate. It also includes systemd's early TPM setup in the initrd. The **target's Secure Boot is off** because its custom kernel/UKI is not signed by a firmware-trusted key; its **vTPM stays on**. Neither a vTPM nor this check establishes a production Secure Boot chain or remote attestation. The operator keeps Secure Boot on.

Both GRUB selections in the fresh initializer are **one-shot**. The saved default stays the distribution kernel. If the new boot fails, inspect boot diagnostics; `restart --reboot` on this receipted target consumes no new boot selection and returns to the saved default after the one-shot has been consumed. If `verify` fails, do not claim enforcement. Do not reset a target identity or wipe its state to make a check pass.

The previously measured guest had the UKI explicitly selected as the saved default. That is **not** the fresh-lab default. Only after `verify` succeeds, an operator who wants that behavior can run `sudo grub-set-default shirudo-uki` **on the target**. Keep the stock kernel and serial recovery access: after promotion, an ordinary restart no longer automatically falls back to the stock entry.

### Run the upstream controls on a fresh lab

After the boot bundle is relayed and the target passes `verify`, **from the workstation**:

```sh
python3 infra/azure/lab.py build-controls
python3 infra/azure/lab.py stage-controls
```

The operator builds five named pairs: upstream `basic`, the Base64 JDK guard, the **JDBC agent module only**, the `app-sandbox` Beefile (including its generated policy), and the broad `AF_ALG` socket guard. It reads only the required blobs at the pinned commit. The runtime itself uses a filtered sparse checkout. No vulnerable application, parent Maven reactor, reproducer, or vulnerable input is built or run. The BPF header is regenerated from the actual Azure kernel BTF and compared with the installed operator header. Upstream `shirudo build` signs each payload and its digest-bound unload using the existing BPF key; the two Java unloads use `--java`.

`stage-controls` updates the signed Ubuntu package index, installs the distribution's current OpenJDK 25 JDK and JRE, checks the operator's signed transport manifest, and installs only ten named signed files into a new root-owned `/var/tmp/shields`. The operator retains the originals at `~/build/shields`; neither build directories nor private keys are copied. Do not reuse artifact directories from another lab.

The [control runner](demos/controls/) uses Azure VM Run Command. Export `AZ_SUBSCRIPTION` and `AZ_RESOURCE_GROUP` with the **same values** as your private `.env` (do not execute `.env` as shell). From the workstation, create a private state directory **outside the checkout**, enroll once, and run the controls:

```sh
umask 077
export SHIRUDO_CONTROL_STATE="$(mktemp -d)"
demos/controls/run.sh enroll
demos/controls/run.sh run --receipt "$SHIRUDO_CONTROL_STATE/receipt.json"
```

Use the runner's documented VM-name overrides if you changed either name in `.env`. The runner checks enrolled digests before load. The recorded guest measurements used previously staged artifacts; they are not a live test of this fresh-clone build/transfer path.

### Stop spending

```sh
python3 infra/azure/lab.py rollback --delete-owned
```

Keep the ignored `.state/owner.json` and matching `.env` until cleanup. Rollback checks the subscription, group, VM names, owner tag, expected resource IDs and VM attachment settings before deleting named VMs, disks, NICs, public IPs, VNet and NSG. It never deletes a subscription or a resource group. Do not add other workloads or modify attachments in this dedicated group. If provisioning was interrupted or an unexpected/untagged resource is found, rollback may refuse: inspect that group and its billing inventory in Azure, and remove **only** confirmed lab resources. A stopped guest can still incur disk and IP charges.

## The two compatibility patches

| Change to pinned upstream | Why it is here | Tradeoff |
| --- | --- | --- |
| [vTPM NV writer key size](patches/shirudo/0001-tpm-size-the-NV-writer-key-for-vTPMs-without-RSA-307.patch) | The tested Azure vTPM rejected the upstream RSA-3072 writer and accepted RSA-2048. | This reduces the writer key's security margin and changes its evidence layout. Build operator/verifier and target from the same patched revision. This is not a change to the shield-signing algorithm. |
| [Retry boot image teardown on `EBUSY`](patches/shirudo/0002-init-retry-boot-image-teardown-while-udev-probes-the.patch) | udev probing of dm-verity devices can race teardown in a generic Azure initrd. | A busy unmount/mapping can take about one extra second **per operation**. Persistent busy conditions and other errors still fail initialization; verification is not skipped. |

For the underlying trust model and boot order, see the [pinned upstream boot integration guide](https://github.com/shirudo-dev/shirudo/blob/ff5dd643ac0b3d68310450a2cb9b668416eac036/Documentation/operate/deploy/boot-integration.rst). This lab does not claim binary reproducibility: system packages, build timestamps and the optional `latest` image version can vary.

## Publication hygiene

In a standalone release clone, run `tools/install_hooks.sh` and configure a GitHub noreply author address. Keep real identifiers in the ignored `.env`; add additional private strings to `PRIVATE_TERMS`. `python3 tools/check_leaks.py --staged` checks the whole index, and `python3 tools/check_leaks.py` checks reachable history. Do not bypass a failing hook. The scanner supplements, not replaces, human review of the actual paths, contents, and commit messages being published.
