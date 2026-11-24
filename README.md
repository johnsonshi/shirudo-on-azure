# Shirudo on Azure

Shirudo on Azure is a two-VM reference deployment of [Shirudo](https://github.com/shirudo-dev/shirudo), the open-source Linux runtime from OpenAI and Cisco. Shirudo lets an operator put a temporary security rule in place while a software patch is being tested. This repository provides the Azure kernel configuration, build and deployment scripts, and five demos using the upstream rules unchanged.

To try the file rule, start with the recorded demo below; it needs no Azure account. To run the demos on your own VMs, use the [Azure setup guide](docs/azure-lab-runbook.md).

<a name="replay-this-result-on-your-laptop-right-now-offline-0-no-azure-account-required"></a>

## Quick start: replay a recorded demo

From the repository root, run this command with a shell and Python 3.11 or later:

```sh
demos/controls/app-sandbox.sh --receipt docs/results/azure-controls-real-runtimes.json
```

The command reads the saved result of an Azure run. It does not create a VM or start a web server. The relevant lines are:

```text
Before: Ubuntu PHP-FPM worker (private Unix socket): both canaries written
Active: .php denied (EACCES); .txt written
Restored: both canaries written after unload
```

The two test files contained the same harmless text. With the rule active, a PHP worker could save `canary.txt` but got “Permission denied” when it tried to create `canary.php`. After the rule was removed, both writes succeeded again. That distinction is useful for a web service that needs to save data but should not create new files that the web server could run as code. The rule contains that behavior; it does not fix PHP itself.

## Included demos

| Demo | Result on Azure |
| --- | --- |
| [PHP file creation](demos/controls/app-sandbox.sh) | A worker started under the rule could create the text file but not the PHP file. The test used a private directory outside the web root. |
| [Java database queries](demos/controls/java-sql-inj.sh) | A normal query returned `7` throughout. A second, harmless query matched the guard's rule and was rejected before reaching the H2 database. It ran again after the guard was removed and the Java process restarted. |
| [Linux crypto sockets](demos/controls/af-alg.sh) | The rule denied creation of a kernel crypto socket (`AF_ALG`) but allowed a local Unix socket. Both worked again after removal. The VM's separate built-in restriction was off during this test; the [post-run record](docs/results/azure-af-alg-restoration.json) shows it was restored to the stricter default. |
| [Java live attachment](demos/controls/java-base64.sh) | A running Java process decoded valid Base64 before and after the signed agent attached. Its process ID and start time stayed the same. This checks continuity, not whether an exploit was stopped. |
| [Signed rule lifecycle](demos/controls/basic.sh) | A signed rule that performs no action was loaded, recorded, then removed with a signed instruction for that exact rule. |

The [demo guide](demos/controls/README.md) lists all five replay commands and explains how to run the suite live. The [real PHP-FPM and H2 results](docs/results/azure-controls-real-runtimes.json) are separate from the [smaller fixture run](docs/results/azure-controls.json).

## Deploy and run on Azure

The lab uses two CPU-only Ubuntu VMs. The **operator** builds the software, holds the signing keys, and verifies changes to the loaded rules. The **target** boots the custom Linux kernel and runs the workloads. Its virtual Trusted Platform Module (vTPM) provides signed evidence of rule changes. The applications' return values show whether a particular write, query, or socket call was refused.

- **New lab:** Follow the [two-VM runbook](docs/azure-lab-runbook.md) for prerequisites, provisioning, boot verification, and cleanup. Creating the VMs incurs Azure charges.
- **Prepared lab:** Follow the [live runner guide](demos/controls/README.md) to enroll the target and collect a new result. Reading the JSON files in this repository does not rerun these tests.

This is an experimental VM configuration, not a production image or a managed AKS installation. It requires a [Hyper-V kernel configuration](kernel/azure.conf) and [two runtime compatibility patches](patches/shirudo/). The target ran with vTPM enabled and Secure Boot **off**: it could report what booted, but firmware did not prevent a modified boot image from starting. The [field notes](docs/blog/shirudo-on-azure-field-notes.md) cover those tradeoffs, the Azure port, and both measured runs.
