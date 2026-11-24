#!/usr/bin/env python3
"""Workstation entry point. Running without arguments is an offline plan."""
import argparse
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile

sys.dont_write_bytecode = True
from resources import Lab, check

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "infra"))
from bundle import CONTROL_FILES, FILES, META

TARGET_CONDITIONS = {"LsmAttached", "KeyringSealed", "ChainIntact", "UpatchesMeasured",
                     "TpmMeasured", "ConfigActive", "XdpCovered"}
PROJECT_FILES = {
    "operator": ("infra/operator/bootstrap.sh", "infra/operator/build-shirudo.sh",
                 "infra/operator/build_controls.py", "infra/operator/runtime.paths",
                 "infra/operator/make-target-bundle.sh", "kernel/azure.conf", "kernel/build-kernel.sh",
                 "patches/shirudo/BASE",
                 "patches/shirudo/0001-tpm-size-the-NV-writer-key-for-vTPMs-without-RSA-307.patch",
                 "patches/shirudo/0002-init-retry-boot-image-teardown-while-udev-probes-the.patch",
                 "infra/bundle.py"),
    "target": ("infra/target/install-kernel.sh", "infra/target/enable-shirudo.sh",
               "infra/target/dracut/91shirudo-tpm2-setup/module-setup.sh", "infra/bundle.py"),
}
PLAN = """Offline plan (no Azure, SSH or file changes):
  create --spend       Fresh dedicated group; operator + target, one public SSH /32.
  stage operator       Send only allowlisted blobs from this Git commit.
  stage target         No working tree, .env, keys, or drafts are sent.
  build                On operator: pinned source, Azure kernel/BTF, packages, signed boot bundle.
  relay                Send named artifacts, pin operator transport signer, verify manifest.
  install-kernel       Target arms one boot of custom kernel. Does not reboot.
  restart --reboot     Restart target; wait for SSH and check status.
  enable               Build/arm Shirudo UKI. Does not reboot.
  restart --reboot     Restart target; wait, then run status and verify.
  build-controls       Optional: build the five upstream signed pairs on the operator.
  stage-controls       Install current Ubuntu JDK/JRE; verify and stage only those pairs.
  rollback --delete-owned  Remove only the dedicated lab's named resources (not its group).
See README.md for prerequisites, trust and cost boundaries."""


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args])


def verify_target(raw):
    report = json.loads(raw)
    check(isinstance(report, dict) and type(report.get("schema")) is int and report["schema"] == 1
          and report.get("is_target") is True and report.get("status") == "ok",
          "upstream did not report a healthy schema-1 target")
    rows = report.get("conditions")
    check(isinstance(rows, list) and len(rows) == len(TARGET_CONDITIONS)
          and all(isinstance(r, dict) and isinstance(r.get("type"), str) and r.get("status") == "OK" for r in rows)
          and {r["type"] for r in rows} == TARGET_CONDITIONS,
          "missing, unexpected, or unhealthy upstream target condition")


def payload(root, sha, role):
    """Read regular Git blobs, never local files (including tracked-but-modified ones)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as archive:
        for name in PROJECT_FILES[role]:
            info = git(root, "ls-tree", "-l", sha, "--", name).decode().strip().split()
            check(len(info) == 5 and info[0] in ("100644", "100755") and info[1] == "blob" and
                  info[4] == name and int(info[3]) <= 1024**2, "missing/unsafe project input: "+name)
            data = git(root, "cat-file", "blob", info[2])
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            entry.mode = 0o755 if info[0] == "100755" else 0o644
            archive.addfile(entry, io.BytesIO(data))
    return buf.getvalue()


class Guests:
    def __init__(self, lab):
        self.lab = lab
        self.sha = git(lab.root, "rev-parse", "HEAD").decode().strip()
        check(re.fullmatch("[a-f0-9]{40}", self.sha), "invalid project commit")
        self.dir = "shirudo-on-azure-" + self.sha
        self.hosts = {}

    def command(self, role, command):
        if role not in self.hosts:
            self.hosts[role] = self.lab.address(role)
        return ["ssh", "-i", str(self.lab.key), "-o", "IdentitiesOnly=yes", "-o", "ForwardAgent=no",
                "-o", "ClearAllForwardings=yes", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20",
                "-o", "ServerAliveInterval=30", "-o", "StrictHostKeyChecking=accept-new",
                "-o", "UserKnownHostsFile="+str(self.lab.state / "known_hosts"),
                self.lab.user+"@"+self.hosts[role], command]

    def stage(self, role):
        data = payload(self.lab.root, self.sha, role)
        subprocess.run(self.command(role, f"umask 077 && mkdir {self.dir} && tar -C {self.dir} -xf - "
                                    f"&& touch {self.dir}/.complete"), input=data, check=True)

    def run(self, role, cmd, **kwargs):
        return subprocess.run(self.command(role, f"cd {self.dir} && test -f .complete && "+cmd),
                              check=True, **kwargs)

    def relay(self, controls=False):
        tool = "python3 infra/bundle.py" + (" controls" if controls else "")
        public = self.run("operator", tool+" public-signer", stdout=subprocess.PIPE).stdout
        self.run("target", tool+" begin-receive", input=public)
        for name in (CONTROL_FILES if controls else FILES) + META:
            cmd = self.command("operator", f"cd {self.dir} && {tool} send {name}")
            with subprocess.Popen(cmd, stdout=subprocess.PIPE) as sender:
                try:
                    self.run("target", f"{tool} receive {name}", stdin=sender.stdout)
                finally:
                    sender.stdout.close()
                check(sender.wait() == 0, "operator transfer failed")
        self.run("target", tool+" verify")
        if controls:
            self.run("target", tool+" install")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    cmds = parser.add_subparsers(dest="action")
    for cmd in ("plan", "build", "relay", "install-kernel", "enable", "status", "verify",
                "build-controls", "stage-controls"):
        cmds.add_parser(cmd)
    for cmd, flag in (("create", "--spend"), ("restart", "--reboot"), ("rollback", "--delete-owned")):
        cmds.add_parser(cmd).add_argument(flag, required=True, action="store_true")
    for cmd in ("stage", "files"):
        cmds.add_parser(cmd).add_argument("role", choices=tuple(PROJECT_FILES))
    args = parser.parse_args(argv)
    if args.action in (None, "plan"):
        print(PLAN)
        return
    if args.action == "files":
        print(*PROJECT_FILES[args.role], sep="\n")
        return
    os.umask(0o077)
    lab = Lab(ROOT)
    if args.action == "create":
        lab.create()
    elif args.action == "rollback":
        lab.rollback()
    elif args.action == "restart":
        lab.owned_vm("target", lab.owned())
        lab.az("vm", "restart", "-g", lab.group, "-n", lab.vms["target"])
    else:
        guests = Guests(lab)
        if args.action == "stage":
            guests.stage(args.role)
        elif args.action == "build":
            guests.run("operator", "infra/operator/bootstrap.sh && kernel/build-kernel.sh kernel/azure.conf && "
                       "infra/operator/build-shirudo.sh && infra/operator/make-target-bundle.sh")
        elif args.action == "relay":
            guests.relay()
        elif args.action == "build-controls":
            guests.run("operator", "python3 infra/operator/build_controls.py")
        elif args.action == "stage-controls":
            guests.run("target", "sudo apt-get -o APT::Update::Error-Mode=any update -q && "
                       "sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "
                       "openjdk-25-jdk-headless openjdk-25-jre-headless")
            guests.relay(controls=True)
        elif args.action in ("install-kernel", "enable"):
            script = "install-kernel" if args.action == "install-kernel" else "enable-shirudo"
            guests.run("target", f'python3 infra/bundle.py verify && sudo infra/target/{script}.sh "$HOME/build/target-bundle"')
        elif args.action == "status":
            guests.run("target", "uname -r && sudo grub-editenv list")
        elif args.action == "verify":
            report = guests.run("target", 'test "$(uname -r)" = "$(cat /etc/shirudo-kernel-release)" && '
                                "mountpoint -q /run/shirudo/runtime && systemctl is-active --quiet shirudo.service && "
                                "sudo /run/shirudo/runtime/usr/bin/shirudo status --json", stdout=subprocess.PIPE)
            verify_target(report.stdout)
            print("Shirudo target: ok; all seven pinned runtime conditions are OK.")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        sys.exit(f"lab: {Path(exc.cmd[0]).name} failed (exit {exc.returncode}); stopped")
    except (ValueError, KeyError, OSError) as exc:
        sys.exit(f"lab: {exc}")
