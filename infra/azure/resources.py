"""Ownership boundary for a disposable two-VM lab. No default subscription."""
import ipaddress
import json
import os
import re
import subprocess
import uuid
from pathlib import Path


def check(condition, message):
    if not condition:
        raise ValueError(message)


def settings(file):
    values = {}
    for line in file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, val = line.partition("=")
        check(sep and key not in values, "malformed or duplicate .env setting")
        values[key] = val.strip().strip('"').strip("'")
    return values


class Lab:
    def __init__(self, root):
        self.root = root
        self.cfg = c = settings(root / ".env")
        self.sub = str(uuid.UUID(c["AZ_SUBSCRIPTION"]))
        self.group, self.location = c["AZ_RESOURCE_GROUP"], c["AZ_LOCATION"]
        self.vms = {"operator": c["OPERATOR_VM"], "target": c["TARGET_VM"]}
        self.user = c["ADMIN_USER"]
        self.key = Path(c["SSH_KEY"]).expanduser()
        check(self.key.is_absolute(), "SSH_KEY must be an absolute or ~/ path")
        check(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", self.group), "invalid resource group")
        check(re.fullmatch(r"[a-z][a-z0-9]+", self.location), "invalid Azure location")
        check(re.fullmatch(r"[a-z][a-z0-9_-]{0,30}", self.user), "invalid admin username")
        check(len(set(self.vms.values())) == 2 and all(
            re.fullmatch(r"[a-z][a-z0-9-]{0,38}[a-z0-9]", n) for n in self.vms.values()),
            "VM names must be distinct lowercase DNS labels")
        source = c["ALLOWED_SSH_CIDR"]
        block = ipaddress.IPv4Network(source, strict=True)
        check(source.endswith("/32") and block.network_address.is_global and
              not block.network_address.is_multicast and not c.get("ALLOWED_SSH_SOURCES"),
              "SSH requires exactly one public workstation IPv4 /32; no ranges or service tags")
        self.scope = {"subscription": self.sub, "group": self.group, "vms": self.vms,
                      "location": self.location}
        self.state = root / ".state"
        self.receipt = self.state / "owner.json"

    def az(self, *args, read=False):
        p = subprocess.run(["az", *args, "--subscription", self.sub, "--only-show-errors",
                            "-o", "json" if read else "none"], check=True, stdout=subprocess.PIPE)
        return json.loads(p.stdout) if read else None

    def owned(self):
        check(self.receipt.is_file() and not self.receipt.is_symlink(), "no private ownership receipt")
        receipt = json.loads(self.receipt.read_text())
        check(receipt["scope"] == self.scope, ".env does not match receipt; refusing to change scope")
        token = str(uuid.UUID(receipt["token"]))
        tag = self.az("group", "show", "-n", self.group, "--query", "tags.shirudoLab", read=True)
        check(tag == token, "group ownership tag does not match receipt")
        return token

    def resource_id(self, kind, name):
        return f"/subscriptions/{self.sub}/resourceGroups/{self.group}/providers/{kind}/{name}"

    def create(self):
        c = self.cfg
        pub = Path(str(self.key) + ".pub")
        check(self.key.is_file() and pub.is_file() and not pub.is_symlink(), "generate a dedicated SSH key pair first")
        check(re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\n]*)?", pub.read_text().strip()),
              "expected one Ed25519 public key")
        for key in ("OPERATOR_SIZE", "TARGET_SIZE"):
            check(re.fullmatch(r"Standard_[A-Za-z0-9_]+", c[key]), "invalid VM size")
        check(re.fullmatch(r"Canonical:ubuntu-26_04-lts:server:(latest|[0-9.]+)", c["UBUNTU_IMAGE"]),
              "expected the Canonical Ubuntu 26.04 server image")
        check(self.az("group", "exists", "-n", self.group, read=True) is False,
              "group already exists; never adopt or retag an existing group")
        self.state.mkdir(mode=0o700, exist_ok=True)
        token = str(uuid.uuid4())
        # Exclusive creation prevents two local runs from racing or overwriting a recovery receipt.
        with self.receipt.open("x") as f:
            os.chmod(self.receipt, 0o600)
            json.dump({"scope": self.scope, "token": token}, f)
        tags = ["--tags", f"shirudoLab={token}"]
        rg = ["-g", self.group]
        self.az("group", "create", "-n", self.group, "-l", self.location, *tags)
        self.owned()
        check(not self.az("resource", "list", *rg, read=True), "new group is not empty")
        self.az("network", "nsg", "create", *rg, "-n", "shirudo-nsg", *tags)
        for name, priority, access, source in [
            ("workstation-ssh", "1000", "Allow", c["ALLOWED_SSH_CIDR"]),
            ("deny-other-ssh", "1010", "Deny", "*"),
        ]:
            self.az("network", "nsg", "rule", "create", *rg, "--nsg-name", "shirudo-nsg", "-n", name,
                    "--direction", "Inbound", "--priority", priority, "--access", access, "--protocol", "Tcp",
                    "--source-address-prefixes", source, "--destination-port-ranges", "22")
        self.az("network", "vnet", "create", *rg, "-n", "shirudo-vnet", "--address-prefixes", "10.42.0.0/16",
                "--subnet-name", "vms", "--subnet-prefixes", "10.42.1.0/24", "--network-security-group",
                "shirudo-nsg", *tags)
        for role, vm in self.vms.items():
            self.az("network", "public-ip", "create", *rg, "-n", vm+"-ip", "--sku", "Standard",
                    "--allocation-method", "Static", *tags)
            self.az("network", "nic", "create", *rg, "-n", vm+"-nic", "--vnet-name", "shirudo-vnet",
                    "--subnet", "vms", "--public-ip-address", vm+"-ip", "--accelerated-networking", "false", *tags)
            self.az("vm", "create", *rg, "-n", vm, "--image", c["UBUNTU_IMAGE"], "--size", c[role.upper()+"_SIZE"],
                    "--admin-username", self.user, "--authentication-type", "ssh", "--ssh-key-values", str(pub),
                    "--nics", vm+"-nic", "--nic-delete-option", "Detach", "--os-disk-name", vm+"-os",
                    "--os-disk-delete-option", "Detach", "--os-disk-size-gb", "256" if role=="operator" else "64",
                    "--storage-sku", "Premium_LRS", "--security-type", "TrustedLaunch", "--enable-vtpm", "true",
                    "--enable-secure-boot", "true" if role=="operator" else "false", *tags)
            self.az("tag", "update", "--resource-id", self.resource_id("Microsoft.Compute/disks", vm+"-os"),
                    "--operation", "Merge", *tags)
            self.az("vm", "boot-diagnostics", "enable", *rg, "-n", vm)

    def inventory(self):
        ordered = [self.resource_id(kind, vm + suffix) for kind, suffix in (
            ("Microsoft.Compute/virtualMachines", ""), ("Microsoft.Compute/disks", "-os"),
            ("Microsoft.Network/networkInterfaces", "-nic"), ("Microsoft.Network/publicIPAddresses", "-ip"))
            for vm in self.vms.values()]
        return ordered + [self.resource_id("Microsoft.Network/virtualNetworks", "shirudo-vnet"),
                          self.resource_id("Microsoft.Network/networkSecurityGroups", "shirudo-nsg")]

    def owned_vm(self, role, token):
        vm = self.vms[role]
        info = self.az("vm", "show", "-g", self.group, "-n", vm, read=True)
        check(info["id"].lower() == self.resource_id("Microsoft.Compute/virtualMachines", vm).lower() and
              (info.get("tags") or {}).get("shirudoLab") == token, "not an owned VM")
        return info

    def address(self, role):
        vm = self.vms[role]
        token = self.owned()
        info = self.owned_vm(role, token)
        nic_id = self.resource_id("Microsoft.Network/networkInterfaces", vm+"-nic")
        ip_id = self.resource_id("Microsoft.Network/publicIPAddresses", vm+"-ip")
        check([n["id"].lower() for n in info["networkProfile"]["networkInterfaces"]] == [nic_id.lower()],
              "unexpected VM NIC")
        nic = self.az("network", "nic", "show", "--ids", nic_id, read=True)
        check([i["publicIPAddress"]["id"].lower() for i in nic["ipConfigurations"]] == [ip_id.lower()],
              "unexpected public IP binding")
        public = self.az("network", "public-ip", "show", "--ids", ip_id, read=True)
        check((public.get("tags") or {}).get("shirudoLab") == token, "not an owned public IP")
        return str(ipaddress.IPv4Address(public["ipAddress"]))

    def rollback(self):
        token = self.owned()
        ids = self.inventory()
        expected = {i.lower() for i in ids}
        actual = self.az("resource", "list", "-g", self.group, read=True)
        check(all(r["id"].lower() in expected and (r.get("tags") or {}).get("shirudoLab") == token
                  for r in actual), "unexpected or untagged resource; stop and inspect partial deployment")
        existing = {r["id"].lower() for r in actual}
        for role, vm in self.vms.items():
            if self.resource_id("Microsoft.Compute/virtualMachines", vm).lower() in existing:
                info = self.owned_vm(role, token)
                check(not info["storageProfile"]["dataDisks"] and
                      info["storageProfile"]["osDisk"]["deleteOption"] == "Detach" and
                      all(n.get("deleteOption", "Detach") in ("Detach", None)
                          for n in info["networkProfile"]["networkInterfaces"]),
                      "VM attachments or deletion options changed; inspect manually")
        for rid in ids:
            if rid.lower() in existing:
                self.az("resource", "delete", "--ids", rid)
        check(not self.az("resource", "list", "-g", self.group, read=True), "group is not empty")
        print("Removed the named lab resources. The empty group and private ownership receipt remain.")
