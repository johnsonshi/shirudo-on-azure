"""A single signed manifest for the kernel, packages and upstream boot images.

This is SSH transport integrity, not a replacement for Shirudo image signing.
The target accepts the public transport key separately over authenticated SSH.
"""
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile


FILES = ("kernel.deb", "target.deb", "initial.img", "initial.verity", "initial.roothash",
         "initial.p7s", "runtime.img", "runtime.verity", "runtime.roothash",
         "bpf-cert.der", "uki-bootstrap.conf", "runtime-service.conf")
META = ("SHA256SUMS", "SHA256SUMS.sig")
KEY = Path.home() / "shirudo-keys" / "transport"
OUT = Path.home() / "build" / "target-bundle"
SIGNERS = Path.home() / ".shirudo-transport-signers"
NAMESPACE = "shirudo-on-azure/boot"


def limit(name):
    if name not in FILES + META:
        raise ValueError("not a named boot artifact")
    return 512 * 1024**2 if name.endswith((".deb", ".img", ".verity")) else 64 * 1024


def open_artifact(root, name):
    maximum = limit(name)
    if root.resolve() != root:
        raise ValueError("refusing linked bundle directory")
    fd = os.open(root / name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    f = os.fdopen(fd, "rb")
    s = os.fstat(fd)
    if not (stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and 0 < s.st_size <= maximum):
        f.close()
        raise ValueError("expected a bounded, single-link regular artifact")
    return f


def manifest(root):
    lines = []
    for name in FILES:
        h = hashlib.sha256()
        with open_artifact(root, name) as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        lines.append(f"{h.hexdigest()}  {name}\n")
    return "".join(lines).encode("ascii")


def signer():
    pub = Path(str(KEY) + ".pub").read_text().split()
    if len(pub) < 2 or pub[0] != "ssh-ed25519" or not re.fullmatch(r"[A-Za-z0-9+/=]{64,128}", pub[1]):
        raise ValueError("invalid public transport key")
    return f"operator {pub[0]} {pub[1]}\n".encode("ascii")


def signed_manifest(root, allowed):
    with open_artifact(root, META[0]) as f:
        sums = f.read()
    with open_artifact(root, META[1]):
        subprocess.run(["ssh-keygen", "-Y", "verify", "-n", NAMESPACE, "-I", "operator",
                        "-f", str(allowed), "-s", str(root / META[1])], input=sums, check=True,
                       stdout=subprocess.DEVNULL)
    rows = sums.splitlines(keepends=True)
    if len(rows) != len(FILES) or not all(re.fullmatch(rb"[a-f0-9]{64}  "+re.escape(name.encode())+rb"\n", row)
                                          for row, name in zip(rows, FILES)):
        raise ValueError("unexpected names or format in signed manifest")
    return sums


def verify(root, allowed):
    if signed_manifest(root, allowed) != manifest(root):
        raise ValueError("boot bundle differs from signed manifest")


def send(name):
    maximum = limit(name)
    with tempfile.NamedTemporaryFile() as authorized:
        authorized.write(signer())
        authorized.flush()
        sums = signed_manifest(OUT, authorized.name)
    if name in META:
        with open_artifact(OUT, name) as f:
            sys.stdout.buffer.write(f.read())
        return
    expected = sums.splitlines()[FILES.index(name)][:64].decode("ascii")
    with open_artifact(OUT, name) as source, tempfile.TemporaryFile() as verified:
        digest = hashlib.sha256()
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            if verified.tell() + len(chunk) > maximum:
                raise ValueError("artifact grew during verification")
            digest.update(chunk)
            verified.write(chunk)
        if digest.hexdigest() != expected:
            raise ValueError("refusing to send unsigned or modified content")
        verified.seek(0)
        shutil.copyfileobj(verified, sys.stdout.buffer)


def main(args):
    os.umask(0o077)
    if args == ["seal"]:
        if not KEY.exists():
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "lab-transport",
                            "-f", str(KEY)], check=True)
        with (OUT / META[0]).open("xb") as f:
            f.write(manifest(OUT))
        subprocess.run(["ssh-keygen", "-Y", "sign", "-n", NAMESPACE, "-f", str(KEY),
                        str(OUT / META[0])], check=True)
    elif args == ["public-signer"]:
        sys.stdout.buffer.write(signer())
    elif args == ["begin-receive"]:
        key = sys.stdin.buffer.read(257)
        if not re.fullmatch(rb"operator ssh-ed25519 [A-Za-z0-9+/=]{64,128}\n", key):
            raise ValueError("not a public transport signer")
        if SIGNERS.exists():
            if SIGNERS.read_bytes() != key:
                raise ValueError("operator signer changed")
        else:
            with SIGNERS.open("xb") as f:
                f.write(key)
        if OUT.resolve() != OUT:
            raise ValueError("refusing linked bundle directory")
        OUT.mkdir(mode=0o700, parents=True, exist_ok=False)
    elif len(args) == 2 and args[0] == "send":
        send(args[1])
    elif len(args) == 2 and args[0] == "receive":
        maximum = limit(args[1])
        if OUT.resolve() != OUT:
            raise ValueError("refusing linked bundle directory")
        with (OUT / args[1]).open("xb") as f:
            size = 0
            for chunk in iter(lambda: sys.stdin.buffer.read(1024 * 1024), b""):
                size += len(chunk)
                if size > maximum:
                    raise ValueError("artifact is larger than its transport limit")
                f.write(chunk)
            if not size:
                raise ValueError("empty artifact")
    elif args == ["verify"]:
        verify(OUT, SIGNERS)
    else:
        raise ValueError("unknown bundle operation")


if __name__ == "__main__":
    main(sys.argv[1:])
