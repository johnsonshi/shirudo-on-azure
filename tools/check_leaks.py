"""Check the index (--staged), one commit and its ancestors (--commit SHA),
or all reachable history (the default pre-push check). Diagnostics are redacted.
"""
import argparse
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

REPO = Path(__file__).resolve().parents[1]
DENY_DIRS = {".git", ".scratch", ".state", ".ssh", ".gnupg", ".keys", "keys", "operator-keys",
             "shirudo-keys", "build", "artifacts", "out", "__pycache__"}
DENY_FILES = {"id_ed25519", "id_rsa", "signing_key", "credentials.json", "kubeconfig", "known_hosts"}
DENY_SUFFIXES = (".key", ".der", ".pem", ".pub", ".p12", ".pfx", ".kubeconfig", ".log", ".deb", ".upatch",
                 ".bee", ".efi", ".img", ".jar", ".class", ".p7s", ".pyc", ".zip", ".tar", ".gz", ".zst")
SECRET = re.compile(rb"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{30,}")
NOREPLY = re.compile(rb"^[^<>\s@]+@users\.noreply\.github\.com$")


def terms():
    found = set()
    for line in (REPO / ".env").read_text().splitlines():
        key, _, value = line.strip().partition("=")
        if key not in {"AZ_SUBSCRIPTION", "AZ_RESOURCE_GROUP", "ALLOWED_SSH_CIDR", "PRIVATE_TERMS"}:
            continue
        for part in value.strip().strip('"').strip("'").split(","):
            part = part.strip().lower()
            if part.endswith("/32"):
                part = part[:-3]
            if len(part) >= 4 and not part.startswith("<"):
                found.add(part.encode())
    for file in (REPO / ".state").glob("ip-*"):
        found.add(file.read_bytes().strip().lower())
    return found - {b""}


def git(*args):
    return subprocess.check_output(["git", "-C", str(REPO), *args])


def denied(name):
    path = PurePosixPath(name.lower())
    return (path.parts[:1] == ("shields",) or
            (path.parts[:1] == ("demos",) and path.parts[:2] != ("demos", "controls")) or
            bool(DENY_DIRS.intersection(path.parts)) or path.name in DENY_FILES or
            any(p.startswith(".env") for p in path.parts) and name != ".env.example" or
            path.name.endswith(DENY_SUFFIXES))


def scan(needles, staged=False, commit=None):
    problems, blobs, trees = set(), set(), set()

    def content(data):
        return SECRET.search(data) or any(needle in data.lower() for needle in needles)

    def entry(name, mode, oid):
        if mode not in (b"100755", b"100644") or denied(name.decode("utf-8", "surrogateescape")) or content(name):
            problems.add(f"{oid[:12]}: disallowed path, mode or private name")
        if mode in (b"100755", b"100644") and oid not in blobs:
            blobs.add(oid)
            if content(git("cat-file", "blob", oid)):
                problems.add(f"{oid[:12]}: private content")

    if staged:
        for row in git("ls-files", "--stage", "-z").split(b"\0"):
            if row:
                header, name = row.split(b"\t", 1)
                mode, oid, stage = header.split()
                if stage != b"0":
                    problems.add("unmerged index")
                entry(name, mode, oid.decode())
        return problems

    for oid in git("rev-list", commit or "--all").decode().splitlines():
        head, _, msg = git("cat-file", "commit", oid).partition(b"\n\n")
        for line in head.splitlines():
            if line.startswith((b"author ", b"committer ")):
                email = re.search(rb"<([^<>]+)> [0-9]+ [+-][0-9]{4}$", line)
                if not email or not NOREPLY.fullmatch(email.group(1)):
                    problems.add(f"{oid[:12]}: non-noreply identity")
        if content(head) or content(msg):
            problems.add(f"{oid[:12]}: private commit metadata")
        tree = head.splitlines()[0].split()[1].decode()
        if tree in trees:
            continue
        trees.add(tree)
        # rev-list --objects names a blob just once, even after it is copied under a private path.
        for row in git("ls-tree", "-rz", tree).split(b"\0"):
            if row:
                header, name = row.split(b"\t", 1)
                mode, _, obj = header.split()
                entry(name, mode, obj.decode())
    return problems


def main():
    opts = argparse.ArgumentParser(description=__doc__)
    group = opts.add_mutually_exclusive_group()
    group.add_argument("--staged", action="store_true")
    group.add_argument("--commit", metavar="SHA")
    args = opts.parse_args()
    if args.commit and not re.fullmatch("[0-9a-f]{40}", args.commit):
        opts.error("--commit requires a full commit id")
    try:
        needles = terms()
    except OSError:
        sys.exit("check_leaks: missing or unreadable private scan input")
    if not needles:
        sys.exit("check_leaks: no real .env terms configured")
    problems = scan(needles, args.staged, args.commit)
    if problems:
        sys.exit("check_leaks: refused\n" + "\n".join(sorted(problems)))
    print("check_leaks: clean")


if __name__ == "__main__":
    main()
