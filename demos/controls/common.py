"""Shared by the workstation, operator and target. Only these pairs may be opened."""
import base64
import hashlib
import json
import os
import re
import subprocess
import tempfile
import zlib
from pathlib import Path


BASE = "ff5dd643ac0b3d68310450a2cb9b668416eac036"
CASES = {
    "basic": ("walkthrough", "bpf"),
    "java-base64": ("java4shell", "java"),
    "app-sandbox": ("php2shell", "bpf"),
    "java-sql-inj": ("sqli", "java"),
    "cve-2026-31431-af-alg-block": ("copy-fail", "bpf"),
}
AF = "cve-2026-31431-af-alg-block"
PAGE = 2400


def need(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def hexstr(value, length):
    return isinstance(value, str) and re.fullmatch("[0-9a-f]{%d}" % length, value)


def output(*args):
    return subprocess.check_output(args, stderr=subprocess.PIPE, timeout=90)


def paths(root, case):
    parent = Path(root) / CASES[case][0]
    return tuple(parent / (case + suffix) for suffix in (".upatch", ".unload.upatch"))


def extend(chain, name, op, payload):
    # Upstream Documentation/reference/eventlog.rst, including the NUL in the tag.
    tag = {
        ("bpf", "load"): "shirudo-upatch", ("bpf", "unload"): "shirudo-unload",
        ("java", "load"): "shirudo-java", ("java", "unload"): "shirudo-java-unload",
    }[CASES[name][1], op]
    event = hashlib.sha256(tag.encode() + b"\0" + bytes.fromhex(payload) + name.encode()).digest()
    return sha(bytes.fromhex(chain) + event)


def intended_chain(start, pairs, controls):
    need(set(controls) == set(CASES), "incomplete control report")
    chain = start
    for case in CASES:
        row = controls[case]
        if row["status"] == "unsupported":
            continue
        need(row["status"] == "verified", "unknown control outcome")
        if row["lifecycle"] == "preserved_preexisting":
            need(case == "java-base64", "unexpected preexisting shield")
            continue
        need(row["lifecycle"] == "owned_pair", "unknown shield ownership")
        for op in ("load", "unload"):
            chain = extend(chain, case, op, pairs[case][2])
    return chain


def workspace(token):
    need(hexstr(token, 32), "invalid run identifier")
    return Path("/var/tmp", "shirudo-controls-" + token)


def log_offset(evidence):
    # Upstream writes its bulky optional firmware/systemd log object last.
    # This is a lossless transport optimization, never a verification decision.
    offset = evidence.rfind(b'"logs"')
    return offset if offset >= 0 else len(evidence)


def frame(data):
    body = zlib.compress(json.dumps(data, separators=(",", ":")).encode(), 9)
    message = base64.b64encode(body).decode()
    need(len(message) <= 3800, "response exceeds management channel limit")
    print("CONTROL:" + message)
