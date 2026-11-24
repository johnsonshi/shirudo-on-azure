"""Orchestrate the pinned defensive controls using Azure RBAC Run Command."""
import argparse
import base64
import datetime
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.append(str(HERE))
from common import BASE, CASES, hexstr, intended_chain, log_offset, need, sha


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["enroll", "run"])
    parser.add_argument("--receipt", type=Path, help="new file for a scrubbed receipt (required for run)")
    parser.add_argument("--distro-debs", help="private target directory with the three current Ubuntu package files")
    args = parser.parse_args()
    os.umask(0o077)
    sub = os.environ["AZ_SUBSCRIPTION"]
    group = os.environ["AZ_RESOURCE_GROUP"]
    admin = os.environ.get("ADMIN_USER", "azureuser")
    roles = {r: os.environ.get(r.upper() + "_VM", "shirudo-" + r) for r in ("target", "operator")}
    state = Path(os.environ["SHIRUDO_CONTROL_STATE"]).expanduser().resolve()
    need(not state.is_relative_to(HERE.parents[1]), "private state must be outside checkout")
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    need(state.stat().st_uid == os.getuid() and state.stat().st_mode & 0o077 == 0, "state must be owner-private")
    pin_file = state / "enrolled.json"
    if args.action == "run":
        need(args.receipt and not args.receipt.exists() and args.receipt.parent.is_dir(), "supply a new --receipt path")
    else:
        need(not pin_file.exists() and args.receipt is None and args.distro_debs is None, "invalid enrollment or existing pin")

    def az(*command):
        call = subprocess.run(["az", *command, "--subscription", sub, "--only-show-errors", "-o", "json"],
                              capture_output=True, timeout=700)
        if call.returncode:
            with tempfile.NamedTemporaryFile(dir=state, prefix="az-error-", delete=False) as log:
                log.write(call.stderr)
            raise ValueError("Azure call failed; see private state diagnostics")
        return json.loads(call.stdout)

    matches = az("group", "list", "--tag", "purpose=shirudo-demo", "--query", "[].name")
    need(matches == [group], "no unique matching tagged lab in explicit subscription")
    vms = {v["name"]: v for v in az("vm", "list", "-g", group)}
    need(set(vms) == set(roles.values()) and len(vms) == 2, "unexpected VM roles")
    profile = {}
    for role, vmname in roles.items():
        vm = vms[vmname]
        sku = vm["hardwareProfile"]["vmSize"]
        need(sku == {"target": "Standard_D4ds_v5", "operator": "Standard_D32ds_v5"}[role], "wrong VM size")
        sec = vm["securityProfile"]["uefiSettings"]
        image = vm["storageProfile"]["imageReference"]
        ver = image.get("exactVersion") or image["version"]
        need(sec["vTpmEnabled"] is True and type(sec["secureBootEnabled"]) is bool and
             image["publisher"].lower() == "canonical" and re.fullmatch(r"\d+\.\d+\.\d+", ver),
             "unsupported vTPM or image profile")
        profile[role] = {"size": sku, "image_version": ver, "secure_boot": sec["secureBootEnabled"], "vtpm": True}
    vm_id = vms[roles["target"]]["vmId"]

    def remote(role, action, **params):
        worker = (HERE / {"operator": "verifier.py", "target": "target.py"}[role]).read_text()
        if action == "measure" and args.distro_debs is not None:
            worker += "\n" + (HERE / "distro.py").read_text()
        common = (HERE / "common.py").read_text()
        packed = base64.b64encode(json.dumps({"action": action, **params}).encode()).decode()
        # The result must have a single completion frame. ARM can return success for
        # a guest script that failed, and Run Command truncates long output.
        code = common + "\n" + worker + "\n" + f"""
try:
    frame({role}(json.loads(base64.b64decode('{packed}'))))
except subprocess.CalledProcessError as exc:
    sys.stderr.buffer.write(exc.stderr or b'')
    raise
"""
        namespace = "unshare --mount --propagation private -- " if action == "measure" else ""
        body = ("#!/bin/sh\nset -eu\numask 077\n" + namespace +
                "env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root "
                "LC_ALL=C /usr/bin/python3 -I - <<'CONTROL_PROGRAM'\n" + code + "\nCONTROL_PROGRAM\n")
        with tempfile.NamedTemporaryFile(mode="w", dir=state, prefix="request-") as f:
            f.write(body)
            f.flush()
            result = az("vm", "run-command", "invoke", "-g", group, "-n", roles[role],
                        "--command-id", "RunShellScript", "--scripts", "@" + f.name)
        message = result["value"][0]["message"]
        framed = re.findall(r"^CONTROL:([A-Za-z0-9+/=]+)$", message, re.M)
        if len(framed) != 1:
            with tempfile.NamedTemporaryFile(mode="w", dir=state, prefix=f"{role}-{action}-", delete=False) as log:
                log.write(message)
            raise ValueError(f"{role}/{action} did not return a completion frame; see private diagnostics")
        return json.loads(zlib.decompress(base64.b64decode(framed[0], validate=True)))

    if args.action == "enroll":
        ak = remote("target", "enroll")["ak"]
        need(hexstr(ak, 68), "invalid AK")
        with pin_file.open("x") as f:
            json.dump({"vm": vm_id, "ak": ak}, f)
        print("Pinned the target AK in private state (separate Azure RBAC enrollment, TOFU).")
        return 0
    need(pin_file.is_file() and not pin_file.is_symlink() and pin_file.stat().st_mode & 0o077 == 0, "no private AK pin")
    pin = json.loads(pin_file.read_bytes())
    need(pin["vm"] == vm_id and hexstr(pin["ak"], 68), "pin is not for this VM")
    token = secrets.token_hex(16)

    def attest(manifest, expected):
        nonce = secrets.token_hex(32)
        cache = state / "evidence-logs-cache"
        suffix = cache.read_bytes() if cache.is_file() else b""
        head = remote("target", "evidence", token=token, nonce=nonce, cached_suffix=sha(suffix) if suffix else None)
        pages = [head["first"]] + [remote("target", "page", token=token, index=i) for i in range(1, head["pages"])]
        data = b"".join(base64.b64decode(p, validate=True) for p in pages)
        need(sha(data) == head["sha"], "incomplete evidence")
        raw = zlib.decompress(data) + (suffix if head["reused_suffix"] else b"")
        need(sha(raw) == head["full_sha"], "reconstructed evidence is not byte-identical")
        verdict = remote("operator", "verify", evidence=base64.b64encode(zlib.compress(raw, 9)).decode(),
                         nonce=nonce, pin=pin["ak"], config=manifest["config"], chain=expected)
        if not head["reused_suffix"]:
            with tempfile.NamedTemporaryFile(dir=state, delete=False) as f:
                f.write(raw[log_offset(raw):])
            os.replace(f.name, cache)
        return verdict

    remote("target", "begin", token=token)
    try:
        print("Checking approved operator artifacts and verifying the target's fresh baseline quote ...", flush=True)
        manifest = remote("operator", "manifest", admin=admin)
        before = attest(manifest, None)
        print("Baseline verified. Running the fixed local controls on the target ...", flush=True)
        result = remote("target", "measure", token=token, root=os.environ.get("SHIRUDO_TARGET_SHIELDS", "/var/tmp/shields"),
                        manifest=manifest["pairs"], cert=manifest["cert"], chain=before["chain"],
                        java=(HERE / "Control.java").read_text(), distro=args.distro_debs)
        chain = intended_chain(before["chain"], manifest["pairs"], result["controls"])
        need(result.pop("chain") == chain, "guest did not reach independently computed final register")
        print("Fixtures stopped. Verifying the expected final register and wrong-nonce rejection ...", flush=True)
        final = attest(manifest, chain)
        need(final["chain"] == chain and before["wrong_nonce_rejected"] and final["wrong_nonce_rejected"],
             "final evidence not verified")
    finally:
        remote("target", "end", token=token)
    receipt = {
        "schema": 1, "measured_utc": datetime.datetime.now(datetime.timezone.utc).date().isoformat(),
        "upstream": BASE, "azure": profile,
        "attestation": {"fresh_before_and_after": True, "wrong_nonce_rejected": True, "bound_in": "initrd",
                        "ak_enrollment": "separate_Azure_RBAC_TOFU", "operator_signed_config_root_pcr": 13,
                        "final_register": "verified_baseline_plus_planned_signed_payload_transitions",
                        "historical_intent_approved": False, "ek_endorsement_verified": False,
                        "nv_writer_rsa_bits": final["writer_bits"],
                        "azure_guest_attestation_service_used": False},
        "timing": {"clock": "guest monotonic", "operation_ms": "one signed CLI load/unload including TPM",
                   "socket_median_ns": "15 create/close or synchronous refusals after 3 warmups per family/phase",
                   "observer_delivery_measured": False, "control_plane_latency_included": False},
        **result,
    }
    with args.receipt.open("x") as f:
        json.dump(receipt, f, indent=2)
        f.write("\n")
    complete = all(c["status"] == "verified" for c in result["controls"].values())
    for case in CASES:
        row = result["controls"][case]
        print(f'{case}: {row["status"]} ({row.get("lifecycle") or row["reason"]})')
    print("Verified final evidence and cleanup. Receipt written; " +
          ("all controls verified." if complete else "one or more controls unsupported."))
    return 0 if complete else 3


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, FileExistsError, subprocess.TimeoutExpired) as exc:
        print(f"Controls stopped: {exc}", file=sys.stderr)
        sys.exit(1)
