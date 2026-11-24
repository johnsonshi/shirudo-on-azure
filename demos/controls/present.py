"""Display one control from a recorded suite. No Azure access or guest operations."""
import argparse
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.append(str(HERE))
from common import AF, BASE, CASES, need

UPSTREAM = {
    "basic": "testing/fixtures/basic.bpf.c",
    "java-base64": "upatches/java-base64",
    "app-sandbox": "upatches/app-sandbox",
    "java-sql-inj": "upatches/java-sql-inj/agent",
    AF: "upatches/kernel-cve/sources/cve-2026-31431-crypto-algif-aead-copy-fail/mitigation/" + AF + ".bpf.c",
}


def outcomes(case, r):
    lifecycle = r["lifecycle"]
    need(lifecycle == "owned_pair" or (case == "java-base64" and lifecycle == "preserved_preexisting"),
         "unexpected artifact lifecycle")
    if case == "basic":
        stages = [r[k] for k in ("before", "during", "after_unload")]
        need(stages == ["absent", "loaded_and_measured", "absent"], "signed lifecycle mismatch")
        return *stages, "the signed no-op was accepted and measured; no separate workload probe"
    if case == "java-base64":
        need(r["scope"] == "continuity_only" and r["same_pid_and_jvm_start"] is True and
             r["upstream_install_diagnostic"] is True and r["sealed_jar"] is True and
             r["before"] == r["after_attach"] == "control", "JVM continuity evidence missing")
        restored = "pre-existing agent retained, not unloaded" if lifecycle == "preserved_preexisting" else "owned pair unloaded"
        return ("normal input decoded to control", "same JVM decoded control after explicit attach",
                restored + "; post-unload decode not measured", "normal Base64 decode remained unchanged")
    if case == "app-sandbox":
        variants = {True: "Ubuntu_PHP_FPM_one_worker_private_Unix_socket", False: "private_PHP_FPM_name_on_distro_Python"}
        real = r["real_php_fpm"]
        need(type(real) is bool and r["fixture"] == variants[real] and r["first_exec_after_load"] is True and
             r["order"] == [".php", ".txt"] and r["before"] == r["after_unload"] == ["written", "written"]
             and r["after_load"] == ["EACCES", "written"], "sandbox canary observations do not match")
        fixture = "Ubuntu PHP-FPM worker (private Unix socket)" if real else "PHP-FPM-named Python fixture"
        return (fixture + ": both canaries written", ".php denied (EACCES); .txt written",
                "both canaries written after unload", "inert .txt write succeeded in all three phases")
    if case == "java-sql-inj":
        variants = {"Ubuntu_H2_JDBC_Statement_with_empty_in_memory_database": "H2 JDBC",
                    "mock_JDBC_Statement_with_empty_in_memory_SQLite": "mock JDBC / SQLite"}
        fixture = variants[r["fixture"]]
        stages = [r[k] for k in ("before", "after_load_new_jvm", "after_unload_new_jvm")]
        need(r["sealed_jar"] is True and all(s["fixed_read"] == 7 for s in stages)
             and [s["fixed_false_predicate"] for s in stages] == ["empty", "policy-exception", "empty"],
             "JDBC positive or policy control mismatch")
        return (fixture + ": fixed false read returned no rows", "upstream agent rejected the same read in a fresh JVM",
                "same read again returned no rows", "SELECT 7 returned 7 in all three phases")
    stages = [r[k] for k in ("before", "after_load", "after_unload")]
    need(r["fixture"] == "unprivileged_unbound_socket_create_and_close" and
         [s["alg"]["result"] for s in stages] == ["allowed", "EPERM", "allowed"] and
         all(s["unix"]["result"] == "allowed" for s in stages), "socket family controls do not match")
    return ("unbound AF_ALG socket creation allowed", "AF_ALG denied (EPERM)",
            "AF_ALG allowed after unload", "unbound AF_UNIX socket creation succeeded in all three phases")


def present(case, report):
    need(report["schema"] == 1 and report["upstream"] == BASE and set(report["controls"]) == set(CASES),
         "not a complete suite receipt for this upstream revision")
    need(report["attestation"]["fresh_before_and_after"] is True and report["attestation"]["wrong_nonce_rejected"] is True
         and report["shield_set_restored"] is True and report["no_new_tcp_listeners"] is True,
         "attestation or cleanup was not recorded as successful")
    r = report["controls"][case]
    path = UPSTREAM[case]
    ref = "blob" if path.endswith(".c") else "tree"
    print(f"Recorded evidence (offline replay): {case}, one row from the full suite; no guest contacted.")
    print(f"Upstream: https://github.com/shirudo-dev/shirudo/{ref}/{BASE}/{path}")
    if r["status"] == "unsupported":
        need(r["reason"] in ("signed_pair_not_staged", "name_already_in_use", "AF_ALG_baseline_not_allowed"),
             "unrecognized unsupported condition")
        print("Unsupported in this receipt:", r["reason"])
        return 3
    need(r["status"] == "verified", "control was not recorded as verified")
    for label, value in zip(("Before", "Active", "Restored", "Positive control"), outcomes(case, r)):
        print(f"{label}: {value}")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", choices=CASES)
    parser.add_argument("--receipt", type=Path, default=HERE.parents[1] / "docs/results/azure-controls.json",
                        help="suite receipt to replay (default: committed fixed-fixture run)")
    args = parser.parse_args()
    try:
        with args.receipt.open("rb") as f:
            data = f.read(256 * 1024 + 1)
        need(len(data) <= 256 * 1024, "receipt is too large")
        sys.exit(present(args.case, json.loads(data)))
    except (KeyError, TypeError, ValueError, OSError) as exc:
        sys.exit(f"Cannot present recorded control: {exc}")
