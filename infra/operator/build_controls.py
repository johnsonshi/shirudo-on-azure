"""Build five upstream defensive load/unload pairs without checking out example apps."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile

HERE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(HERE / "infra"))
import bundle

BASE64 = "upatches/java-base64"
JDBC = "upatches/java-sql-inj"
APP = "upatches/app-sandbox"
ALG = ("upatches/kernel-cve/sources/cve-2026-31431-crypto-algif-aead-copy-fail/mitigation/"
       "cve-2026-31431-af-alg-block.bpf.c")
INPUTS = (
    "testing/fixtures/basic.bpf.c", ALG,
    BASE64+"/build.sh", BASE64+"/src/com/shirudo/base64guard/Base64GuardAgent.java",
    BASE64+"/src/com/shirudo/base64guard/GuardCheck.java",
    JDBC+"/pom.xml", JDBC+"/agent/pom.xml",
    JDBC+"/agent/src/main/java/com/security/rasp/RaspAgent.java",
    JDBC+"/agent/src/main/java/com/security/rasp/SqlInjectionAdvisor.java",
    APP+"/Beefile", APP+"/app-sandbox.bpf.c", APP+"/gen_policy.py", APP+"/sandbox.toml", APP+"/README.md",
)
CLI = "/usr/bin/shirudo"


def export_inputs(repo, base, work):
    for name in INPUTS:
        git = ["git", "-C", str(repo)]
        meta = subprocess.check_output(git+["ls-tree", "-l", base, "--", name]).decode().split()
        if len(meta) != 5 or meta[0] not in ("100644", "100755") or meta[1] != "blob" or meta[4] != name or int(meta[3]) > 1024**2:
            raise ValueError("missing or unsafe pinned control input: "+name)
        dest = work / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open("xb") as f:
            subprocess.run(git+["cat-file", "blob", meta[2]], check=True, stdout=f)
        dest.chmod(0o700 if meta[0] == "100755" else 0o600)


def check_info(info, name, action, kind, bound=None):
    if (info.get("type") != action or info.get("payload_type") != kind or info.get("signed_name") != name
            or info.get("name") != name or info.get("signature_len", 0) <= 0
            or info.get("unload_payload_sha256") != bound
            or not re.fullmatch("[0-9a-f]{64}", info.get("payload_sha256", ""))):
        raise ValueError("unexpected signed metadata or load/unload payload mismatch")
    return info["payload_sha256"]


def build(work):
    repo = Path.home() / "shirudo"
    base = (HERE / "patches/shirudo/BASE").read_text().strip()
    if not re.fullmatch("[0-9a-f]{40}", base) or subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip() != base:
        raise ValueError("operator source is not the pinned checkout")
    export_inputs(repo, base, work)
    home = Path.home()
    keys = home / "shirudo-keys/bpf"
    if not all((keys / name).is_file() for name in ("cert.der", "signing_key.pem")):
        raise ValueError("use the existing initializer's BPF signing key")
    btfs = list((home / "build/azure-kernel/latest").glob("vmlinux-*.btf"))
    if len(btfs) != 1:
        raise ValueError("expected the single target kernel BTF")
    header = work / "vmlinux.h"
    with header.open("xb") as f:
        subprocess.run([home / "build/shirudo/src/tools/gen-vmlinux-h/gen-vmlinux-h", btfs[0]], stdout=f, check=True)
    subprocess.run(["cmp", "-s", header, "/usr/share/shirudo/vmlinux.h"], check=True)
    out = home / "build/shields"
    out.mkdir(mode=0o700)
    for stem in bundle.STEMS:
        name = Path(stem).name
        load, unload = out / (stem+".upatch"), out / (stem+".unload.upatch")
        load.parent.mkdir(mode=0o700)
        key_opts = ["--keys-dir", str(keys)]
        is_java = name in ("java-base64", "java-sql-inj")
        if name == "app-sandbox":
            # Use the Beefile: a bare C build omits its generated rodata and policy selectors.
            subprocess.run([CLI, "bpm", "build", work / APP, "--version", "1.0.0", "--vmlinux", header,
                            *key_opts], cwd=work, check=True)
            with tarfile.open(work / "app-sandbox-1.0.0.bee", "r:gz") as pkg:
                member = pkg.getmember("upatches/app-sandbox.upatch")
                if not member.isreg() or not 0 < member.size <= 16*1024**2:
                    raise ValueError("unexpected app-sandbox package member")
                with pkg.extractfile(member) as src, load.open("xb") as dst:
                    dst.write(src.read())
        else:
            if name == "java-base64":
                subprocess.run([work / BASE64 / "build.sh", "--jar-only"], cwd=work, check=True)
                source = work / BASE64 / "java-base64.jar"
            elif name == "java-sql-inj":
                agent = work / JDBC / "agent"
                subprocess.run(["mvn", "-B", "-ntp", "-f", agent / "pom.xml", "-DskipTests", "package"],
                               cwd=agent, check=True)
                source = agent / "target/shirudo-sqli-agent-1.0-SNAPSHOT.jar"
            elif name == "basic":
                source = work / "testing/fixtures/basic.bpf.c"
            elif name == "cve-2026-31431-af-alg-block":
                source = work / ALG
            else:
                raise ValueError("unknown control")
            subprocess.run([CLI, "build", source, "--name", name, "-o", load, *key_opts,
                            *([] if is_java else ["--vmlinux", header])], cwd=work, check=True)
        kind = "java" if is_java else "bpf"
        def info(path):
            return json.loads(subprocess.check_output([CLI, "upatch", "info", "--json", path]))
        digest = check_info(info(load), name, "load", kind)
        subprocess.run([CLI, "build", "--unload", name, "--payload-sha256", digest,
                        *(["--java"] if is_java else []), "-o", unload, *key_opts], check=True)
        check_info(info(unload), name, "unload", kind, digest)
    bundle.main(["controls", "seal"])


if __name__ == "__main__":
    os.umask(0o077)
    with tempfile.TemporaryDirectory(dir=Path.home() / "build") as tmp:
        build(Path(tmp))
