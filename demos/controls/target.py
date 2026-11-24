"""Target entry points. Run by the management wrapper in a private mount namespace."""
import contextlib
import fcntl
import math
import pwd
import secrets
import select
import shutil
import sys
import time
from email.utils import parsedate_to_datetime


RUNTIME = "/run/shirudo/runtime/usr/bin/shirudo"
SEAL = b"94442b45cfcdc59aabc2a91364ed2ae129418e05a5c1985231b9c032e673f469"
NOBODY = ["setpriv", "--reuid=nobody", "--regid=nogroup", "--clear-groups", "--no-new-privs", "--"]
JAR_DIR = Path("/run/shirudo-java")


def cli(*args):
    return output(RUNTIME, *args)


def health():
    st = json.loads(cli("status", "--json"))
    t = st["tpm"]
    need(st["status"] == "ok" and st["lsm_attached"] is True and st["keyring_serial_matches"] is True
         and t["reachable"] is True and t["bound_in"] == "initrd" and t["chain_matches_eventlog"] is True
         and t["register_bound"] and t["register_anchored"] and hexstr(t["chain"], 64),
         "target not healthy or not measured in initrd")
    return st


def inventory():
    return sorted(json.loads(cli("upatch", "list", "--json"))["upatches"], key=lambda r: r["name"])


def listeners():
    addrs = sorted((name, row.split()[1]) for name in ("tcp", "tcp6")
                   for row in Path("/proc/net", name).read_text().splitlines()[1:] if row.split()[3] == "0A")
    need(not any(addr.endswith(":1F90") for _, addr in addrs), "port 8080 in use")
    state = subprocess.run(["systemctl", "show", "-p", "LoadState,ActiveState,UnitFileState,MainPID",
                            "legacy-auth.service"], capture_output=True, text=True)
    props = dict(s.split("=", 1) for s in state.stdout.splitlines())
    need(state.returncode in (0, 4) and props.get("MainPID") == "0" and
         props.get("ActiveState") in {"inactive", "failed"} and
         (props.get("LoadState") == "not-found" or props.get("UnitFileState") in {"disabled", "masked"}),
         "legacy service is not stopped and disabled")
    return addrs, props["ActiveState"]


def jdk():
    releases = list(Path("/var/lib/apt/lists").glob("*-security_InRelease"))
    need(releases, "no local security index")
    for p in releases:
        output("gpgv", "--keyring", "/usr/share/keyrings/ubuntu-archive-keyring.gpg", p)
        published = re.search(r"^Date: (.+)$", p.read_text(), re.M)
        need(published and -3600 <= time.time() - parsedate_to_datetime(published[1]).timestamp() <= 3 * 86400,
             "security index not recent; refresh packages separately")
    versions = []
    for pkg in ("openjdk-25-jdk-headless", "openjdk-25-jre-headless"):
        apt = output("apt-cache", "policy", pkg).decode()
        current = re.search(r"Installed: ([\w.+:~\-]+)", apt)
        candidate = re.search(r"Candidate: ([\w.+:~\-]+)", apt)
        need(current and candidate and current[1] == candidate[1], "installed JDK is not distro candidate")
        versions.append(current[1])
    need(versions[0] == versions[1], "JDK/JRE package mismatch")
    java = Path("/usr/bin/java").resolve()
    javac = Path("/usr/bin/javac").resolve()
    need(output("dpkg-query", "-S", java).decode().startswith("openjdk-25-jre-headless:") and
         output("dpkg-query", "-S", javac).decode().startswith("openjdk-25-jdk-headless:"), "unexpected Java binaries")
    return versions[0]


def sealed_agent(name):
    jar = JAR_DIR / (name + ".jar")
    need(jar.is_file() and not jar.is_symlink() and jar.stat().st_mode & 0o777 == 0o644 and
         os.getxattr(jar, "security.bpf.shirudo") == SEAL and
         os.getxattr(JAR_DIR, "security.bpf.shirudo") == SEAL, "agent or directory not sealed")
    return str(jar)


def sandbox_probe(executable, work):
    with tempfile.TemporaryDirectory(dir=work) as tmp:
        user = pwd.getpwnam("nobody")
        os.chown(tmp, user.pw_uid, user.pw_gid)
        script = """
import errno,json,os,sys
os.chdir(sys.argv[1])
out=[]
for name in ('canary.php','canary.txt'):
    try:
        with open(name, 'xb') as f: f.write(b'control-only')
    except OSError as e:
        if e.errno != errno.EACCES or os.path.lexists(name): raise
        out.append('EACCES')
    else:
        with open(name,'rb') as f:
            if f.read() != b'control-only': raise ValueError('canary mismatch')
        out.append('written')
print(json.dumps(out))
"""
        return json.loads(output(*NOBODY, executable, "-I", "-c", script, tmp))


def af_probe():
    # Measure only socket creation + close (or synchronous errno). No bind, data,
    # algorithms, socket options, monitored files or network peers.
    script = """
import errno,json,socket,statistics,time
rows={}
for family,typ,key in ((socket.AF_UNIX,socket.SOCK_DGRAM,'unix'),(socket.AF_ALG,socket.SOCK_SEQPACKET,'alg')):
    times=[]; result=set()
    for i in range(18):
        start=time.monotonic_ns()
        try: socket.socket(family,typ,0).close()
        except OSError as e: outcome=errno.errorcode[e.errno]
        else: outcome='allowed'
        end=time.monotonic_ns()
        if i>=3: times.append(end-start);result.add(outcome)
    if len(result)!=1: raise ValueError('inconsistent result')
    rows[key]={'result':result.pop(),'n':len(times),'median_ns':statistics.median_low(times)}
print(json.dumps(rows))
"""
    return json.loads(output(*NOBODY, "/usr/bin/python3", "-I", "-c", script))


def base64_probe(work, shield):
    with tempfile.TemporaryFile(mode="w+") as log:
        cmd = [*NOBODY, "/usr/bin/java", "-XX:+EnableDynamicAgentLoading", "-cp", str(work), "Control", "base64"]
        p = subprocess.Popen(cmd, cwd=work, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, text=True)
        try:
            def read():
                p.stdin.write("read\n")
                p.stdin.flush()
                need(select.select([p.stdout], [], [], 15)[0], "fixture timed out")
                fields = p.stdout.readline().strip().split()
                need(len(fields) == 3 and fields[0] == str(p.pid) and fields[1].isdigit() and fields[2] == "control",
                     "unexpected JVM response")
                return fields
            before = read()
            need(os.fstat(log.fileno()).st_size == 0, "fixture did not start cleanly")
            with shield():
                jar = sealed_agent("java-base64")
                output(*NOBODY, "/usr/bin/java", "-jar", jar, str(p.pid))
                need(read() == before, "PID, JVM start time or fixed decode changed")
                log.seek(0)
                need("Base64 guard installed on java.util.Base64$Decoder.decode0" in log.read().splitlines(),
                     "missing upstream install diagnostic")
            p.stdin.write("quit\n")
            p.stdin.flush()
            need(p.wait(timeout=10) == 0, "fixture JVM did not quit cleanly")
        finally:
            if p.poll() is None:
                p.kill()
            p.wait()
            p.stdin.close()
            p.stdout.close()
    return {"before": "control", "after_attach": "control", "same_pid_and_jvm_start": True,
            "upstream_install_diagnostic": True, "sealed_jar": True, "scope": "continuity_only"}


def jdbc_probe(work, guarded):
    args = ["-javaagent:" + sealed_agent("java-sql-inj")] if guarded else []
    p = subprocess.run([*NOBODY, "/usr/bin/java", *args, "-cp", str(work), "Control", "jdbc"],
                       cwd=work, capture_output=True, text=True, timeout=45)
    need(p.returncode == 0 and "fixed-read=7" in p.stdout.splitlines(), "normal JDBC read failed")
    expected = "policy-exception" if guarded else "empty"
    need("fixed-marker=" + expected in p.stdout.splitlines(), "unexpected fixed JDBC marker verdict")
    if guarded:
        need("[RASP Agent] Initializing SQL Injection Shield..." in p.stdout and
             "[RASP ALERT]" in p.stderr, "missing advisor diagnostics")
    return {"fixed_read": 7, "fixed_false_predicate": expected}


def measure(args):
    start = health()
    need(start["tpm"]["chain"] == args["chain"], "verified baseline changed before suite")
    need({c["sha256"] for c in start["certs"]} == {args["cert"]}, "unexpected enrolled BPF certificate set")
    initial = inventory()
    view = {r["name"]: r for r in initial}
    boot = Path("/proc/sys/kernel/random/boot_id").read_text()
    listening = listeners()
    initial_sysctl = Path("/proc/sys/crypto/af_alg_restrict").read_text().strip()
    chain = args["chain"]
    pairs, controls = {}, {}

    with tempfile.TemporaryDirectory(prefix="shirudo-control-", dir="/var/tmp") as temp:
        work = Path(temp)
        work.chmod(0o711)
        os.chdir(work)
        for name in CASES:
            lb = paths(args["root"], name)
            absent = [not p.exists() for p in lb]
            if all(absent):
                controls[name] = {"status": "unsupported", "reason": "signed_pair_not_staged"}
                continue
            need(not any(absent), "incomplete signed pair")
            copied = []
            for p, expected in zip(lb, args["manifest"][name][:2]):
                need(p.is_file() and not p.is_symlink() and p.stat().st_size <= 16*1024*1024, "invalid staged artifact")
                data = p.read_bytes()
                need(sha(data) == expected, "staged file differs from operator artifact")
                dest = work / p.name
                dest.write_bytes(data)
                copied.append(dest)
            pairs[name] = copied
            if name in view:
                if name != "java-base64":
                    controls[name] = {"status": "unsupported", "reason": "name_already_in_use"}
                else:
                    row = view[name]
                    need(row["loaded"] is True and row["archived"] is True and
                         row["payload_sha256"] == args["manifest"][name][2] and
                         sha(Path("/var/lib/shirudo/upatches/java-base64.upatch").read_bytes()) == args["manifest"][name][0],
                         "existing base64 artifact differs from operator approval")
        java_version = None
        if any(n not in controls for n in ("java-base64", "java-sql-inj")):
            java_version = jdk()
            src = work / "Control.java"
            src.write_text(args["java"])
            output("/usr/bin/javac", "-d", work, src)
            for cls in work.glob("Control*.class"):
                cls.chmod(0o644)
            output("mount", "-t", "tmpfs", "-o", "mode=1777,nosuid,nodev", "tmpfs", "/tmp")

        @contextlib.contextmanager
        def shield(name, timings):
            nonlocal chain
            digest = args["manifest"][name][2]
            owned = False
            def change(op):
                nonlocal chain, owned
                proposed = extend(chain, name, op, digest)
                report = work / (name + "-" + op + ".json")
                t = time.monotonic_ns()
                cli("upatch", op, "--expect-chain=" + chain, "--report=" + str(report), pairs[name][op == "unload"])
                owned = op == "load"
                chain = proposed
                timings[op] = round((time.monotonic_ns() - t) / 1e6, 3)
                rec = json.loads(report.read_bytes())
                need(rec["result"] == "ok" and rec["category"] == "ok" and rec["tpm"]["chain_after"] == proposed,
                     "signed operation did not measure intended transition")
            if name in view:
                need(health()["tpm"]["chain"] == chain, "concurrent change")
                yield
                return
            need(name not in {r["name"] for r in inventory()}, "name collision before load")
            try:
                change("load")
                row = next((r for r in inventory() if r["name"] == name), {})
                need(row.get("loaded") is True and row.get("payload_sha256") == digest, "load not active")
                yield
            finally:
                if owned:
                    row = next((r for r in inventory() if r["name"] == name), {})
                    need(row.get("loaded") is True and row.get("payload_sha256") == digest, "ownership changed; refusing unload")
                    change("unload")
                    need(name not in {r["name"] for r in inventory()}, "owned artifact still present")

        for name in CASES:
            if name in controls:
                continue
            timings = {}
            if name == "basic":
                with shield(name, timings):
                    pass
                result = {"before": "absent", "during": "loaded_and_measured", "after_unload": "absent"}
            elif name == "java-base64":
                result = base64_probe(work, lambda: shield(name, timings))
            elif name == "app-sandbox":
                # Do not label any installed server. Only the fixture inode is visible
                # at the stock PHP-FPM selector inside THIS private mount namespace.
                need(not any(Path(p).exists() for p in ("/usr/local/apache2/bin/httpd", "/usr/local/sbin/php-fpm")),
                     "refusing to label an existing shared server")
                private_sbin = work / "sbin"
                private_sbin.mkdir(mode=0o755)
                private_sbin.chmod(0o755)
                executable = Path("/usr/sbin/php-fpm-shirudo-control")
                shutil.copyfile(Path("/usr/bin/python3").resolve(), private_sbin / executable.name)
                (private_sbin / executable.name).chmod(0o755)
                output("mount", "--bind", private_sbin, "/usr/sbin")
                try:
                    before = sandbox_probe(executable, work)
                    with shield(name, timings):
                        after = sandbox_probe(executable, work)
                    restored = sandbox_probe(executable, work)
                    need(before == restored == ["written", "written"] and after == ["EACCES", "written"],
                         "sandbox did not produce matched writes")
                finally:
                    output("umount", "/usr/sbin")
                result = {"fixture": "private_PHP_FPM_name_on_distro_Python", "real_php_fpm": False,
                          "first_exec_after_load": True, "order": [".php", ".txt"],
                          "before": before, "after_load": after, "after_unload": restored}
            elif name == "java-sql-inj":
                before = jdbc_probe(work, False)
                with shield(name, timings):
                    after = jdbc_probe(work, True)
                restored = jdbc_probe(work, False)
                result = {"fixture": "mock_JDBC_Statement_with_empty_in_memory_SQLite", "before": before,
                          "after_load_new_jvm": after, "after_unload_new_jvm": restored, "sealed_jar": True}
            else:
                baseline = af_probe()
                need(baseline["unix"]["result"] == "allowed", "AF_UNIX control unavailable")
                if baseline["alg"]["result"] != "allowed":
                    controls[name] = {"status": "unsupported", "reason": "AF_ALG_baseline_not_allowed",
                                      "baseline_errno": baseline["alg"]["result"]}
                    continue
                with shield(name, timings):
                    blocked = af_probe()
                restored = af_probe()
                need(blocked["alg"]["result"] == "EPERM" and restored["alg"]["result"] == "allowed"
                     and blocked["unix"]["result"] == restored["unix"]["result"] == "allowed", "family policy mismatch")
                result = {"before": baseline, "after_load": blocked, "after_unload": restored,
                          "fixture": "unprivileged_unbound_socket_create_and_close"}
            controls[name] = {"status": "verified", "lifecycle": "preserved_preexisting" if name in view else "owned_pair",
                              "operation_ms": timings, **result}
        os.chdir("/")
    end = health()
    need(boot == Path("/proc/sys/kernel/random/boot_id").read_text() and chain == end["tpm"]["chain"]
         and inventory() == initial and listeners() == listening and initial_sysctl ==
         Path("/proc/sys/crypto/af_alg_restrict").read_text().strip(), "final state differs from expected")
    return {"controls": controls, "initial_count": len(initial), "shield_set_restored": True, "no_new_tcp_listeners": True,
            "legacy_service_stopped_disabled": True, "legacy_unit_state_unchanged": listening[1],
            "port_8080_closed": True, "af_alg_restrict_unchanged": int(initial_sysctl),
            "jdk_package": java_version, "kernel": os.uname().release, "chain": chain}


def target(args):
    os.umask(0o077)
    act = args["action"]
    if act == "enroll":
        with tempfile.TemporaryDirectory() as d:
            ev = Path(d, "enrollment.json")
            cli("attest", "--nonce=" + secrets.token_hex(32), "--output=" + str(ev))
            ak = json.loads(ev.read_bytes())["ak"]["name"]
            need(hexstr(ak, 68), "invalid enrollment response")
            return {"ak": ak}
    d = workspace(args["token"])
    if act == "begin":
        d.mkdir(mode=0o700)
        return True
    need(d.is_dir() and not d.is_symlink() and d.stat().st_uid == 0 and d.stat().st_mode & 0o777 == 0o700,
         "lost private target directory")
    if act == "evidence":
        health()
        need(hexstr(args["nonce"], 64), "invalid challenge")
        ev = d / "evidence.json"
        if ev.exists():
            ev.unlink()
        cli("attest", "--nonce=" + args["nonce"], "--output=" + str(ev))
        raw = ev.read_bytes()
        off = log_offset(raw)
        reused = bool(args.get("cached_suffix")) and sha(raw[off:]) == args["cached_suffix"]
        data = zlib.compress(raw[:off] if reused else raw, 9)
        (d / "evidence.z").write_bytes(data)
        pages = math.ceil(len(data) / PAGE)
        need(1 <= pages <= 64, "evidence exceeds bounded relay")
        return {"pages": pages, "sha": sha(data), "full_sha": sha(raw), "reused_suffix": reused,
                "first": base64.b64encode(data[:PAGE]).decode()}
    if act == "page":
        i = args["index"]
        need(type(i) is int and 1 <= i < 64, "invalid page")
        return base64.b64encode((d / "evidence.z").read_bytes()[i * PAGE:(i + 1) * PAGE]).decode()
    if act == "measure":
        # One point of serialization plus Shirudo's expected-chain compare before
        # each mutation. Refuse interference instead of claiming/unloading its shield.
        with open("/run/lock/shirudo-controls.lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return measure(args)
    if act == "end":
        for name in ("evidence.json", "evidence.z"):
            (d / name).unlink(missing_ok=True)
        d.rmdir()
        return True
    raise ValueError("unknown target action")
