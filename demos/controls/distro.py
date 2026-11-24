"""Opt-in real distro workloads; extract individual checked files, never install a service."""
import io
import signal
import socket
import stat
import struct
import tarfile


def ubuntu_candidate(cache, pkg):
    candidate = cache[pkg].candidate
    origins = [o for o in candidate.origins if o.archive != "now"] if candidate else []
    if not origins or not all(o.trusted and o.origin == "Ubuntu" and o.label == "Ubuntu" for o in origins):
        raise ValueError("expected a candidate from authenticated Ubuntu archive metadata")
    return candidate.version, candidate.sha256


def distro_inputs(directory, work):
    import apt

    root = Path(directory)
    need(root.is_absolute() and root.resolve() == root and root.is_dir() and
         root.stat().st_uid == 0 and root.stat().st_mode & 0o077 == 0, "expected a root-private distro staging directory")
    cache = apt.Cache()
    versions = {}
    for pkg, member, dest in (
        ("php8.5-fpm", "./usr/sbin/php-fpm8.5", "fpm"),
        ("libargon2-1", "./usr/lib/x86_64-linux-gnu/libargon2.so.1", "libargon2.so.1"),
        ("libh2-java", None, "h2.jar"),
    ):
        path = root / (pkg + ".deb")
        candidate, digest = ubuntu_candidate(cache, pkg)
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), "rb") as src:
            st = os.fstat(src.fileno())
            need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and not st.st_mode & 0o022
                 and 0 < st.st_size <= 16 * 1024 * 1024, "unexpected distro package file")
            data = src.read(st.st_size)
        need(len(data) == st.st_size and sha(data) == digest, "package differs from signed-index candidate")
        # Inspect precisely the bytes that passed the digest check, never reopen the staging path.
        package = work / (pkg + ".deb")
        with package.open("xb") as f:
            f.write(data)
        need(output("dpkg-deb", "-f", package, "Package").decode().strip() == pkg and
             output("dpkg-deb", "-f", package, "Version").decode().strip() == candidate, "unexpected package identity")
        if member is None:
            member = "./usr/share/java/h2-" + candidate.split(":")[-1].split("-")[0] + ".jar"
        with tarfile.open(fileobj=io.BytesIO(output("dpkg-deb", "--fsys-tarfile", package))) as archive:
            entries = [e for e in archive if e.name == member]
            need(len(entries) == 1 and entries[0].isfile() and 0 < entries[0].size <= 32 * 1024 * 1024,
                 "expected one regular allowed package member")
            (work / dest).write_bytes(archive.extractfile(entries[0]).read())
            (work / dest).chmod(0o755 if dest == "fpm" else 0o644)
        versions[pkg] = candidate
    return versions


def fastcgi(sock_path, script):
    def record(t, data):
        return struct.pack("!BBHHBB", 1, t, 1, len(data), 0, 0) + data

    fields = {b"SCRIPT_FILENAME": os.fsencode(script), b"SCRIPT_NAME": b"/control.php",
              b"REQUEST_METHOD": b"GET", b"SERVER_PROTOCOL": b"HTTP/1.1"}
    need(all(len(v) < 128 for v in fields.values()), "private path exceeds fixed FastCGI fixture bound")
    params = b"".join(bytes((len(k), len(v))) + k + v for k, v in fields.items())
    request = record(1, struct.pack("!HB5x", 1, 0)) + record(4, params) + record(4, b"") + record(5, b"")
    data = bytearray()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(5)
        client.connect(str(sock_path))
        client.sendall(request)
        with client.makefile("rb") as inp:
            for _ in range(16):
                v, typ, ident, size, pad, _ = struct.unpack("!BBHHBB", inp.read(8))
                need(v == 1 and ident == 1 and size <= 8192, "bad local FastCGI response")
                body = inp.read(size)
                need(len(body) == size and len(inp.read(pad)) == pad, "short local response")
                if typ == 6:
                    data.extend(body)
                elif typ == 3:
                    need(body == bytes(8), "worker did not complete")
                    headers, sep, result = bytes(data).partition(b"\r\n\r\n")
                    need(sep and b"Status:" not in headers, "worker returned a failure status")
                    return json.loads(result)
                else:
                    need(typ == 7 and not body, "worker reported a diagnostic")
    raise ValueError("no complete response from private FPM worker")


def fpm_probe(executable, work):
    user = pwd.getpwnam("nobody")
    with tempfile.TemporaryDirectory(dir=work) as tmp:
        root = Path(tmp)
        root.chmod(0o711)
        app, data, private = [root / s for s in ("app", "canaries", "socket")]
        app.mkdir()
        app.chmod(0o755)
        for path in (data, private):
            path.mkdir(mode=0o700)
            os.chown(path, user.pw_uid, user.pw_gid)
        file = app / "control.php"
        file.write_text("""<?php
$out = [];
foreach (['canary.php', 'canary.txt'] as $name) {
    $path = __DIR__ . '/../canaries/' . $name;
    $handle = @fopen($path, 'xb');
    if (!$handle) {
        if (!str_contains(error_get_last()['message'], 'Permission denied') || file_exists($path)) exit(1);
        $out[] = 'EACCES';
    } else {
        if (fwrite($handle, 'control-only') !== 12 || !fclose($handle)) exit(1);
        $out[] = 'written';
    }
}
echo json_encode($out);
""")
        file.chmod(0o644)
        conf = root / "pool.conf"
        sock = private / "fpm.sock"
        conf.write_text(f"""[global]
daemonize = no
error_log = {private}/error.log
[control]
user = nobody
group = nogroup
listen = {sock}
listen.mode = 0600
pm = static
pm.max_children = 1
clear_env = yes
security.limit_extensions = .php
""")
        conf.chmod(0o644)
        with tempfile.TemporaryFile() as log:
            p = subprocess.Popen(["unshare", "--net", "--", *NOBODY, "env", "LD_LIBRARY_PATH=" + str(work), executable,
                                  "-n", "-F", "-y", conf], cwd=root, stdout=log, stderr=log, start_new_session=True)
            try:
                for _ in range(150):
                    if p.poll() is not None:
                        log.seek(0)
                        sys.stderr.buffer.write(log.read(1500))
                        raise ValueError("private FPM pool exited before ready")
                    if sock.is_socket():
                        break
                    time.sleep(.05)
                need(sock.is_socket() and sock.stat().st_mode & 0o777 == 0o600, "private FPM socket not ready")
                results = fastcgi(sock, file)
                need(isinstance(results, list) and len(results) == 2, "missing FPM canary results")
                for name, outcome in zip(("canary.php", "canary.txt"), results):
                    path = data / name
                    need((outcome == "written" and path.read_bytes() == b"control-only") or
                         (outcome == "EACCES" and not path.exists()), "canary differs from FPM result")
                children = output("ps", "-o", "pid=", "--ppid", str(p.pid)).split()
                need(len(children) == 1, "unexpected number of FPM workers")
                return results
            finally:
                if p.poll() is None:
                    p.send_signal(signal.SIGQUIT)
                try:
                    p.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    p.terminate()
                    p.wait(timeout=5)
                try:
                    os.killpg(p.pid, 0)
                except ProcessLookupError:
                    pass
                else:
                    raise ValueError("an owned FPM worker is still running")
