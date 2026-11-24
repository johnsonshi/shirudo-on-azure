"""Run only on the signing/verification operator. Never export keys."""
import pwd
import sys


def operator(args):
    if args["action"] == "manifest":
        home = Path(pwd.getpwnam(args["admin"]).pw_dir)
        root = home / "build/shields"
        cfg = home / "build/target-bundle/initial"
        repo = home / "shirudo"
        git = ["git", "-c", "safe.directory=" + str(repo), "-C", repo]
        output(*git, "merge-base", "--is-ancestor", BASE, "HEAD")
        output(*git, "diff", "--quiet", BASE, "--", "testing/fixtures/basic.bpf.c",
               "upatches/java-base64", "upatches/app-sandbox", "upatches/java-sql-inj/agent",
               "upatches/kernel-cve")
        output("shirudo", "image", "verify", cfg, "--cert", home / "shirudo-keys/config/cert.der")
        manifest = {}
        for name, (_, kind) in CASES.items():
            load, unload = paths(root, name)
            need(all(p.is_file() and not p.is_symlink() for p in (load, unload)), "missing operator pair")
            a, b = [json.loads(output("shirudo", "upatch", "info", "--json", p)) for p in (load, unload)]
            for x, op in ((a, "load"), (b, "unload")):
                need(x["schema"] == 1 and x["name"] == x["signed_name"] == name and
                     x["type"] == op and x["payload_type"] == kind and x["signature_len"] > 0,
                     "wrong operator artifact")
            payload = a["payload_sha256"]
            need(hexstr(payload, 64) and b["unload_payload_sha256"] == payload, "unbound unload")
            manifest[name] = [sha(load.read_bytes()), sha(unload.read_bytes()), payload]
        config = cfg.with_suffix(".roothash").read_text().strip()
        need(hexstr(config, 64), "invalid approved config root")
        return {"pairs": manifest, "config": config, "cert": sha((home / "shirudo-keys/bpf/cert.der").read_bytes())}
    if args["action"] == "verify":
        need(hexstr(args["pin"], 68) and hexstr(args["nonce"], 64) and hexstr(args["config"], 64),
             "invalid verifier inputs")
        with tempfile.TemporaryDirectory() as tmp:
            ev = Path(tmp, "evidence.json")
            ev.write_bytes(zlib.decompress(base64.b64decode(args["evidence"], validate=True)))
            common = ["shirudo", "attest", "verify", "--json", "--evidence=" + str(ev),
                      "--ak-name=" + args["pin"], "--expect-config-root=" + args["config"],
                      "--expect-config-pcr=13", "--require-initrd"]
            # The measured baseline is NOT approved historical intent. A final chain, when
            # supplied, adds only the operator's intended deltas to the verified baseline.
            if args["chain"] is not None:
                need(hexstr(args["chain"], 64), "invalid expected register")
                common.append("--expect-chain=" + args["chain"])
            good = json.loads(output(*common, "--nonce=" + args["nonce"]))
            need(good["verdict"] == "ok", "operator rejected evidence")
            other = ("0" if args["nonce"][0] != "0" else "1") + args["nonce"][1:]
            wrong = subprocess.run([*common, "--nonce=" + other], capture_output=True, timeout=90)
            bad = json.loads(wrong.stdout)
            need(wrong.returncode == 1 and bad["verdict"] == "fail" and
                 any(c["result"] == "fail" and "nonce" in c["text"].lower() for c in bad["checks"]),
                 "wrong nonce not rejected for nonce mismatch")
            doc = json.loads(ev.read_bytes())
            chain = doc["register"]["value"]
            need(hexstr(chain, 64), "verified register unreadable")
            init = [r for r in doc["eventlog"] if r["type"] == "init"][-1]
            writer = init["nv_writer_public"]
            need(len(writer) in (512, 768) and hexstr(writer, len(writer)), "unexpected NV writer key")
            return {"chain": chain, "wrong_nonce_rejected": True, "writer_bits": len(writer) * 4}
    raise ValueError("unknown operator action")
