import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "infra/azure"), str(ROOT / "infra/operator"), str(ROOT / "infra"), str(ROOT / "tools")]
import bundle
import build_controls
import check_leaks
import lab
from resources import Lab


class Fixture(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.cfg = dict(AZ_SUBSCRIPTION=str(uuid.uuid4()), AZ_LOCATION="eastus",
                        AZ_RESOURCE_GROUP="fixture", OPERATOR_VM="op-vm", TARGET_VM="target-vm",
                        ADMIN_USER="labuser", SSH_KEY=str(self.root / "key"), ALLOWED_SSH_CIDR="8.8.8.8/32",
                        OPERATOR_SIZE="Standard_D8ds_v5", TARGET_SIZE="Standard_D4ds_v5",
                        UBUNTU_IMAGE="Canonical:ubuntu-26_04-lts:server:latest")

    def write_cfg(self):
        (self.root / ".env").write_text("".join(f"{k}={v}\n" for k, v in self.cfg.items()))
        return Lab(self.root)

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root), *args], stderr=subprocess.PIPE)

    def new_repo(self):
        self.git("init", "-q")
        self.git("config", "user.name", "Fixture")
        self.git("config", "user.email", "fixture@users.noreply.github.com")


class Infrastructure(Fixture):
    def test_verify_does_not_trust_successful_process_exit(self):
        rows = [{"type": s, "status": "OK"} for s in sorted(lab.TARGET_CONDITIONS)]
        healthy = {"schema": 1, "is_target": True, "status": "ok", "conditions": rows}
        with patch.object(lab, "Lab"), patch.object(lab, "Guests") as guests:
            run = guests.return_value.run
            run.return_value = subprocess.CompletedProcess([], 0, json.dumps(healthy).encode())
            with contextlib.redirect_stdout(io.StringIO()):
                lab.main(["verify"])
            self.assertIn("status --json", run.call_args.args[1])
            for invalid in [b"not-json", b"[]", b"{}", b'{"status":"ok"}',
                            *[json.dumps({**healthy, **overrides}).encode() for overrides in [
                                {"status": "degraded"}, {"status": "tampered"}, {"is_target": False},
                                {"conditions": rows[:-1]}, {"conditions": [rows[1], *rows[1:]]},
                                {"conditions": [dict(rows[0], status="WARN"), *rows[1:]]}]]]:
                with self.subTest(report=invalid), self.assertRaises(ValueError):
                    run.return_value = subprocess.CompletedProcess([], 0, invalid)
                    lab.main(["verify"])

    def test_offline_plan_and_explicit_mutation_flags(self):
        with patch.object(lab, "Lab", side_effect=AssertionError("must remain offline")):
            with contextlib.redirect_stdout(io.StringIO()):
                lab.main([])
                lab.main(["files", "target"])
            for args in (["create"], ["restart"], ["rollback"], ["relay", "/tmp", "/tmp"],
                         ["stage", "neither"]):
                with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    lab.main(args)

    def test_refuses_broad_or_ambiguous_networks_and_scope(self):
        for key, value in (("ALLOWED_SSH_CIDR", "0.0.0.0/0"), ("ALLOWED_SSH_CIDR", "8.8.8.0/24"),
                           ("ALLOWED_SSH_CIDR", "10.0.0.1/32"), ("ALLOWED_SSH_SOURCES", "AzureCloud"),
                           ("ALLOWED_SSH_CIDR", "Internet"), ("AZ_SUBSCRIPTION", ""),
                           ("OPERATOR_VM", "../other"), ("TARGET_VM", self.cfg["OPERATOR_VM"])):
            with self.subTest(key=key, value=value), patch.dict(self.cfg, {key: value}), self.assertRaises(ValueError):
                self.write_cfg()

    def test_each_cli_call_has_subscription_and_queried_values_are_not_shell(self):
        obj = self.write_cfg()
        with patch("resources.subprocess.run", return_value=Mock(stdout=b"true")) as run:
            self.assertTrue(obj.az("group", "exists", "-n", obj.group, read=True))
        cli = run.call_args.args[0]
        self.assertEqual(cli[cli.index("--subscription")+1], self.cfg["AZ_SUBSCRIPTION"])
        self.assertNotIn("shell", run.call_args.kwargs)

    def test_create_refuses_existing_group_and_fails_closed_on_query_error(self):
        obj = self.write_cfg()
        obj.key.write_text("test-only")
        Path(str(obj.key)+".pub").write_text("ssh-ed25519 AAAA fixture")
        for result in (True, None, "false"):
            with self.subTest(result=result), patch.object(obj, "az", return_value=result) as az:
                with self.assertRaises(ValueError):
                    obj.create()
                self.assertEqual(az.call_count, 1)
                self.assertFalse(obj.receipt.exists())

    def test_creation_assigns_narrow_rule_and_different_boot_settings(self):
        obj = self.write_cfg()
        obj.key.write_text("test-only")
        Path(str(obj.key)+".pub").write_text("ssh-ed25519 AAAA fixture")

        def fake(*args, read=False):
            if read:
                if args[:2] == ("group", "exists"):
                    return False
                if args[:2] == ("group", "show"):
                    return json.loads(obj.receipt.read_text())["token"]
                if args[:2] == ("resource", "list"):
                    return []
                self.fail("unexpected read")

        with patch.object(obj, "az", side_effect=fake) as az:
            obj.create()
        calls = [c.args for c in az.call_args_list]
        rules = [c for c in calls if c[:4] == ("network", "nsg", "rule", "create")]
        self.assertEqual([(r[r.index("--access")+1], r[r.index("--source-address-prefixes")+1],
                           r[r.index("--destination-port-ranges")+1]) for r in rules],
                         [("Allow", self.cfg["ALLOWED_SSH_CIDR"], "22"), ("Deny", "*", "22")])
        vms = [c for c in calls if c[:2] == ("vm", "create")]
        self.assertEqual([c[c.index("--enable-secure-boot")+1] for c in vms], ["true", "false"])
        for c in vms:
            self.assertEqual(c[c.index("--enable-vtpm")+1], "true")
            self.assertEqual(c[c.index("--os-disk-delete-option")+1], "Detach")
            self.assertEqual(c[c.index("--nic-delete-option")+1], "Detach")

    def test_rollback_checks_complete_inventory_before_named_deletes(self):
        obj = self.write_cfg()
        token = str(uuid.uuid4())
        obj.state.mkdir()
        obj.receipt.write_text(json.dumps({"scope": obj.scope, "token": token}))
        resources = [{"id": rid, "tags": {"shirudoLab": token}} for rid in obj.inventory()[2:]]
        for extra in ({"id": obj.inventory()[0], "tags": {}}, {"id": "unrelated", "tags": {"shirudoLab": token}}):
            with patch.object(obj, "az", side_effect=[token, resources+[extra]]) as az, self.assertRaises(ValueError):
                obj.rollback()
            self.assertEqual(az.call_count, 2)
        with patch.object(obj, "az", side_effect=["wrong-token"]) as az, self.assertRaises(ValueError):
            obj.rollback()
        self.assertEqual(az.call_count, 1)
        with patch.object(obj, "az", side_effect=[token, resources]+[None]*len(resources)+[[]]) as az:
            with contextlib.redirect_stdout(io.StringIO()):
                obj.rollback()
            deletes = [c.args for c in az.call_args_list if c.args[:2] == ("resource", "delete")]
            self.assertEqual([x[-1] for x in deletes], [r["id"] for r in resources])
        with patch.dict(self.cfg, AZ_RESOURCE_GROUP="another"):
            foreign = self.write_cfg()
            with patch.object(foreign, "az", side_effect=AssertionError), self.assertRaises(ValueError):
                foreign.rollback()


class Transfers(Fixture):
    def test_control_context_excludes_sibling_modules_and_untracked_bytes(self):
        self.new_repo()
        names = build_controls.INPUTS
        for name in (*names, "upatches/java-sql-inj/app/fixture.txt", "testing/fixtures/unrelated.txt"):
            p = self.root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("from exact commit")
        self.git("add", "upatches", "testing")
        self.git("commit", "-qm", "fixture")
        (self.root / names[0]).write_text("not in the pinned commit")
        dest = self.root / "build"
        build_controls.export_inputs(self.root, "HEAD", dest)
        self.assertEqual({str(p.relative_to(dest)) for p in dest.rglob("*") if p.is_file()}, set(names))
        self.assertFalse(any(p.startswith("upatches/java-sql-inj/app/") for p in names))
        self.assertEqual((dest / names[0]).read_text(), "from exact commit")

    def test_control_pair_requires_correct_signed_type_and_bound_payload(self):
        n, d = "java-base64", "a"*64
        info = dict(name=n, signed_name=n, type="unload", payload_type="java", signature_len=4000,
                    unload_payload_sha256=d, payload_sha256="b"*64)
        self.assertEqual(build_controls.check_info(info, n, "unload", "java", d), "b"*64)
        for delta in (dict(signed_name="other"), dict(payload_type="bpf"), dict(signature_len=0),
                      dict(type="load"), dict(unload_payload_sha256="c"*64)):
            with self.assertRaises(ValueError):
                build_controls.check_info({**info, **delta}, n, "unload", "java", d)

    def test_control_manifest_admits_only_known_pairs_and_refuses_linked_parent(self):
        for name in bundle.CONTROL_FILES:
            p = self.root / name
            p.parent.mkdir(exist_ok=True)
            p.write_bytes(b"benign fixture")
        (self.root / "walkthrough/.signer").write_bytes(b"never transfer")
        lines = bundle.manifest(self.root, bundle.CONTROL_FILES).decode().splitlines()
        self.assertEqual(len(lines), 10)
        self.assertEqual([x.split("  ")[1] for x in lines], list(bundle.CONTROL_FILES))
        for name in ("walkthrough/.signer", "walkthrough/*.upatch", "other/basic.upatch", "kernel.deb"):
            with self.assertRaises(ValueError):
                bundle.open_artifact(self.root, name, bundle.CONTROL_FILES)
        (self.root / "walkthrough").rename(self.root / "unexpected-dir")
        (self.root / "walkthrough").symlink_to(self.root / "unexpected-dir", target_is_directory=True)
        with self.assertRaises(ValueError):
            bundle.manifest(self.root, bundle.CONTROL_FILES)

    def test_stage_reads_only_allowed_regular_blobs_at_commit(self):
        self.new_repo()
        names = lab.PROJECT_FILES["target"]
        for name in names:
            p = self.root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("committed\n")
        extra = self.root / "infra/target/extra"
        extra.write_text("tracked, not an input")
        self.git("add", "infra")
        self.git("commit", "-qm", "fixture")
        (self.root / names[0]).write_text("unstaged private edit")
        (self.root / "infra/target/.signer").write_text("untracked secret")
        self.write_cfg()
        data = lab.payload(self.root, "HEAD", "target")
        with tarfile.open(fileobj=io.BytesIO(data)) as tar:
            self.assertEqual(set(tar.getnames()), set(names))
            self.assertEqual(tar.extractfile(names[0]).read(), b"committed\n")
        (self.root / names[0]).unlink()
        (self.root / names[0]).symlink_to(extra)
        self.git("add", names[0])
        self.git("commit", "-qm", "linked input")
        with self.assertRaises(ValueError):
            lab.payload(self.root, "HEAD", "target")

    def test_bundle_refuses_private_paths_links_and_oversize(self):
        key = self.root / ".signer"
        key.write_text("private")
        for name in (".signer", "../.signer", "/etc/passwd", "sub/target.deb", "*.deb"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                bundle.open_artifact(self.root, name)
        (self.root / "target.deb").symlink_to(key)
        with self.assertRaises(OSError):
            bundle.open_artifact(self.root, "target.deb")
        os.link(key, self.root / "kernel.deb")
        with self.assertRaises(ValueError):
            bundle.open_artifact(self.root, "kernel.deb")
        (self.root / "SHA256SUMS").write_bytes(b"x"*(65536+1))
        with self.assertRaises(ValueError):
            bundle.open_artifact(self.root, "SHA256SUMS")

    def test_real_sign_stream_receive_verify_and_tamper_rejection(self):
        tool = [sys.executable, str(ROOT / "infra/bundle.py")]
        operator, target = self.root / "operator", self.root / "target"
        (operator / "shirudo-keys").mkdir(parents=True)
        target.mkdir()
        out = Path("build/target-bundle")
        (operator / out).mkdir(parents=True)
        for name in bundle.FILES:
            (operator / out / name).write_bytes(("benign fixture: "+name).encode())
        (operator / out / ".hidden-signer").write_text("never a transport input")

        def run(home, *args, data=None, ok=True):
            p = subprocess.run(tool+list(args), input=data, capture_output=True, env={**os.environ, "HOME": str(home)})
            self.assertEqual(p.returncode == 0, ok, p.stderr.decode())
            return p.stdout

        run(operator, "seal")
        key = run(operator, "public-signer")
        run(target, "begin-receive", data=key)
        run(target, "begin-receive", data=key, ok=False)  # No overwrites.
        run(operator, "send", ".hidden-signer", ok=False)
        for name in bundle.FILES+bundle.META:
            run(target, "receive", name, data=run(operator, "send", name))
        run(target, "verify")
        self.assertEqual({p.name for p in (target / out).iterdir()}, set(bundle.FILES+bundle.META))
        controls = Path("build/shields")
        for name in bundle.CONTROL_FILES:
            path = operator / controls / name
            path.parent.mkdir(exist_ok=True, parents=True)
            path.write_bytes(("benign control: "+name).encode())
        run(operator, "controls", "seal")
        run(target, "controls", "begin-receive", data=key)
        for name in bundle.CONTROL_FILES+bundle.META:
            run(target, "controls", "receive", name, data=run(operator, "controls", "send", name))
        run(target, "controls", "verify")
        run(operator, "controls", "send", "target.deb", ok=False)
        (target / "build/control-inbox" / bundle.META[1]).write_bytes((target / out / bundle.META[1]).read_bytes())
        run(target, "controls", "verify", ok=False)  # Wrong signed namespace/contents.
        (operator / out / "kernel.deb").write_bytes(b"unsigned")
        self.assertEqual(run(operator, "send", "kernel.deb", ok=False), b"")
        (target / out / "kernel.deb").write_bytes(b"edited")
        run(target, "verify", ok=False)
        (target / out / "SHA256SUMS").write_bytes(bundle.manifest(target / out))
        run(target, "verify", ok=False)  # Rehashing without the transport private key is not enough.


class Publication(Fixture):
    def test_ignore_private_files_even_under_admitted_directories(self):
        self.new_repo()
        shutil.copyfile(ROOT / ".gitignore", self.root / ".gitignore")
        paths = [".scratch/social.md", ".env", ".state/ip-guest", "infra/.env.example",
                 "demos/.env.local", "docs/.scratch/private.md", "infra/keys/config.secret",
                 "tools/shirudo-keys/.hidden", "infra/.ssh/id_rsa", "docs/provision.log",
                 "demos/.keys/signer", "tools/operator.pub", "demos/old-draft.sh", "demos/archive/old-integration.py",
                 "shields/prototype/Beefile", "shields/old-policy.c"]
        self.assertEqual(set(self.git("check-ignore", *paths).decode().splitlines()), set(paths))
        self.assertTrue(all(check_leaks.denied(p) for p in paths))
        self.assertFalse(check_leaks.denied(".env.example"))
        self.assertFalse(check_leaks.denied("demos/controls/run.sh"))
        self.assertEqual(subprocess.run(["git", "-C", str(self.root), "check-ignore", "-q", "demos/controls/run.sh"]).returncode, 1)

    def test_index_and_history_catch_renames_and_redact_findings(self):
        self.new_repo()
        (self.root / "README.md").write_text("okay")
        self.git("add", "README.md")
        self.git("commit", "-qm", "first")
        (self.root / ".scratch").mkdir()
        self.git("mv", "README.md", ".scratch/example")
        secret = b"unique-private-fixture"
        (self.root / "note.txt").write_bytes(secret)
        self.git("add", "note.txt")
        with patch.object(check_leaks, "REPO", self.root):
            for staged in (True, False):
                if not staged:
                    self.git("commit", "-qm", "second")
                findings = " ".join(check_leaks.scan([secret], staged=staged))
                self.assertIn("disallowed path", findings)
                self.assertIn("private content", findings)
                self.assertNotIn(secret.decode(), findings)
                self.assertNotIn(".scratch", findings)


if __name__ == "__main__":
    unittest.main()
