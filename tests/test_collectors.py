import unittest
import socket
import threading
import os
from pathlib import Path
from tempfile import TemporaryDirectory

from dockscan.collectors import redact_environment
from dockscan.cli import remote_spec, service_set
from dockscan.models import HostInventory
from dockscan.recovery import write_recovery_kit
from dockscan.agent_server import InventoryServer
from dockscan.blueprint import create_blueprint, inspect_blueprint, recovery_plan
from dockscan.engine import run_session, resume_session
from dockscan.verification import os_compatibility
from dockscan.migrations import migrate
from dockscan.evidence import create as create_evidence
from dockscan.staticify import staticify
from zipfile import ZipFile
import json


class CollectorTests(unittest.TestCase):
    def test_redacts_sensitive_values(self):
        self.assertEqual(
            redact_environment(["TOKEN=abc", "PORT=80"], False),
            ["TOKEN=__REDACTED__", "PORT=80"],
        )


    def test_parsers(self):
        self.assertEqual(remote_spec("nas=user@nas"), ("nas", "user@nas"))
        self.assertEqual(service_set("tailscale,step-ca"), {"tailscale", "step-ca"})

    def test_writes_runnable_host_task_file(self):
        container = {"Name": "/app", "Config": {"Image": "example/app", "Env": ["PORT=80"]}, "HostConfig": {"RestartPolicy": {"Name": "always"}}}
        host = HostInventory(name="node-1", hostname="node-1", os_release={}, kernel="x", docker_version="1", containers=[container])
        # Keep test artifacts inside the writable project workspace.
        with TemporaryDirectory(dir=Path.cwd()) as directory:
            write_recovery_kit(Path(directory), [host])
            generated = Path(directory, "ansible", "generated", "node-1.yml").read_text()
            include = Path(directory, "ansible", "restore-containers.yml").read_text()
            self.assertIn("community.docker.docker_container", generated)
            self.assertIn("generated/{{ inventory_hostname }}.yml", include)
            self.assertTrue(Path(directory, "docs", "SYSTEM_OVERVIEW.md").is_file())
            self.assertTrue(Path(directory, "docs", "MACHINE_node-1.md").is_file())

    @unittest.skipIf(os.name == "nt", "Windows sandbox blocks local TCP listeners")
    def test_agent_rejects_bad_token(self):
        server = InventoryServer(("127.0.0.1", 0), "correct-token", accept_insecure=True)
        thread = threading.Thread(target=server.handle_request)
        thread.start()
        try:
            with socket.create_connection(server.server_address, timeout=2) as client:
                client.sendall(b'{"action":"inventory","token":"wrong"}\n')
                self.assertIn("authentication failed", client.makefile("rb").readline().decode())
        finally:
            thread.join(timeout=2)
            server.server_close()

    def test_blueprint_is_portable_and_checksummed(self):
        host = HostInventory(name="node-1", hostname="node-1", os_release={"ID": "debian"}, kernel="x", docker_version="1")
        with TemporaryDirectory(dir=Path.cwd()) as directory:
            blueprint = Path(directory, "lab.dsrcvr")
            create_blueprint(blueprint, [host], "Test lab")
            result = inspect_blueprint(blueprint)
            self.assertTrue(result["valid"])
            self.assertEqual(result["manifest"]["format"], "dsrcvr")
            self.assertFalse(result["execution_allowed"])
            self.assertTrue(recovery_plan(blueprint)["valid"])

    def test_blueprint_embeds_encrypted_secret_blob_without_reading_it(self):
        host = HostInventory(name="node-1", hostname="node-1", os_release={}, kernel="x", docker_version="1")
        with TemporaryDirectory(dir=Path.cwd()) as directory:
            envelope = Path(directory, "lab.encsec")
            envelope.write_bytes(b"age-encryption.org/v1\n-> X25519 test\n")
            blueprint = Path(directory, "lab.dsrcvr")
            create_blueprint(blueprint, [host], encrypted_secrets=envelope)
            with ZipFile(blueprint) as archive:
                self.assertEqual(archive.read("requirements/secrets.encsec"), envelope.read_bytes())
            self.assertTrue(inspect_blueprint(blueprint)["valid"])

    def test_audit_session_is_resumable(self):
        host = HostInventory(name="node-1", hostname="node-1", os_release={}, kernel="x", docker_version="1")
        with TemporaryDirectory(dir=Path.cwd()) as directory:
            directory = Path(directory)
            blueprint = directory / "lab.dsrcvr"
            create_blueprint(blueprint, [host])
            session = run_session(blueprint, directory / "sessions")
            session_file = next((directory / "sessions").glob("*.json"))
            resumed = resume_session(session_file, [session["tasks"][0]["id"]])
            self.assertEqual(resumed["status"], "resumed-audit")
            self.assertEqual(resumed["tasks"][0]["status"], "planned")

    def test_blueprint_rejects_duplicate_archive_entries(self):
        with TemporaryDirectory(dir=Path.cwd()) as directory:
            archive = Path(directory, "bad.dsrcvr")
            manifest = {"format": "dsrcvr", "format_version": "1.0.0", "checksums": {}}
            with ZipFile(archive, "w") as zip_file:
                zip_file.writestr("manifest.json", json.dumps(manifest))
                zip_file.writestr("manifest.json", json.dumps(manifest))
            with self.assertRaises(ValueError):
                inspect_blueprint(archive)

    def test_os_mismatch_is_flagged(self):
        result = os_compatibility({"os": "definitely-not-this-os", "version": "0", "architecture": "other"})
        self.assertTrue(result["mismatch"])
        self.assertIn("FLAGGED OS", result["message"])

    def test_migration_and_evidence_do_not_modify_source(self):
        host = HostInventory(name="node-1", hostname="node-1", os_release={}, kernel="x", docker_version="1")
        with TemporaryDirectory(dir=Path.cwd()) as directory:
            directory = Path(directory)
            source = directory / "source.dsrcvr"
            create_blueprint(source, [host])
            source_hash = source.read_bytes()
            migrated = directory / "migrated.dsrcvr"
            migrate(source, migrated)
            self.assertEqual(source.read_bytes(), source_hash)
            session = run_session(source, directory / "sessions")
            session_file = next((directory / "sessions").glob("*.json"))
            evidence = directory / "evidence.zip"
            create_evidence(source, session_file, evidence)
            with ZipFile(evidence) as archive:
                self.assertIn("evidence.json", archive.namelist())

    def test_staticify_renders_markdown_site(self):
        with TemporaryDirectory(dir=Path.cwd()) as directory:
            directory = Path(directory)
            docs = directory / "docs"; docs.mkdir()
            (docs / "SYSTEM_OVERVIEW.md").write_text("# Overview\n\n| Host | State |\n|---|---|\n| pi | ready |\n\n```bash\ndockscan scan\n```\n")
            (docs / "RECOVERY.md").write_text("# Recovery\n\n- Review plan\n")
            result = staticify(docs, directory / "site")
            page = (directory / "site" / "index.html").read_text()
            self.assertEqual(len(result), 3)
            self.assertIn("<table>", page)
            self.assertIn("dockscan scan", page)
