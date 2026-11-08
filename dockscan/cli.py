import argparse
import json
from pathlib import Path

from .collectors import collect
from .agent_server import serve
from .interactive import interactive
from .pki import enroll_step_ca, create_jwk_provisioner
from .blueprint import create_blueprint, inspect_blueprint, sign_blueprint, verify_signature, recovery_plan
from .models import HostInventory
from .encsec import decrypt as decrypt_encsec, encrypt as encrypt_encsec, inspect as inspect_encsec
from .enrollment import await_enrollment, enroll_outbound
from .engine import run_session, resume_session
from .backups import verify_backup
from .security import private_file
from .trust import add as trust_add, load as trust_load, revoke as trust_revoke
from .migrations import preview as migration_preview, migrate as migrate_blueprint
from .evidence import create as create_evidence
from .staticify import staticify
from .update import check as update_check, apply as update_apply
from .recovery import write_recovery_kit
from .remote import collect_remote


def service_set(value: str) -> set[str]:
    known = {"step-ca", "tailscale"}
    requested = {part.strip() for part in value.split(",") if part.strip()}
    unknown = requested - known
    if unknown:
        raise argparse.ArgumentTypeError("unsupported services: " + ", ".join(sorted(unknown)))
    return requested


def remote_spec(value: str) -> tuple[str, str]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("remote must be NAME=SSH_TARGET")
    return tuple(value.split("=", 1))


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dockscan", description="Create a Docker homelab recovery kit")
    commands = p.add_subparsers(dest="action", required=True)
    scan = commands.add_parser("scan", help="scan hosts and write a recovery kit")
    scan.add_argument("--output", required=True, type=Path)
    scan.add_argument("--name", help="local host display name")
    scan.add_argument("--remote", action="append", type=remote_spec, default=[], metavar="NAME=SSH_TARGET")
    scan.add_argument("--remote-command", default="dockscan", help="agent command on remote hosts")
    scan.add_argument("--services", type=service_set, default=set())
    scan.add_argument("--include-secrets", action="store_true")
    scan.add_argument("--ignore-secrets", action="store_true", help="redact suspected secrets without prompting")
    scan.add_argument("--blueprint", type=Path, help="also write a portable .dsrcvr recovery blueprint")
    scan.add_argument("--environment", default="DockScan environment", help="blueprint environment name")
    scan.add_argument("--encrypted-secrets", type=Path, help="age-encrypted .encsec file to embed in the blueprint")
    talk = commands.add_parser("interact", help="interactive controller for TCP inventory agents")
    talk.add_argument("--output", required=True, type=Path)
    talk.add_argument("--port", type=int, default=45832)
    talk.add_argument("--services", type=service_set, default=set())
    talk.add_argument("--ignore-secrets", action="store_true")
    talk.add_argument("--tls-ca", help="PEM CA bundle used to verify the remote agent")
    talk.add_argument("--tls-cert", help="PEM client certificate for mutual TLS")
    talk.add_argument("--tls-key", help="PEM client private key for mutual TLS")
    talk.add_argument("--tls-server-name", help="expected agent certificate DNS name; defaults to IP address")
    talk.add_argument("--accept-insecure", action="store_true", help="allow unsigned/unverified agents (unsafe)")
    talk.add_argument("--i-understand-insecure", action="store_true", help="required with --accept-insecure")
    agent = commands.add_parser("agent", help="emit an inventory for SSH orchestration")
    agent.add_argument("--json", action="store_true")
    agent.add_argument("--serve", action="store_true", help="serve inventory requests over authenticated TCP")
    agent.add_argument("--bind", default="127.0.0.1")
    agent.add_argument("--port", type=int, default=45832)
    agent.add_argument("--token", help="required shared token when using --serve")
    agent.add_argument("--token-file", type=Path, help="mode-0600 token file for direct serving or outbound enrollment")
    agent.add_argument("--tls-cert", help="PEM server certificate")
    agent.add_argument("--tls-key", help="PEM server private key")
    agent.add_argument("--tls-ca", help="PEM CA bundle for client-certificate verification")
    agent.add_argument("--accept-insecure", action="store_true", help="permit unsigned peers; unsafe")
    agent.add_argument("--name")
    agent.add_argument("--services", type=service_set, default=set())
    agent.add_argument("--include-secrets", action="store_true")
    agent.add_argument("--ignore-secrets", action="store_true")
    agent.add_argument("--enroll", action="store_true", help="initiate a single-use outbound enrollment to a controller")
    agent.add_argument("--controller", help="controller HOST:PORT for --enroll")
    agent.add_argument("--allowed-client-name", action="append", default=[], help="trusted mTLS client certificate CN; repeat as needed")
    agent.add_argument("--i-understand-insecure", action="store_true", help="required with --accept-insecure")
    orchestrator = commands.add_parser("orchestrator", help="approve an outbound agent enrollment")
    orchestrator_commands = orchestrator.add_subparsers(dest="orchestrator_action", required=True)
    enroll_wait = orchestrator_commands.add_parser("enroll", help="wait for one outbound agent using a short-lived token")
    enroll_wait.add_argument("--bind", default="0.0.0.0")
    enroll_wait.add_argument("--port", type=int, default=45833)
    enroll_wait.add_argument("--timeout", type=int, default=600)
    enroll_wait.add_argument("--output", type=Path, required=True, help="write approved inventory JSON")
    enroll_wait.add_argument("--tls-ca", type=Path)
    enroll_wait.add_argument("--tls-cert", type=Path)
    enroll_wait.add_argument("--tls-key", type=Path)
    enroll_wait.add_argument("--accept-insecure", action="store_true")
    enroll_wait.add_argument("--i-understand-insecure", action="store_true")
    step = commands.add_parser("step-ca", help="bootstrap and enroll TLS identities using the Step CLI")
    step_commands = step.add_subparsers(dest="step_action", required=True)
    enroll = step_commands.add_parser("enroll", help="bootstrap Step CA trust and issue a PEM certificate")
    enroll.add_argument("--ca-url", required=True)
    enroll.add_argument("--fingerprint", required=True)
    enroll.add_argument("--name", required=True, help="certificate common name, e.g. John-PC-1")
    enroll.add_argument("--cert", type=Path, help="output certificate path; defaults to /etc/dockscan/<name>.pem")
    enroll.add_argument("--key", type=Path, help="output private-key path; defaults to /etc/dockscan/<name>-key.pem")
    enroll.add_argument("--san", action="append", default=[], help="DNS name or IP SAN; repeat as needed")
    enroll.add_argument("--dry-run", action="store_true", help="validate and show no token-bearing commands")
    provisioner = step_commands.add_parser("provisioner", help="manage local CA provisioners using the supported Step CLI")
    provisioner_commands = provisioner.add_subparsers(dest="provisioner_action", required=True)
    create_provisioner = provisioner_commands.add_parser("create", help="create a local password-protected JWK provisioner and restart step-ca")
    create_provisioner.add_argument("--name", required=True)
    create_provisioner.add_argument("--ca-config", type=Path, help="explicit ca.json path; auto-detected on apply when omitted")
    create_provisioner.add_argument("--password-file", type=Path, default=Path("/etc/step-ca/secrets/dockscan-provisioner-password"))
    create_provisioner.add_argument("--service", default="step-ca")
    create_provisioner.add_argument("--dry-run", action="store_true")
    create_provisioner.add_argument("--apply", action="store_true")
    create_provisioner.add_argument("--confirm", help="must exactly match --name when applying")
    blueprint = commands.add_parser("blueprint", help="create or safely inspect .dsrcvr recovery blueprints")
    blueprint_commands = blueprint.add_subparsers(dest="blueprint_action", required=True)
    create = blueprint_commands.add_parser("create", help="package an existing DockScan inventory into a blueprint")
    create.add_argument("--inventory", type=Path, required=True, help="inventory.json produced by dockscan scan")
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--environment", default="DockScan environment")
    create.add_argument("--encrypted-secrets", type=Path, help="age-encrypted .encsec file to embed")
    inspect = blueprint_commands.add_parser("inspect", help="validate checksums and inspect in audit mode")
    inspect.add_argument("file", type=Path)
    sign = blueprint_commands.add_parser("sign", help="sign a checksummed blueprint with an external OpenSSL private key")
    sign.add_argument("file", type=Path)
    sign.add_argument("--private-key", type=Path, required=True)
    sign.add_argument("--public-key", type=Path, required=True, help="matching public key; fingerprint is bound into the signature")
    sign.add_argument("--signer", required=True, help="human-readable trusted-signer identifier")
    verify = blueprint_commands.add_parser("verify", help="verify a blueprint signature against a trusted public key")
    verify.add_argument("file", type=Path)
    verify.add_argument("--public-key", type=Path, required=True)
    plan = blueprint_commands.add_parser("plan", help="validate and display the dependency-ordered audit plan")
    plan.add_argument("file", type=Path)
    run = blueprint_commands.add_parser("run", help="create an auditable audit/dry-run recovery session")
    run.add_argument("file", type=Path)
    run.add_argument("--mode", choices=("audit", "dry-run", "recovery"), default="audit")
    run.add_argument("--session-dir", type=Path, default=Path("./dockscan-sessions"))
    run.add_argument("--approve", action="store_true", help="required for recovery mode")
    run.add_argument("--trust-store", type=Path)
    run.add_argument("--trusted-fingerprint")
    run.add_argument("--approve-plan-hash", help="must equal the current signed plan hash in recovery mode")
    resume = blueprint_commands.add_parser("resume", help="resume an audit session without repeating checkpoints")
    resume.add_argument("session", type=Path)
    resume.add_argument("--retry", action="append", default=[], help="task ID to mark for retry; repeat as needed")
    trust = blueprint_commands.add_parser("trust", help="manage local trusted blueprint signers")
    trust_commands = trust.add_subparsers(dest="trust_action", required=True)
    trust_add_cmd = trust_commands.add_parser("add")
    trust_add_cmd.add_argument("--store", type=Path, required=True)
    trust_add_cmd.add_argument("--public-key", type=Path, required=True)
    trust_add_cmd.add_argument("--signer", required=True)
    trust_add_cmd.add_argument("--expires-at")
    trust_add_cmd.add_argument("--replaces")
    trust_list = trust_commands.add_parser("list")
    trust_list.add_argument("--store", type=Path, required=True)
    trust_revoke_cmd = trust_commands.add_parser("revoke")
    trust_revoke_cmd.add_argument("--store", type=Path, required=True)
    trust_revoke_cmd.add_argument("--fingerprint", required=True)
    migrate = blueprint_commands.add_parser("migrate", help="preview or copy-migrate a blueprint; never alters the source")
    migrate.add_argument("file", type=Path)
    migrate.add_argument("--output", type=Path, help="required to write the migrated copy")
    evidence = commands.add_parser("evidence", help="create redacted recovery evidence bundles")
    evidence_commands = evidence.add_subparsers(dest="evidence_action", required=True)
    evidence_create = evidence_commands.add_parser("create")
    evidence_create.add_argument("--blueprint", type=Path, required=True)
    evidence_create.add_argument("--session", type=Path, required=True)
    evidence_create.add_argument("--output", type=Path, required=True)
    evidence_create.add_argument("--private-key", type=Path, required=True)
    evidence_create.add_argument("--signer", required=True)
    encsec = commands.add_parser("encsec", help="create and inspect age-encrypted recovery-secret envelopes")
    encsec_commands = encsec.add_subparsers(dest="encsec_action", required=True)
    encrypt = encsec_commands.add_parser("encrypt", help="encrypt JSON secrets to an .encsec file")
    encrypt.add_argument("--input", type=Path, required=True, help="JSON object containing secret values")
    encrypt.add_argument("--output", type=Path, required=True)
    encrypt.add_argument("--recipient", action="append", required=True, help="age recipient; repeat for recovery recipients")
    decrypt = encsec_commands.add_parser("decrypt", help="decrypt .encsec to a protected local JSON file")
    decrypt.add_argument("--input", type=Path, required=True)
    decrypt.add_argument("--output", type=Path, required=True, help="required; plaintext is never printed")
    decrypt.add_argument("--identity", type=Path, action="append", required=True, help="age identity file")
    encsec_inspect = encsec_commands.add_parser("inspect", help="show only encrypted-envelope metadata")
    encsec_inspect.add_argument("file", type=Path)
    backup = commands.add_parser("backup", help="read-only backup availability verification")
    backup_commands = backup.add_subparsers(dest="backup_action", required=True)
    backup_verify = backup_commands.add_parser("verify", help="verify Restic, Borg, age archive, or S3 availability")
    backup_verify.add_argument("--type", choices=("restic", "borg", "age", "s3"), required=True)
    backup_verify.add_argument("--location", help="repository or archive path")
    backup_verify.add_argument("--bucket")
    backup_verify.add_argument("--key")
    site = commands.add_parser("staticify", help="render generated Markdown documentation as a static HTML site")
    site.add_argument("--input", type=Path, required=True, help="recovery-kit docs directory")
    site.add_argument("--output", type=Path, required=True, help="static site directory")
    site.add_argument("--title", default="DockScan system documentation")
    update = commands.add_parser("update", help="check or apply a pinned DockScan release update")
    update.add_argument("--repository", default="https://github.com/Danng-Dev/DockScan.git")
    update.add_argument("--ref", help="immutable release tag or commit required with --apply")
    update.add_argument("--check", action="store_true", help="list available release tags")
    update.add_argument("--apply", action="store_true", help="install --ref after explicit confirmation")
    update.add_argument("--verify-tag", action="store_true", help="verify a signed Git release tag")
    update.add_argument("--service", action="store_true", help="also install the optional agent systemd template")
    return p


def main() -> None:
    args = parser().parse_args()
    if getattr(args, "accept_insecure", False) and not getattr(args, "i_understand_insecure", False):
        parser.error("--accept-insecure requires --i-understand-insecure")
    if args.action == "step-ca":
        if args.step_action == "enroll":
            cert = args.cert or Path("/etc/dockscan") / f"{args.name}.pem"
            key = args.key or Path("/etc/dockscan") / f"{args.name}-key.pem"
            result = enroll_step_ca(args.ca_url, args.fingerprint, args.name, cert, key, args.san, None, args.dry_run)
            if args.dry_run:
                print("Step CA enrollment validated. Commands will run without printing sensitive token values.")
            else:
                print(f"Issued certificate {cert} and private key {key} for {args.name}.")
        else:
            print(json.dumps(create_jwk_provisioner(args.name, args.ca_config, args.password_file, args.service, args.apply, args.confirm, args.dry_run), indent=2))
        return
    if args.action == "blueprint":
        if args.blueprint_action == "create":
            payload = json.loads(args.inventory.read_text())
            hosts = [HostInventory(**host) for host in payload["hosts"]]
            create_blueprint(args.output, hosts, args.environment, args.encrypted_secrets)
            print(f"Recovery blueprint written to {args.output.resolve()}")
        elif args.blueprint_action == "inspect":
            print(json.dumps(inspect_blueprint(args.file), indent=2))
        elif args.blueprint_action == "sign":
            sign_blueprint(args.file, args.private_key, args.signer, args.public_key)
            print(f"Signed recovery blueprint {args.file.resolve()}")
        elif args.blueprint_action == "verify":
            result = verify_signature(args.file, args.public_key)
            print(json.dumps(result, indent=2))
            if not result["valid"]:
                raise SystemExit(1)
        elif args.blueprint_action == "plan":
            result = recovery_plan(args.file)
            print(json.dumps(result, indent=2))
            if not result["valid"]:
                raise SystemExit(1)
        elif args.blueprint_action == "run":
            result = run_session(args.file, args.session_dir, args.mode, args.approve, args.trusted_fingerprint, args.trust_store, args.approve_plan_hash)
            print(json.dumps(result, indent=2))
        elif args.blueprint_action == "trust":
            if args.trust_action == "add":
                print(json.dumps(trust_add(args.store, args.public_key, args.signer, args.expires_at, args.replaces), indent=2))
            elif args.trust_action == "list":
                print(json.dumps(trust_load(args.store), indent=2))
            else:
                trust_revoke(args.store, args.fingerprint)
                print("Trusted signer revoked.")
        elif args.blueprint_action == "migrate":
            if args.output:
                print(f"Migrated copy written to {migrate_blueprint(args.file, args.output).resolve()}")
            else:
                print(json.dumps(migration_preview(args.file), indent=2))
        else:
            print(json.dumps(resume_session(args.session, args.retry), indent=2))
        return
    if args.action == "evidence":
        print(f"Evidence bundle written to {create_evidence(args.blueprint, args.session, args.output, args.private_key, args.signer).resolve()}")
        return
    if args.action == "encsec":
        if args.encsec_action == "encrypt":
            encrypt_encsec(args.input, args.output, args.recipient)
            print(f"Encrypted secret envelope written to {args.output.resolve()}")
        elif args.encsec_action == "decrypt":
            decrypt_encsec(args.input, args.output, args.identity)
            print(f"Decrypted secret envelope written to protected local file {args.output.resolve()}")
        else:
            print(json.dumps(inspect_encsec(args.file), indent=2))
        return
    if args.action == "backup":
        result = verify_backup(args.type, args.location, args.bucket, args.key)
        print(json.dumps(result, indent=2))
        if not result["available"]:
            raise SystemExit(1)
        return
    if args.action == "staticify":
        pages = staticify(args.input, args.output, args.title)
        print(f"Static documentation site written to {args.output.resolve()} ({len(pages) - 1} pages plus index)")
        return
    if args.action == "update":
        if args.check:
            print(json.dumps({"available_versions": update_check(args.repository)}, indent=2))
            return
        if not args.apply or not args.ref:
            parser.error("update requires --check, or both --apply and --ref")
        extras = ["--service"] if args.service else []
        print(f"Updated DockScan to commit {update_apply(args.repository, args.ref, args.verify_tag, extras)}")
        return
    if args.action == "agent":
        if args.enroll:
            if not args.controller or not args.token_file:
                parser.error("agent --enroll requires --controller and --token-file")
            if not args.token_file.is_file():
                parser.error("enrollment token file does not exist")
            if __import__("os").name != "nt" and args.token_file.stat().st_mode & 0o077:
                parser.error("enrollment token file permissions must be 0600 or stricter")
            enroll_outbound(args.controller, args.token_file.read_text().strip(), args.name, args.services, Path(args.tls_ca) if args.tls_ca else None, Path(args.tls_cert) if args.tls_cert else None, Path(args.tls_key) if args.tls_key else None, args.accept_insecure)
            print("Outbound enrollment approved by controller.")
            return
        if args.serve:
            if not args.token and not args.token_file:
                parser.error("agent --serve requires --token or --token-file")
            if args.token_file:
                if not args.token_file.is_file():
                    parser.error("token file does not exist")
                if __import__("os").name != "nt" and args.token_file.stat().st_mode & 0o077:
                    parser.error("token file permissions must be 0600 or stricter")
                token = args.token_file.read_text().strip()
            else:
                token = args.token
            serve(args.bind, args.port, token, args.accept_insecure, args.tls_cert, args.tls_key, args.tls_ca, set(args.allowed_client_name))
            return
        if not args.json:
            parser.error("agent requires --json or --serve")
        print(json.dumps(collect(args.name, args.include_secrets, args.services, "ignore" if args.ignore_secrets else "prompt").to_dict()))
        return
    if args.action == "orchestrator":
        inventory = await_enrollment(args.bind, args.port, args.timeout, args.tls_cert, args.tls_key, args.tls_ca, args.accept_insecure)
        args.output.write_text(json.dumps(inventory, indent=2) + "\n")
        private_file(args.output)
        print(f"Approved agent inventory written to {args.output.resolve()}")
        return
    if args.action == "interact":
        interactive(args.output, args.port, args.services, "ignore" if args.ignore_secrets else "prompt", args.tls_ca, args.tls_cert, args.tls_key, args.accept_insecure, args.tls_server_name)
        return
    hosts = [collect(args.name, args.include_secrets, args.services, "ignore" if args.ignore_secrets else "prompt")]
    hosts.extend(collect_remote(name, target, args.remote_command, args.services, args.include_secrets) for name, target in args.remote)
    write_recovery_kit(args.output, hosts)
    if args.blueprint:
        create_blueprint(args.blueprint, hosts, args.environment, args.encrypted_secrets)
        print(f"Recovery blueprint written to {args.blueprint.resolve()}")
    print(f"Recovery kit written to {args.output.resolve()}")


def safe_main() -> None:
    try:
        main()
    except KeyboardInterrupt:
        print("\nDockScan cancelled by operator; no recovery operation was executed.", file=__import__("sys").stderr)
        raise SystemExit(130)


if __name__ == "__main__":
    safe_main()
