"""Outbound, single-use agent enrollment. The agent initiates the connection."""
import hmac
import json
import secrets
import socket
import socketserver
import ssl
import time
from pathlib import Path

from .collectors import collect
from .pki import subject_common_name
from .security import read_json_line, private_file


class EnrollmentHandler(socketserver.StreamRequestHandler):
    def setup(self):
        self.request.settimeout(15)
        super().setup()

    def handle(self) -> None:
        request = read_json_line(self.rfile)
        if time.time() > self.server.expires_at or self.server.used or not hmac.compare_digest(str(request.get("token", "")), self.server.token):
            self.wfile.write(b'{"accepted":false,"reason":"invalid, expired, or already-used enrollment token"}\n')
            return
        cert = self.request.getpeercert() if isinstance(self.request, ssl.SSLSocket) else None
        identity = subject_common_name(cert) or request.get("name") or self.client_address[0]
        answer = input(f"Outbound agent '{identity}' from {self.client_address[0]} requests enrollment. Approve? [Y/n] ").strip().lower()
        if answer not in ("", "y", "yes"):
            self.wfile.write(b'{"accepted":false,"reason":"rejected by operator"}\n')
            return
        self.server.used = True
        self.server.inventory = request.get("inventory")
        self.wfile.write(b'{"accepted":true}\n')


class EnrollmentServer(socketserver.TCPServer):
    allow_reuse_address = True

    def __init__(self, address, token, expires_at, context=None):
        self.token, self.expires_at, self.used, self.inventory = token, expires_at, False, None
        super().__init__(address, EnrollmentHandler)
        if context:
            self.socket = context.wrap_socket(self.socket, server_side=True)


def server_context(cert: Path | None, key: Path | None, ca: Path | None, accept_insecure: bool) -> ssl.SSLContext | None:
    if not cert and accept_insecure:
        return None
    if not (cert and key and ca):
        raise ValueError("controller TLS cert, key, and CA are required unless --accept-insecure is set")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    context.load_verify_locations(cafile=ca)
    context.verify_mode = ssl.CERT_OPTIONAL if accept_insecure else ssl.CERT_REQUIRED
    return context


def await_enrollment(bind: str, port: int, timeout_seconds: int, cert: Path | None = None, key: Path | None = None, ca: Path | None = None, accept_insecure: bool = False) -> dict:
    token = secrets.token_urlsafe(32)
    context = server_context(cert, key, ca, accept_insecure)
    with EnrollmentServer((bind, port), token, time.time() + timeout_seconds, context) as server:
        server.timeout = min(timeout_seconds, 1)
        print(f"Enrollment token (single-use, expires in {timeout_seconds}s): {token}")
        print(f"Transfer it out-of-band to a mode-0600 file, then run: dockscan agent --enroll --controller <controller-host>:{port} --token-file /secure/enrollment-token")
        deadline = time.time() + timeout_seconds
        while time.time() < deadline and not server.used:
            server.handle_request()
        if not server.inventory:
            raise TimeoutError("no approved agent enrolled before token expiry")
        return server.inventory


def enroll_outbound(controller: str, token: str, name: str | None, services: set[str], tls_ca: Path | None = None, tls_cert: Path | None = None, tls_key: Path | None = None, accept_insecure: bool = False) -> None:
    host, port_text = controller.rsplit(":", 1)
    raw = socket.create_connection((host, int(port_text)), timeout=10)
    if tls_ca or tls_cert or tls_key:
        context = ssl._create_unverified_context() if accept_insecure else ssl.create_default_context(cafile=str(tls_ca) if tls_ca else None)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        if not accept_insecure and not tls_ca:
            raise ValueError("--tls-ca is required unless --accept-insecure is set")
        if tls_cert and tls_key:
            context.load_cert_chain(tls_cert, tls_key)
        connection = context.wrap_socket(raw, server_hostname=host)
    elif accept_insecure:
        connection = raw
    else:
        raise ValueError("TLS options are required unless --accept-insecure is set")
    with connection:
        payload = {"token": token, "name": name, "inventory": collect(name, False, services, "ignore").to_dict()}
        connection.sendall((json.dumps(payload) + "\n").encode())
        response = json.loads(connection.makefile("rb").readline().decode())
    if not response.get("accepted"):
        raise RuntimeError(response.get("reason", "enrollment rejected"))
