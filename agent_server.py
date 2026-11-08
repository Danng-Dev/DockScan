"""Minimal token-authenticated inventory agent for a trusted LAN or VPN."""
import hmac
import json
import socketserver
import ssl
import threading

from .collectors import collect
from .pki import subject_common_name
from .security import read_json_line


class InventoryHandler(socketserver.StreamRequestHandler):
    def setup(self):
        self.request.settimeout(15)
        super().setup()

    def handle(self) -> None:
        try:
            request = read_json_line(self.rfile)
            if not hmac.compare_digest(str(request.get("token", "")), self.server.token):
                self.wfile.write(b'{"error":"authentication failed"}\n')
                return
            certificate = self.request.getpeercert() if isinstance(self.request, ssl.SSLSocket) else None
            identity = subject_common_name(certificate)
            if not self.server.accept_insecure:
                if not identity or (self.server.allowed_names and identity not in self.server.allowed_names):
                    self.wfile.write(b'{"error":"unapproved client certificate identity"}\n')
                    return
                answer = input(f"Verified device '{identity}' is connecting. Allow inventory request? [Y/n] ").strip().lower()
                if answer not in ("", "y", "yes"):
                    self.wfile.write(b'{"error":"connection rejected by agent operator"}\n')
                    return
            if request.get("action") != "inventory":
                self.wfile.write(b'{"error":"unsupported action"}\n')
                return
            # Prompting happens on the remote agent's terminal, not over the wire.
            # Remote clients can never request unredacted values or alter local prompt policy.
            host = collect(request.get("name"), False, set(request.get("services", [])), "ignore")
            self.wfile.write((json.dumps(host.to_dict()) + "\n").encode("utf-8"))
        except Exception as exc:  # return a useful protocol error instead of crashing the listener
            self.wfile.write((json.dumps({"error": str(exc)}) + "\n").encode("utf-8"))


class InventoryServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    max_workers = 8

    def __init__(self, address: tuple[str, int], token: str, accept_insecure: bool = False, tls_cert: str | None = None, tls_key: str | None = None, tls_ca: str | None = None, allowed_names: set[str] | None = None):
        self.token = token
        self.accept_insecure = accept_insecure
        self.allowed_names = allowed_names or set()
        self._slots = threading.BoundedSemaphore(self.max_workers)
        super().__init__(address, InventoryHandler)
        if tls_cert and tls_key:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(tls_cert, tls_key)
            if tls_ca:
                context.load_verify_locations(cafile=tls_ca)
                context.verify_mode = ssl.CERT_OPTIONAL if accept_insecure else ssl.CERT_REQUIRED
            elif not accept_insecure:
                raise ValueError("--tls-ca is required unless --accept-insecure is set")
            self.socket = context.wrap_socket(self.socket, server_side=True)
        elif not accept_insecure:
            raise ValueError("TLS certificate, key, and CA are required unless --accept-insecure is set")

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            request.close()
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def serve(bind: str, port: int, token: str, accept_insecure: bool = False, tls_cert: str | None = None, tls_key: str | None = None, tls_ca: str | None = None, allowed_names: set[str] | None = None) -> None:
    with InventoryServer((bind, port), token, accept_insecure, tls_cert, tls_key, tls_ca, allowed_names) as server:
        mode = "plaintext insecure" if not tls_cert else ("TLS; unverified clients permitted" if accept_insecure else "mutual TLS")
        print(f"DockScan agent listening on {bind}:{port} ({mode}); stop with Ctrl+C", flush=True)
        server.serve_forever()
