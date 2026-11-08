import ipaddress
import json
import re
import socket
import ssl
from pathlib import Path

from .models import HostInventory
from .recovery import write_recovery_kit


def request_inventory(address: str, port: int, token: str, name: str, services: set[str], secret_mode: str, tls_ca: str | None = None, tls_cert: str | None = None, tls_key: str | None = None, accept_insecure: bool = False, tls_server_name: str | None = None) -> HostInventory:
    payload = {"action": "inventory", "token": token, "name": name, "services": sorted(services), "secret_mode": secret_mode}
    raw_connection = socket.create_connection((address, port), timeout=5)
    if tls_ca or tls_cert or tls_key:
        context = ssl._create_unverified_context() if accept_insecure else ssl.create_default_context(cafile=tls_ca)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        if not accept_insecure and not tls_ca:
            raise ValueError("--tls-ca is required unless --accept-insecure is used")
        if tls_cert and tls_key:
            context.load_cert_chain(tls_cert, tls_key)
        connection = context.wrap_socket(raw_connection, server_hostname=tls_server_name or address)
    elif not accept_insecure:
        raise ValueError("TLS options are required unless --accept-insecure is used")
    else:
        connection = raw_connection
    with connection:
        connection.sendall((json.dumps(payload) + "\n").encode())
        response = json.loads(connection.makefile("rb").readline().decode())
    if "error" in response:
        raise RuntimeError(response["error"])
    return HostInventory(**response)


def interactive(output: Path, port: int, services: set[str], secret_mode: str, tls_ca: str | None = None, tls_cert: str | None = None, tls_key: str | None = None, accept_insecure: bool = False, tls_server_name: str | None = None) -> None:
    print("DockScan interactive controller. Say 'scan 172.0.8.7' or 'quit'.")
    hosts: list[HostInventory] = []
    while True:
        text = input("dockscan> ").strip()
        if text.lower() in {"quit", "exit"}:
            break
        match = re.search(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", text)
        if not match:
            print("I need an IPv4 address, for example: scan 172.0.8.7")
            continue
        address = match.group(0)
        try:
            ipaddress.ip_address(address)
        except ValueError:
            print("That is not a valid IPv4 address.")
            continue
        token = input("Shared one-time token (leave blank to generate your own): ").strip()
        if not token:
            import secrets
            token = secrets.token_urlsafe(24)
        tls_args = f" --tls-cert <agent-cert.pem> --tls-key <agent-key.pem> --tls-ca {tls_ca}" if tls_ca else " --accept-insecure"
        print(f"On {address}, run:\n  dockscan agent serve --bind 0.0.0.0 --port {port} --token '{token}'{tls_args}")
        input("Press Enter after starting it; DockScan will check reachability. ")
        try:
            name = input(f"Host label [{address}]: ").strip() or address
            hosts.append(request_inventory(address, port, token, name, services, secret_mode, tls_ca, tls_cert, tls_key, accept_insecure, tls_server_name))
            print(f"Connected to {address}; inventory received.")
        except OSError as exc:
            print(f"Port {port} is not reachable from this device: {exc}. Check routing, firewall, and agent bind address.")
        except RuntimeError as exc:
            print(f"Agent rejected the request: {exc}")
    if hosts:
        write_recovery_kit(output, hosts)
        print(f"Recovery kit written to {output.resolve()}")
