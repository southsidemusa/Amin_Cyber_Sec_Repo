#!/usr/bin/env python3
"""
portscan.py - A TCP connect() port scanner with service + banner detection.

Pure standard library. Works on macOS (and Linux/Windows).

HOW IT WORKS (the whole idea in 3 lines):
  1. Try to open a TCP connection to ip:port.
  2. If the connection succeeds -> port is OPEN. If refused -> CLOSED.
     If nothing comes back before the timeout -> FILTERED (firewall dropping it).
  3. For open ports, PROBE the service (greeting? TLS? HTTP?) to see what it really is.

ONLY SCAN NETWORKS YOU OWN OR HAVE WRITTEN PERMISSION TO TEST.
"""

import argparse
import errno
import ipaddress
import json
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

# Ports worth checking first. Includes common UniFi ports.
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    631, 993, 995, 1723, 1883, 3306, 3389, 5000, 5001, 5353, 5432, 5900,
    6379, 7000, 8000, 8080, 8443, 8883, 9100, 27017,
    # UniFi-specific
    6789, 7443, 8843, 8880, 8881, 8882,
]

# Names the OS database may not know (UniFi etc.)
EXTRA_SERVICES = {
    6789: "unifi-speedtest",
    7443: "unifi-portal-https",
    8080: "unifi-inform / http-alt",
    8443: "unifi-controller / https-alt",
    8843: "unifi-portal-https",
    8880: "unifi-portal-http",
    5000: "upnp / synology / flask",
    5001: "synology-https",
    9100: "printer-jetdirect",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def service_name(port: int) -> str:
    """Look up a service name: our overrides first, then the OS database."""
    if port in EXTRA_SERVICES:
        return EXTRA_SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def parse_ports(spec: str) -> list[int]:
    """Turn '22,80,8000-8100' / 'top' / 'all' into a sorted list of ports."""
    spec = spec.strip().lower()
    if spec == "top":
        return sorted(set(TOP_PORTS))
    if spec == "all":
        return list(range(1, 65536))

    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo, hi = int(lo), int(hi)
            if lo > hi:
                lo, hi = hi, lo
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))

    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"Ports out of range (1-65535): {sorted(bad)[:5]}")
    return sorted(ports)


def _clean(text: str, limit: int = 110) -> str:
    """One line, printable only. Never trust what the target sends: a hostile
    service could embed terminal escape codes in its reply."""
    text = " ".join(text.split())[:limit]
    return "".join(c if c.isprintable() else "?" for c in text)


def _http_head(sock, host: str) -> str:
    """Send a minimal HTTP request; return 'status line | Server: ...' or ''."""
    sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\nConnection: close\r\n\r\n")
    text = sock.recv(1024).decode("utf-8", errors="replace")
    if not text.upper().startswith("HTTP/"):
        return ""
    lines = text.splitlines()
    parts = [lines[0]]
    for ln in lines[1:]:
        if ln.lower().startswith("server:"):
            parts.append(ln)
            break
    return " | ".join(parts)


def probe_service(ip: str, port: int, timeout: float) -> str:
    """Figure out what an open port speaks by TRYING, not by port number.

    1. Does the server talk first?  (SSH, FTP, SMTP send a greeting)
    2. Does it answer a TLS handshake?  If so, ask it for a web page over TLS.
    3. Does it answer plain HTTP?
    4. Otherwise it speaks something else.
    """
    # Step 1: listen briefly for a greeting
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(min(timeout, 0.5))
            try:
                data = s.recv(256)
            except OSError:  # timed out: server is waiting for us to speak
                data = b""
            if data:
                return _clean(data.decode("utf-8", errors="replace"))
    except OSError:
        return ""

    # Step 2: TLS. We only want to identify the service, so we skip
    # certificate checks (home gear uses self-signed certs).
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw) as s:
                version = s.version() or "TLS"
                try:
                    reply = _http_head(s, ip)
                except OSError:
                    reply = ""
                return _clean(f"[{version}] " + (reply or "(no HTTP reply)"))
    except OSError:  # ssl.SSLError is a subclass of OSError
        pass

    # Step 3: plain HTTP
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            reply = _http_head(s, ip)
            if reply:
                return _clean("[plain] " + reply)
    except OSError:
        pass

    return "(open; no greeting, TLS or HTTP reply - other protocol)"


def scan_port(ip: str, port: int, timeout: float, grab: bool):
    """Return a result dict for OPEN ports, 'filtered' marker, or None if closed."""
    # Socket creation is INSIDE the try: if the OS runs out of file descriptors
    # ("Too many open files") we record an error for this port instead of
    # crashing the whole scan.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            code = s.connect_ex((ip, port))
    except OSError:
        return {"port": port, "state": "error", "service": "", "banner": ""}

    if code == 0:
        banner = probe_service(ip, port, timeout) if grab else ""
        return {"port": port, "state": "open", "service": service_name(port), "banner": banner}
    # ECONNREFUSED -> closed (the host answered "no"); same meaning on every OS
    if code == errno.ECONNREFUSED:
        return None
    # Anything else (timeouts, unreachable) -> likely filtered by a firewall
    return {"port": port, "state": "filtered", "service": "", "banner": ""}


def resolve_target(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        sys.exit(f"[!] Could not resolve '{target}'")


def check_authorization(ip: str, i_own_this: bool):
    """Guardrail: private/loopback addresses are fine; public ones need a flag."""
    addr = ipaddress.ip_address(ip)
    if addr.is_private or addr.is_loopback:
        return
    if not i_own_this:
        sys.exit(
            f"[!] {ip} is a PUBLIC address. Only scan systems you own or have "
            "written permission to test.\n    If that's you, re-run with --i-own-this"
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Simple TCP port scanner with service detection.")
    ap.add_argument("target", help="IP or hostname, e.g. 192.168.1.1")
    ap.add_argument("-p", "--ports", default="top",
                    help="'top' (default), 'all', or a list like 22,80,8000-8100")
    ap.add_argument("-t", "--timeout", type=float, default=1.0, help="seconds per port (default 1.0)")
    ap.add_argument("-w", "--workers", type=int, default=100,
                    help="parallel threads (default 100; macOS caps open files at 256 by default)")
    ap.add_argument("--no-banner", action="store_true", help="skip service probing (faster)")
    ap.add_argument("--show-filtered", action="store_true", help="also list filtered ports")
    ap.add_argument("--json", metavar="FILE", help="save results to a JSON file")
    ap.add_argument("--i-own-this", action="store_true", help="confirm you're authorized to scan a public IP")
    args = ap.parse_args()

    # A timeout of 0 makes sockets non-blocking, so every connect looks
    # unfinished and real open ports get reported as "filtered".
    if args.timeout <= 0:
        sys.exit("[!] --timeout must be greater than 0")

    ip = resolve_target(args.target)
    check_authorization(ip, args.i_own_this)

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        sys.exit(f"[!] {e}")

    workers = max(1, min(args.workers, 200))
    print(f"[*] Target: {args.target} ({ip})")
    print(f"[*] Scanning {len(ports)} ports | timeout {args.timeout}s | {workers} threads")

    start = time.time()
    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(scan_port, ip, p, args.timeout, not args.no_banner) for p in ports]
        try:
            for fut in as_completed(futures):
                r = fut.result()
                if r:
                    results.append(r)
        except KeyboardInterrupt:
            print("\n[!] Interrupted - showing what we have so far")
            for f in futures:
                f.cancel()

    results.sort(key=lambda r: r["port"])
    open_ports = [r for r in results if r["state"] == "open"]
    filtered = [r for r in results if r["state"] == "filtered"]
    errors = [r for r in results if r["state"] == "error"]
    elapsed = time.time() - start

    print(f"\n{'PORT':<8}{'STATE':<8}{'SERVICE (name guess)':<30}DETECTED")
    print("-" * 78)
    for r in open_ports:
        print(f"{r['port']:<8}{r['state']:<8}{r['service']:<30}{r['banner']}")
    if args.show_filtered:
        for r in filtered:
            print(f"{r['port']:<8}{r['state']:<8}")
    if not open_ports:
        print("(no open ports found)")

    print(f"\n[+] Done in {elapsed:.2f}s | open: {len(open_ports)} | filtered: {len(filtered)} "
          f"| closed: {len(ports) - len(results)} | errors: {len(errors)}")
    if errors:
        print(f"[!] {len(errors)} ports could not be scanned (likely 'Too many open files'). "
              "Results are incomplete - try a lower -w, or run: ulimit -n 1024")

    if args.json:
        with open(args.json, "w") as f:
            json.dump({"target": args.target, "ip": ip, "scanned": len(ports),
                       "seconds": round(elapsed, 2), "results": results}, f, indent=2)
        print(f"[+] Saved to {args.json}")


if __name__ == "__main__":
    main()
