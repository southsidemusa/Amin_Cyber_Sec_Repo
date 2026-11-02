# Project 1: Port Scanner

**Goal:** Find which doors (ports) are open on a machine and what is behind them.
This is step one of every security audit: you can't defend what you can't see.

**Rule #1:** Only scan networks you own or have written permission to test.
Your home network = fine. Anyone else's = not fine.

---

## 1. Setup (2 minutes, Mac)

```bash
python3 --version      # need 3.9+. If missing: xcode-select --install
cd ~/Documents/port-scanner   # wherever you saved portscan.py
```

No installs. It uses only Python's built-in `socket` library.

## 2. Run it

```bash
# Your own Mac first (safe warm-up)
python3 portscan.py 127.0.0.1

# Your UniFi gateway (usually 192.168.1.1; check Site Manager for yours)
python3 portscan.py 192.168.1.1

# Custom ports / ranges
python3 portscan.py 192.168.1.1 -p 22,80,443,8000-8100

# Every port, save results
python3 portscan.py 192.168.1.1 -p all --json gateway.json
```

Flags you'll use: `-p` ports, `-t` timeout, `-w` threads, `--show-filtered`, `--json FILE`.

## 3. Read the results

| State | Meaning | What the scanner saw |
|-------|---------|----------------------|
| **open** | A service is listening | Connection succeeded |
| **closed** | Host is there, nothing listening | Connection refused |
| **filtered** | Firewall is silently dropping it | Timeout |

## 4. How it works (the 4 ideas)

1. **TCP connect:** `socket.connect_ex((ip, port))` returns `0` if the handshake worked.
2. **Threads:** Scanning 1 port at a time is slow because you wait on timeouts. `ThreadPoolExecutor` runs ~100 at once.
3. **Service lookup:** `socket.getservbyport(22)` gives `"ssh"`. Port numbers are conventions, not proof.
4. **Service probing:** For each open port the scanner *tries* things instead of trusting the port number: (1) does the server greet first, like SSH? (2) does it answer a TLS handshake? (3) does it answer plain HTTP? The `SERVICE (name guess)` column is only the registry name for that number; the `DETECTED` column is what actually answered. When they disagree, believe `DETECTED`.

## 5. Your UniFi tie-in

1. Open **UniFi Site Manager** and list your devices/clients and their IPs.
2. Scan your gateway, then a few other devices (cameras, NAS, printer, TVs).
3. For each open port, ask: *Do I know what this is? Do I need it? Should it be reachable from here?*
4. Heads up: UniFi's **Threat Management / IDS-IPS** may flag your own scan. That's a free lesson in what a defender sees. Check your alerts after a scan.

## 6. Level-up challenges (do these in order)

- [ ] **L1:** Scan `127.0.0.1`. Start `python3 -m http.server 9000` in another terminal, rescan, and see port 9000 appear.
- [ ] **L1:** Scan your gateway and write down every open port + what it is.
- [x] **L2:** Probe services by behavior (greeting / TLS / HTTP) instead of guessing from the port number. *(done)*
- [ ] **L2:** For TLS ports, also print the certificate's subject and expiry date (`getpeercert(binary_form=True)` plus the `cryptography` package, or `openssl s_client` to compare).
- [ ] **L2:** Add a progress counter (`Scanned 400/1000`).
- [ ] **L3:** Scan a whole subnet: loop over `ipaddress.ip_network("192.168.1.0/24").hosts()` and report live hosts.
- [ ] **L3:** Add colored output (green = open).
- [ ] **L4:** Add UDP scanning. Why is it harder? (Hint: no handshake.)
- [ ] **L4:** Rewrite the core with **Scapy** to send a SYN scan (needs `sudo` on Mac). Compare speed and stealth with connect scans.
- [ ] **L5:** Save two scans and write a "diff" that shows newly opened ports. (This becomes your Intrusion Detection project later.)

## 7. Questions to answer in your own words (learning check)

1. Why does a *closed* port respond fast but a *filtered* port is slow?
2. Why can't a port number alone tell you what service is running?
3. What would a defender see in their logs when you scan them?
4. Why does the scanner cap threads at 200 on a Mac?
