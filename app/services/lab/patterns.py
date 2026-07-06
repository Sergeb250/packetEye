"""Single source of truth for CIC-IDS2017-style lab attack patterns."""

ALL_LAB_PATTERNS = [
    "portscan",
    "bot",
    "ddos",
    "dos_goldeneye",
    "dos_hulk",
    "dos_slowhttptest",
    "dos_slowloris",
    "ftp_patator",
    "ssh_patator",
    "web_brute",
    "dns",
    "infiltration",
    "arp",
]

PATTERN_CIC_LABELS = {
    "portscan": "PortScan",
    "scan": "PortScan",
    "bot": "Bot",
    "beacon": "Bot",
    "ddos": "DDoS",
    "dos_goldeneye": "DoS GoldenEye",
    "dos_hulk": "DoS Hulk",
    "dos_slowhttptest": "DoS Slowhttptest",
    "dos_slowloris": "DoS slowloris",
    "ftp_patator": "FTP-Patator",
    "ssh_patator": "SSH-Patator",
    "web_brute": "Web Attack – Brute Force",
    "dns": "DNS tunnel",
    "infiltration": "Infiltration",
    "arp": "ARP activity",
}
