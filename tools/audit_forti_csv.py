"""Convert a FortiManager-style policy CSV into the API's raw schema and
submit it to /audit/csv, saving the Markdown compliance report.

Usage:
    python tools/audit_forti_csv.py "Firewall Policy.csv" compliance-report.md

The Forti export uses banner rows, sub-headers, and multi-line cells. This
script extracts the policy rows, maps the service names to protocol/port,
and writes our flat raw-standards CSV that /audit/csv understands.
"""
from __future__ import annotations

import csv
import io
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # noqa: E402

from api.main import app  # noqa: E402

# Common FortiGate service objects → (protocol, port)
SERVICE_MAP: dict[str, tuple[str, int]] = {
    "ALL": ("any", 0),
    "ANY": ("any", 0),
    "ALL_TCP": ("tcp", 0),
    "ALL_UDP": ("udp", 0),
    "ALL_ICMP": ("icmp", 0),
    "PING": ("icmp", 0),
    "HTTPS": ("tcp", 443),
    "HTTP": ("tcp", 80),
    "HTTP-8080": ("tcp", 8080),
    "HTTP-8443": ("tcp", 8443),
    "DNS": ("udp", 53),
    "DNS-TCP": ("tcp", 53),
    "SSH": ("tcp", 22),
    "TELNET": ("tcp", 23),
    "FTP": ("tcp", 21),
    "SFTP": ("tcp", 22),
    "SMTP": ("tcp", 25),
    "SMTPS": ("tcp", 465),
    "POP3": ("tcp", 110),
    "POP3S": ("tcp", 995),
    "IMAP": ("tcp", 143),
    "IMAPS": ("tcp", 993),
    "NTP": ("udp", 123),
    "SNMP": ("udp", 161),
    "SYSLOG": ("udp", 514),
    "TFTP": ("udp", 69),
    "LDAP": ("tcp", 389),
    "LDAPS": ("tcp", 636),
    "KERBEROS": ("tcp", 88),
    "RADIUS": ("udp", 1812),
    "SMB": ("tcp", 445),
    "RDP": ("tcp", 3389),
    "MSSQL": ("tcp", 1433),
    "MYSQL": ("tcp", 3306),
    "POSTGRES": ("tcp", 5432),
    "ORACLE": ("tcp", 1521),
    "REDIS": ("tcp", 6379),
    "MONGO": ("tcp", 27017),
    "VNC": ("tcp", 5900),
    "WEB": ("tcp", 80),
    "WEB_BROWSING": ("tcp", 80),
    "DHCP": ("udp", 67),
    "BOOTP": ("udp", 67),
    "ICMP": ("icmp", 0),
    "ICMP_ANY": ("icmp", 0),
    "TRACEROUTE": ("udp", 33434),
    "AH": ("any", 0),
    "ESP": ("any", 0),
    "IKE": ("udp", 500),
    "L2TP": ("udp", 1701),
    "PPTP": ("tcp", 1723),
    "GRE": ("any", 0),
}

# Sensitive keywords → mark data_classification as Confidential to exercise
# the encryption-in-transit control during the audit.
SENSITIVE_HINTS = ("payment", "card", "pos", "voice", "voip", "payroll", "hmrc")

RAW_HEADER = [
    "source",
    "destination",
    "protocol",
    "port",
    "log",
    "action",
    "source_interface",
    "destination_interface",
    "data_classification",
    "approved_external_sharing",
]


def _first_token(value: str) -> str:
    """Pick the first non-empty line from a multi-line Forti cell."""
    for line in value.splitlines():
        token = line.strip()
        if token:
            return token
    return ""


def _map_service(name: str) -> tuple[str, int]:
    key = name.strip().upper()
    if not key:
        return ("any", 0)
    if key in SERVICE_MAP:
        return SERVICE_MAP[key]
    # Try to detect "TCP/443"-style values as a fallback
    for proto in ("tcp", "udp"):
        marker = f"{proto.upper()}/"
        if key.startswith(marker):
            try:
                return (proto, int(key.split("/", 1)[1]))
            except ValueError:
                pass
    return ("any", 0)


def _map_log(value: str) -> str:
    v = value.strip().lower()
    if not v or "no log" in v or v in {"disable", "disabled", "off"}:
        return "no_log"
    if "security" in v or "utm" in v:
        return "utm"
    return "all"


def _map_action(value: str) -> str:
    v = value.strip().lower()
    if v in {"accept", "allow", "permit"}:
        return "accept"
    if v in {"deny", "drop", "block", "reject"}:
        return "deny"
    return "accept"


def _classify(name: str, src: str, dst: str) -> str:
    blob = f"{name} {src} {dst}".lower()
    return "Confidential" if any(h in blob for h in SENSITIVE_HINTS) else "Internal"


def convert(forti_csv_path: Path) -> str:
    with forti_csv_path.open(newline="") as f:
        rows = list(csv.reader(f))

    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(RAW_HEADER)

    for row in rows:
        if not row or not row[0].strip().isdigit():
            continue  # skip banner / sub-header / blank rows
        try:
            name = row[2]
            action = row[3]
            src_iface = _first_token(row[4]) or "unknown-src"
            src_addr = _first_token(row[5]) or src_iface
            dst_iface = _first_token(row[7]) or "unknown-dst"
            dst_addr = _first_token(row[8]) or dst_iface
            service = _first_token(row[12])
            log = row[15] if len(row) > 15 else ""
        except IndexError:
            continue

        protocol, port = _map_service(service)
        writer.writerow([
            src_addr,
            dst_addr,
            protocol,
            port,
            _map_log(log),
            _map_action(action),
            src_iface,
            dst_iface,
            _classify(name, src_addr, dst_addr),
            "false",
        ])

    return out.getvalue()


def audit(raw_csv: str) -> tuple[int, str]:
    client = TestClient(app)
    response = client.post(
        "/audit/csv",
        content=raw_csv,
        headers={"Content-Type": "text/csv"},
    )
    return response.status_code, response.text


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    src = Path(sys.argv[1])
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("compliance-report.md")
    raw_csv = convert(src)
    status, body = audit(raw_csv)
    if status != 200:
        sys.stderr.write(f"Audit failed: HTTP {status}\n{body}\n")
        return 1
    out.write_text(body, encoding="utf-8")
    print(f"Wrote {out} ({len(body)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
