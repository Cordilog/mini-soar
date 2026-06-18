"""
Snort alert parser — handles fast-alert (single-line) and full-alert (multi-line) formats.
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# Snort priority maps directly to severity
_PRIORITY_SEVERITY = {1: "high", 2: "medium", 3: "low"}


@dataclass
class SnortAlert:
    raw: str
    signature: str = ""
    sig_id: str = ""            # gid:sid:rev
    attacker_ip: str = ""
    attacker_port: Optional[int] = None
    target_ip: str = ""
    target_port: Optional[int] = None
    protocol: str = ""
    priority: int = 3
    severity: str = "low"
    classification: str = ""
    timestamp: str = ""


def parse_snort_alert(raw: str) -> SnortAlert:
    """
    Parse a Snort alert string.

    Supported formats
    -----------------
    Fast (single-line):
        06/17-10:30:00.000000  [**] [1:2001:1] SHELLSHOCK ... [**]
        [Classification: Web App Attack] [Priority: 1] {TCP} 192.168.100.3:54321 -> 10.10.11.10:80

    Full (multi-line joined or as-is):
        [**] [1:2001:1] SHELLSHOCK ... [**]
        [Classification: Web App Attack] [Priority: 1]
        06/17-10:30:00.000000 192.168.100.3:54321 -> 10.10.11.10:80
        TCP TTL:64 ...
    """
    alert = SnortAlert(raw=raw)

    # --- Signature -------------------------------------------------------
    sig_match = re.search(
        r'\[\*\*\]\s*\[(\d+:\d+:\d+)\]\s*(.+?)\s*\[\*\*\]', raw
    )
    if sig_match:
        alert.sig_id = sig_match.group(1)
        alert.signature = sig_match.group(2).strip()

    # --- Priority --------------------------------------------------------
    prio_match = re.search(r'\[Priority:\s*(\d+)\]', raw)
    if prio_match:
        alert.priority = int(prio_match.group(1))

    # --- Classification --------------------------------------------------
    class_match = re.search(r'\[Classification:\s*(.+?)\]', raw)
    if class_match:
        alert.classification = class_match.group(1).strip()

    # --- Timestamp -------------------------------------------------------
    ts_match = re.search(r'(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)', raw)
    if ts_match:
        alert.timestamp = ts_match.group(1)

    # --- IPs & Protocol --------------------------------------------------
    # Fast format: {TCP} 1.2.3.4:port -> 5.6.7.8:port
    proto_match = re.search(
        r'\{(\w+)\}\s*([\d.]+)(?::(\d+))?\s*->\s*([\d.]+)(?::(\d+))?', raw
    )
    if proto_match:
        alert.protocol = proto_match.group(1).upper()
        alert.attacker_ip = proto_match.group(2)
        alert.attacker_port = int(proto_match.group(3)) if proto_match.group(3) else None
        alert.target_ip = proto_match.group(4)
        alert.target_port = int(proto_match.group(5)) if proto_match.group(5) else None
    else:
        # Full format: timestamp 1.2.3.4:port -> 5.6.7.8:port (no {PROTO})
        ip_match = re.search(
            r'([\d.]+)(?::(\d+))?\s*->\s*([\d.]+)(?::(\d+))?', raw
        )
        if ip_match:
            alert.attacker_ip = ip_match.group(1)
            alert.attacker_port = int(ip_match.group(2)) if ip_match.group(2) else None
            alert.target_ip = ip_match.group(3)
            alert.target_port = int(ip_match.group(4)) if ip_match.group(4) else None

        # Protocol from last line keyword
        proto_kw = re.search(r'\b(TCP|UDP|ICMP)\b', raw)
        if proto_kw:
            alert.protocol = proto_kw.group(1)

    # --- Severity --------------------------------------------------------
    alert.severity = _PRIORITY_SEVERITY.get(alert.priority, "low")

    logger.debug(
        "Parsed alert: sig=%r attacker=%s target=%s severity=%s",
        alert.signature, alert.attacker_ip, alert.target_ip, alert.severity,
    )
    return alert
