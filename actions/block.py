"""
block.py — block an attacker IP on fwnids via SSH.

The remote authorized_keys entry restricts the session to soar_iptables.sh,
so the SSH command argument is just the IP to block.
The script on fwnids validates the IP and inserts:
    iptables -I FORWARD -s <IP> -j DROP
"""

import os
import re
import subprocess
import logging

logger = logging.getLogger(__name__)

_IP_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')


def block_ip(ip: str) -> bool:
    """SSH into fwnids and block ip in the FORWARD chain. Returns True on success."""
    if not _IP_RE.match(ip):
        logger.error("block_ip: invalid IP format: %s", ip)
        return False

    fwnids_host = os.getenv("FWNIDS_HOST", "192.168.100.6")
    ssh_key = os.getenv("SSH_KEY_PATH", os.path.expanduser("~/.ssh/id_rsa"))

    cmd = [
        "ssh",
        "-i", ssh_key,
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        f"root@{fwnids_host}",
        ip,
    ]

    logger.info("Blocking IP %s on %s", ip, fwnids_host)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode == 0:
            logger.info("IP %s blocked successfully", ip)
            return True
        else:
            logger.error(
                "Failed to block %s (exit %d): %s",
                ip, result.returncode, result.stderr.strip()
            )
            return False
    except subprocess.TimeoutExpired:
        logger.error("SSH timeout while blocking %s", ip)
        return False
    except FileNotFoundError:
        logger.error("ssh binary not found")
        return False
    except Exception as exc:
        logger.error("Unexpected error blocking %s: %s", ip, exc)
        return False
