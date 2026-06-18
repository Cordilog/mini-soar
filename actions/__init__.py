"""
Action dispatcher — routes action type strings to handler functions.
"""

import logging
from typing import Tuple, Dict, Any

from actions.block import block_ip
from actions.slack import send_slack
from actions.notion import create_incident_ticket

logger = logging.getLogger(__name__)


def dispatch_action(
    action_type: str,
    action_def: Dict[str, Any],
    alert,  # SnortAlert — avoid circular import with type annotation
) -> Tuple[bool, Dict]:
    """
    Execute a single action.

    Returns (success: bool, detail: dict).
    Raises on unexpected exceptions (caller catches them).
    """
    if action_type == "block_ip":
        ip = alert.attacker_ip
        if not ip:
            logger.warning("block_ip: no attacker IP in alert, skipping")
            return False, {"reason": "no attacker IP"}
        success = block_ip(ip)
        return success, {"target_ip": ip}

    if action_type == "slack_notify":
        message = action_def.get("message", f"Alert: {alert.signature} from {alert.attacker_ip}")
        success = send_slack(message)
        return success, {}

    if action_type == "notion_ticket":
        title = action_def.get("title", f"Incident: {alert.signature}")
        priority = action_def.get("priority", alert.severity)
        # Normalize priority to Notion-friendly value
        priority = priority.strip("{}").lower()
        if priority not in ("low", "medium", "high"):
            priority = "medium"
        success = create_incident_ticket(
            title=title,
            alert_data={
                "attacker_ip": alert.attacker_ip,
                "target_ip": alert.target_ip,
                "signature": alert.signature,
                "severity": alert.severity,
                "classification": alert.classification,
                "raw": alert.raw,
            },
            priority=priority,
        )
        return success, {"title": title}

    if action_type == "log":
        message = action_def.get("message", f"Alert: {alert.signature}")
        logger.info("[PLAYBOOK] %s", message)
        return True, {}

    logger.warning("Unknown action type: %s", action_type)
    return False, {"reason": f"unknown action type: {action_type}"}
