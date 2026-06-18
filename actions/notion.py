"""
notion.py — create an incident ticket as a Notion database page.

Required Notion database properties (create these columns in your DB):
  Name        — Title
  Status      — Select  (options: Open, In Progress, Resolved)
  Priority    — Select  (options: High, Medium, Low)
  Attacker IP — Rich Text
  Target IP   — Rich Text
  Signature   — Rich Text
  Date        — Date
"""

import os
import logging
from datetime import datetime, timezone
import requests

logger = logging.getLogger(__name__)

_NOTION_API = "https://api.notion.com/v1"
_NOTION_VERSION = "2022-06-28"
_TIMEOUT = 15  # seconds


def create_incident_ticket(
    title: str,
    alert_data: dict,
    priority: str = "medium",
) -> bool:
    """Create a Notion page in the incident database. Returns True on success."""
    api_key = os.getenv("NOTION_API_KEY", "")
    db_id = os.getenv("NOTION_DATABASE_ID", "")

    if not api_key or not db_id:
        logger.warning(
            "Notion not configured (NOTION_API_KEY / NOTION_DATABASE_ID missing)"
        )
        return False

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Notion-Version": _NOTION_VERSION,
    }

    now_iso = datetime.now(timezone.utc).isoformat()

    payload = {
        "parent": {"database_id": db_id},
        "properties": {
            "Name": {
                "title": [{"text": {"content": title}}]
            },
            "Status": {
                "select": {"name": "Open"}
            },
            "Priority": {
                "select": {"name": priority.capitalize()}
            },
            "Attacker IP": {
                "rich_text": [{"text": {"content": alert_data.get("attacker_ip", "N/A")}}]
            },
            "Target IP": {
                "rich_text": [{"text": {"content": alert_data.get("target_ip", "N/A")}}]
            },
            "Signature": {
                "rich_text": [{"text": {"content": alert_data.get("signature", "N/A")}}]
            },
            "Date": {
                "date": {"start": now_iso}
            },
        },
        "children": [
            {
                "object": "block",
                "type": "heading_2",
                "heading_2": {
                    "rich_text": [{"type": "text", "text": {"content": "Alert Details"}}]
                },
            },
            {
                "object": "block",
                "type": "paragraph",
                "paragraph": {
                    "rich_text": [
                        {
                            "type": "text",
                            "text": {
                                "content": (
                                    f"Severity: {alert_data.get('severity', 'N/A')}\n"
                                    f"Classification: {alert_data.get('classification', 'N/A')}\n"
                                )
                            },
                        }
                    ]
                },
            },
            {
                "object": "block",
                "type": "heading_2",
                "heading_2": {
                    "rich_text": [{"type": "text", "text": {"content": "Raw Alert"}}]
                },
            },
            {
                "object": "block",
                "type": "code",
                "code": {
                    "language": "plain text",
                    "rich_text": [
                        {
                            "type": "text",
                            "text": {"content": alert_data.get("raw", "N/A")[:1900]},
                        }
                    ],
                },
            },
        ],
    }

    try:
        resp = requests.post(
            f"{_NOTION_API}/pages",
            headers=headers,
            json=payload,
            timeout=_TIMEOUT,
        )
        if resp.status_code == 200:
            page_id = resp.json().get("id", "")
            logger.info("Notion ticket created: %s (%s)", title, page_id)
            return True
        else:
            logger.error(
                "Notion API error %d: %s", resp.status_code, resp.text[:300]
            )
            return False
    except requests.exceptions.Timeout:
        logger.error("Notion request timed out")
        return False
    except requests.exceptions.RequestException as exc:
        logger.error("Notion request failed: %s", exc)
        return False
