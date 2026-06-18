"""
slack.py — send a notification to a Slack Incoming Webhook.
"""

import os
import logging
import requests

logger = logging.getLogger(__name__)

_TIMEOUT = 10  # seconds


def send_slack(message: str, webhook_url: str = None) -> bool:
    """POST message to Slack webhook. Returns True on success."""
    url = webhook_url or os.getenv("SLACK_WEBHOOK_URL", "")
    if not url:
        logger.warning("Slack webhook URL not configured (SLACK_WEBHOOK_URL)")
        return False

    try:
        resp = requests.post(
            url,
            json={"text": message},
            timeout=_TIMEOUT,
        )
        if resp.status_code == 200 and resp.text == "ok":
            logger.info("Slack notification sent")
            return True
        else:
            logger.error("Slack error %d: %s", resp.status_code, resp.text[:200])
            return False
    except requests.exceptions.Timeout:
        logger.error("Slack request timed out")
        return False
    except requests.exceptions.RequestException as exc:
        logger.error("Slack request failed: %s", exc)
        return False
