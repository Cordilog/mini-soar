"""
Playbook engine — loads YAML playbooks, matches conditions against a SnortAlert,
and executes the configured action chain.
"""

import os
import re
import logging
import yaml
from typing import List, Dict, Any

from snort_parser import SnortAlert
from actions import dispatch_action

logger = logging.getLogger(__name__)


class PlaybookEngine:
    def __init__(self, playbooks_dir: str = "playbooks"):
        self.playbooks_dir = playbooks_dir
        self.playbooks: List[Dict] = []
        self.load_playbooks()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_playbooks(self) -> None:
        self.playbooks = []
        if not os.path.isdir(self.playbooks_dir):
            logger.warning("Playbooks directory not found: %s", self.playbooks_dir)
            return

        for fname in sorted(os.listdir(self.playbooks_dir)):
            if not fname.endswith((".yml", ".yaml")):
                continue
            path = os.path.join(self.playbooks_dir, fname)
            try:
                with open(path) as f:
                    pb = yaml.safe_load(f)
                if not isinstance(pb, dict):
                    continue
                if pb.get("enabled", True):
                    self.playbooks.append(pb)
                    logger.info("Loaded playbook: %s", pb.get("name", fname))
                else:
                    logger.info("Skipped disabled playbook: %s", fname)
            except Exception as exc:
                logger.error("Failed to load playbook %s: %s", fname, exc)

    # ------------------------------------------------------------------
    # Matching
    # ------------------------------------------------------------------

    def match(self, alert: SnortAlert) -> List[Dict]:
        """Return every playbook whose conditions all pass for this alert."""
        return [pb for pb in self.playbooks if self._check_conditions(pb.get("conditions", {}), alert)]

    def _check_conditions(self, conditions: Dict, alert: SnortAlert) -> bool:
        for key, value in conditions.items():
            if not self._eval_condition(key, value, alert):
                return False
        return True

    def _eval_condition(self, key: str, value: Any, alert: SnortAlert) -> bool:
        if key == "signature_contains":
            return str(value).lower() in alert.signature.lower()

        if key == "signature_regex":
            return bool(re.search(str(value), alert.signature, re.IGNORECASE))

        if key == "severity":
            return alert.severity == str(value).lower()

        if key == "severity_in":
            return alert.severity in [str(v).lower() for v in value]

        # priority_lte: Snort priority 1=high, so lte=1 means only high
        if key == "priority_lte":
            return alert.priority <= int(value)

        if key == "attacker_ip":
            return alert.attacker_ip == str(value)

        if key == "target_ip":
            return alert.target_ip == str(value)

        if key == "protocol":
            return alert.protocol.upper() == str(value).upper()

        if key == "classification_contains":
            return str(value).lower() in alert.classification.lower()

        logger.warning("Unknown condition key: %s", key)
        return True  # unknown conditions are ignored (not blocking)

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def execute(self, playbook: Dict, alert: SnortAlert) -> List[Dict]:
        """Execute all actions defined in a playbook and return results list."""
        template_vars = {
            "attacker_ip": alert.attacker_ip or "unknown",
            "attacker_port": str(alert.attacker_port or ""),
            "target_ip": alert.target_ip or "unknown",
            "target_port": str(alert.target_port or ""),
            "signature": alert.signature or "unknown",
            "sig_id": alert.sig_id or "",
            "severity": alert.severity,
            "priority": str(alert.priority),
            "protocol": alert.protocol or "unknown",
            "classification": alert.classification or "",
            "timestamp": alert.timestamp or "",
        }

        results = []
        for action_def in playbook.get("actions", []):
            action_type = action_def.get("type", "")
            result = {"type": action_type, "success": False}

            # Render string templates inside the action definition
            rendered = _render_dict(action_def, template_vars)

            try:
                success, detail = dispatch_action(action_type, rendered, alert)
                result["success"] = success
                if detail:
                    result.update(detail)
            except Exception as exc:
                logger.error("Action '%s' raised exception: %s", action_type, exc)
                result["error"] = str(exc)

            results.append(result)

        return results


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _render_dict(d: Dict, vars: Dict) -> Dict:
    """Recursively format all string values in a dict with vars."""
    out = {}
    for k, v in d.items():
        if isinstance(v, str):
            try:
                out[k] = v.format_map(vars)
            except (KeyError, ValueError):
                out[k] = v
        elif isinstance(v, dict):
            out[k] = _render_dict(v, vars)
        elif isinstance(v, list):
            out[k] = [
                item.format_map(vars) if isinstance(item, str) else item
                for item in v
            ]
        else:
            out[k] = v
    return out
