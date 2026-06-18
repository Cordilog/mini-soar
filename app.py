"""
Mini SOAR — Flask REST API server.

Endpoints
---------
POST /api/alerts          Receive a Snort alert and run matching playbooks
GET  /api/incidents       List incidents (last 100)
GET  /api/incidents/<id>  Get a single incident
GET  /api/status          SOAR health and playbook summary
GET  /api/playbooks       List loaded playbooks
POST /api/playbooks/reload  Hot-reload playbooks from disk
"""

import json
import logging
import os
import threading
from datetime import datetime, timezone

from dotenv import load_dotenv
from flask import Flask, jsonify, request

from snort_parser import parse_snort_alert
from playbook_engine import PlaybookEngine

load_dotenv()

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

os.makedirs("logs", exist_ok=True)
os.makedirs("incidents", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/soar.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Flask app & global state
# ---------------------------------------------------------------------------

app = Flask(__name__)
engine = PlaybookEngine(playbooks_dir="playbooks")

_incidents: list = []
_lock = threading.Lock()
_counter = 0
_INCIDENTS_FILE = "incidents/incidents.json"


def _load_incidents() -> None:
    global _incidents, _counter
    if os.path.exists(_INCIDENTS_FILE):
        try:
            with open(_INCIDENTS_FILE) as f:
                _incidents = json.load(f)
            _counter = len(_incidents)
            logger.info("Loaded %d existing incidents", _counter)
        except Exception as exc:
            logger.error("Could not load incidents file: %s", exc)


def _save_incidents() -> None:
    try:
        with open(_INCIDENTS_FILE, "w") as f:
            json.dump(_incidents, f, indent=2, default=str)
    except Exception as exc:
        logger.error("Could not save incidents: %s", exc)


def _next_id() -> str:
    global _counter
    _counter += 1
    date = datetime.now(timezone.utc).strftime("%Y%m%d")
    return f"INC-{date}-{_counter:04d}"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/api/alerts", methods=["POST"])
def receive_alert():
    """Accept a Snort alert (JSON or plain text) and run playbooks."""
    # --- Parse input --------------------------------------------------------
    raw: str = ""
    ct = request.content_type or ""
    if "json" in ct:
        body = request.get_json(force=True, silent=True) or {}
        raw = body.get("raw") or body.get("alert") or body.get("message") or ""
    else:
        raw = request.get_data(as_text=True)

    raw = raw.strip()
    if not raw:
        return jsonify({"error": "empty alert body"}), 400

    logger.info("Alert received from %s (%d chars)", request.remote_addr, len(raw))

    # --- Parse alert --------------------------------------------------------
    alert = parse_snort_alert(raw)
    if not alert.signature and not alert.attacker_ip:
        logger.warning("Could not parse alert; no signature or IPs found")
        return jsonify({"error": "unparseable alert", "raw_preview": raw[:120]}), 422

    # --- Match playbooks ----------------------------------------------------
    matched = engine.match(alert)
    if not matched:
        logger.info("No playbook matched for: %r", alert.signature)
        return jsonify({
            "status": "no_match",
            "signature": alert.signature,
            "severity": alert.severity,
        }), 200

    # --- Execute & record incident ------------------------------------------
    with _lock:
        inc_id = _next_id()

    pb_results = []
    for pb in matched:
        logger.info("Executing playbook: %s", pb.get("name"))
        actions = engine.execute(pb, alert)
        pb_results.append({"playbook": pb.get("name"), "actions": actions})

    incident = {
        "id": inc_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "alert": {
            "signature": alert.signature,
            "sig_id": alert.sig_id,
            "attacker_ip": alert.attacker_ip,
            "attacker_port": alert.attacker_port,
            "target_ip": alert.target_ip,
            "target_port": alert.target_port,
            "protocol": alert.protocol,
            "severity": alert.severity,
            "priority": alert.priority,
            "classification": alert.classification,
            "snort_timestamp": alert.timestamp,
        },
        "playbooks_executed": pb_results,
        "status": "resolved",
    }

    with _lock:
        _incidents.append(incident)
        _save_incidents()

    logger.info(
        "Incident %s created — %d playbook(s) matched", inc_id, len(matched)
    )
    return jsonify({
        "status": "ok",
        "incident_id": inc_id,
        "playbooks_matched": len(matched),
        "severity": alert.severity,
    }), 200


@app.route("/api/incidents", methods=["GET"])
def list_incidents():
    with _lock:
        total = len(_incidents)
        page = _incidents[-100:]  # most recent 100
    return jsonify({"total": total, "incidents": page})


@app.route("/api/incidents/<incident_id>", methods=["GET"])
def get_incident(incident_id: str):
    with _lock:
        for inc in _incidents:
            if inc["id"] == incident_id:
                return jsonify(inc)
    return jsonify({"error": "not found"}), 404


@app.route("/api/status", methods=["GET"])
def status():
    with _lock:
        total = len(_incidents)
    return jsonify({
        "status": "running",
        "version": "1.0.0",
        "soar_ip": "192.168.100.35",
        "playbooks_loaded": len(engine.playbooks),
        "playbook_names": [pb.get("name") for pb in engine.playbooks],
        "total_incidents": total,
    })


@app.route("/api/playbooks", methods=["GET"])
def list_playbooks():
    return jsonify({
        "total": len(engine.playbooks),
        "playbooks": [
            {
                "name": pb.get("name"),
                "description": pb.get("description", ""),
                "enabled": pb.get("enabled", True),
                "conditions": pb.get("conditions", {}),
                "action_types": [a.get("type") for a in pb.get("actions", [])],
            }
            for pb in engine.playbooks
        ],
    })


@app.route("/api/playbooks/reload", methods=["POST"])
def reload_playbooks():
    engine.load_playbooks()
    logger.info("Playbooks reloaded: %d loaded", len(engine.playbooks))
    return jsonify({
        "status": "reloaded",
        "playbooks_loaded": len(engine.playbooks),
    })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    _load_incidents()
    host = os.getenv("FLASK_HOST", "0.0.0.0")
    port = int(os.getenv("FLASK_PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    logger.info("Starting mini-SOAR on %s:%d", host, port)
    app.run(host=host, port=port, debug=debug)
