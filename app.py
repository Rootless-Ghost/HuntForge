"""
HuntForge — Threat Hunt Playbook Generator
MITRE ATT&CK technique → complete, structured hunt playbook

Author:  Rootless-Ghost
Version: 1.0.0
Port:    5007 (default)

Usage:
    python app.py
    python app.py --port 5007
    python app.py --config /path/to/config.yaml --debug
"""

import argparse
import json
import logging
import os

import yaml
from flask import Flask, jsonify, render_template, request, send_file

from core.engine import PlaybookEngine

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("huntforge")

# ── Config ────────────────────────────────────────────────────────────────────

_DEFAULTS: dict = {
    "port":    5007,
    "db_path": "./huntforge.db",
    "output_dir": "./output",
    "generation": {
        "auto_save":     True,
        "default_env":   "windows",
        "default_sources": ["sysmon", "wazuh"],
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for key, value in override.items():
        if (isinstance(value, dict)
                and key in result
                and isinstance(result[key], dict)):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(path: str) -> dict:
    config = _deep_merge({}, _DEFAULTS)
    if not os.path.exists(path):
        logger.warning("Config not found: %s — using defaults", path)
        return config
    try:
        with open(path, encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh) or {}
        config = _deep_merge(config, loaded)
    except Exception as exc:
        logger.error("Failed to load config: %s — using defaults", exc)
    return config


# ── App factory ───────────────────────────────────────────────────────────────

app = Flask(__name__)
_config: dict = {}
_engine: PlaybookEngine = None  # type: ignore


def create_app(config_path: str = "config.yaml") -> Flask:
    global _config, _engine
    _config = load_config(config_path)
    _engine = PlaybookEngine(_config)
    os.makedirs(_config.get("output_dir", "./output"), exist_ok=True)
    return app


# ── Page routes ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/playbook/<playbook_id>")
def playbook_page(playbook_id: str):
    playbook = _engine.get_playbook(playbook_id)
    if playbook is None:
        return render_template("index.html", error=f"Playbook {playbook_id!r} not found"), 404
    return render_template("playbook.html", playbook=playbook)


@app.route("/library")
def library_page():
    return render_template("library.html")


# ── API: health ───────────────────────────────────────────────────────────────

@app.route("/api/health")
def api_health():
    return jsonify({"status": "ok", "tool": "huntforge", "version": "1.0.0"})


# ── API: techniques ────────────────────────────────────────────────────────────

@app.route("/api/techniques")
def api_techniques():
    """
    Search or list all techniques.
    Query params: q (search), tactic
    """
    query  = request.args.get("q", "").strip()
    tactic = request.args.get("tactic", "").strip()

    results = _engine.search_techniques(query=query, tactic=tactic)
    return jsonify({
        "success":    True,
        "techniques": results,
        "count":      len(results),
    })


@app.route("/api/technique/<technique_id>")
def api_technique(technique_id: str):
    tech = _engine.get_technique(technique_id.upper())
    if tech is None:
        return jsonify({"success": False, "error": f"Technique '{technique_id}' not found"}), 404
    return jsonify({"success": True, "technique": tech})


# ── API: generate playbook ─────────────────────────────────────────────────────

@app.route("/api/playbook/generate", methods=["POST"])
def api_generate():
    """
    Generate a hunt playbook.

    Body: {
        "technique_id": "T1059.001",
        "context": {
            "environment": "windows|linux|cloud",
            "log_sources": ["sysmon", "wazuh", "splunk", "defender", "crowdstrike"]
        },
        "output_format": "json|markdown",
        "save": true
    }
    """
    body = request.get_json(silent=True) or {}

    technique_id = (body.get("technique_id") or "").strip().upper()
    if not technique_id:
        return jsonify({"success": False, "error": "technique_id is required"}), 400

    context       = body.get("context") or {}
    output_format = body.get("output_format", "json").strip().lower()
    save          = bool(body.get("save", _config.get("generation", {}).get("auto_save", True)))

    if output_format not in ("json", "markdown"):
        output_format = "json"

    result = _engine.generate_playbook(
        technique_id=technique_id,
        context=context,
        output_format=output_format,
        save=save,
    )

    if not result.get("success"):
        return jsonify(result), 404

    return jsonify(result)


# ── API: playbooks list ────────────────────────────────────────────────────────

@app.route("/api/playbooks")
def api_playbooks():
    """
    List saved playbooks.
    Query params: page, per_page, tactic, technique_id, search
    """
    page         = max(1, int(request.args.get("page", 1)))
    per_page     = max(1, min(200, int(request.args.get("per_page", 50))))
    tactic       = request.args.get("tactic", "")
    technique_id = request.args.get("technique_id", "")
    search       = request.args.get("search", "")

    result = _engine.get_playbooks(
        page=page, per_page=per_page,
        tactic=tactic, technique_id=technique_id, search=search,
    )
    return jsonify({"success": True, **result})


# ── API: single playbook ───────────────────────────────────────────────────────

@app.route("/api/playbook/<playbook_id>")
def api_playbook(playbook_id: str):
    playbook = _engine.get_playbook(playbook_id)
    if playbook is None:
        return jsonify({"success": False, "error": "Playbook not found"}), 404
    return jsonify({"success": True, "playbook": playbook})


@app.route("/api/playbook/<playbook_id>", methods=["DELETE"])
def api_playbook_delete(playbook_id: str):
    deleted = _engine.delete_playbook(playbook_id)
    if not deleted:
        return jsonify({"success": False, "error": "Playbook not found"}), 404
    return jsonify({"success": True, "deleted": playbook_id})


# ── API: export playbook ───────────────────────────────────────────────────────

@app.route("/api/playbook/<playbook_id>/export")
def api_export(playbook_id: str):
    """Export a playbook as markdown or JSON."""
    fmt = request.args.get("format", "json").lower()
    playbook = _engine.get_playbook(playbook_id)
    if playbook is None:
        return jsonify({"success": False, "error": "Playbook not found"}), 404

    tid  = playbook.get("technique_id", "unknown").replace(".", "-")
    name = playbook.get("technique_name", "hunt").replace(" ", "_").lower()
    filename = f"huntforge_{tid}_{name}"

    if fmt == "markdown":
        md = _engine.to_markdown(playbook)
        md_bytes = md.encode("utf-8")
        import io
        return send_file(
            io.BytesIO(md_bytes),
            mimetype="text/markdown",
            as_attachment=True,
            download_name=f"{filename}.md",
        )

    # JSON export
    import io
    json_bytes = json.dumps(playbook, indent=2, ensure_ascii=False).encode("utf-8")
    return send_file(
        io.BytesIO(json_bytes),
        mimetype="application/json",
        as_attachment=True,
        download_name=f"{filename}.json",
    )


# ── API: LogNorm context enrichment ───────────────────────────────────────────

@app.route("/api/enrich", methods=["POST"])
def api_enrich():
    """
    Accept ECS-lite events from LogNorm (port 5006) and suggest
    hunt playbooks based on observed technique indicators.
    """
    body   = request.get_json(silent=True) or {}
    events = body.get("events") or []

    if not events:
        return jsonify({"success": False, "error": "No events provided"}), 400

    # Heuristic: look for technique IDs in event fields or tags
    seen_techniques = set()
    for event in events[:50]:  # cap at 50 events
        tags = event.get("tags") or []
        for tag in tags:
            if isinstance(tag, str) and tag.upper().startswith("T") and "." in tag:
                seen_techniques.add(tag.upper())
        # Check message/command fields for technique hints
        for field in ("process.command_line", "CommandLine", "message"):
            val = event.get(field, "")
            if val:
                from core.mitre_data import TECHNIQUES
                for tid in TECHNIQUES:
                    if tid.lower() in val.lower():
                        seen_techniques.add(tid)

    suggestions = []
    from core.mitre_data import TECHNIQUES
    for tid in list(seen_techniques)[:10]:
        tech = TECHNIQUES.get(tid)
        if tech:
            suggestions.append({
                "technique_id":   tid,
                "technique_name": tech["name"],
                "tactic":         tech["tactic"],
                "confidence_score": tech["confidence_score"],
                "generate_url": f"/api/playbook/generate",
            })

    return jsonify({
        "success":     True,
        "event_count": len(events),
        "suggestions": suggestions,
    })


# ── CLI entry point ────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="HuntForge — Flask web app")
    p.add_argument("--config",    default="config.yaml")
    p.add_argument("--port",      type=int, default=None)
    p.add_argument("--debug",     action="store_true")
    p.add_argument("--log-level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return p.parse_args()


def main() -> None:
    args = parse_args()
    logging.getLogger().setLevel(args.log_level)
    create_app(args.config)
    port = args.port if args.port is not None else int(_config.get("port", 5007))
    logger.info("HuntForge starting on http://0.0.0.0:%d", port)
    app.run(debug=args.debug, host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
