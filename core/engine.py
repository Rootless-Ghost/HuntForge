"""
HuntForge — Playbook Generation Engine
"""

import json
import logging
from datetime import datetime

from .mitre_data import TECHNIQUES, TACTICS, get_technique, search_techniques, list_techniques
from .query_builder import QueryBuilder
from .storage import PlaybookStorage

logger = logging.getLogger("huntforge.engine")


# ── Confidence level labels ────────────────────────────────────────────────────

def _confidence_label(score: int) -> str:
    if score >= 9:
        return "Very High"
    if score >= 7:
        return "High"
    if score >= 5:
        return "Medium"
    if score >= 3:
        return "Low"
    return "Very Low"


# ── Hypothesis builder ─────────────────────────────────────────────────────────

def _build_hypothesis(technique: dict, context: dict) -> str:
    env        = context.get("environment", "windows")
    log_sources = context.get("log_sources", [])
    base       = technique.get("hunt_hypothesis", "")

    env_ctx = ""
    if env == "windows":
        env_ctx = "In this Windows environment, "
    elif env == "linux":
        env_ctx = "In this Linux environment, "
    elif env == "cloud":
        env_ctx = "In this cloud environment, "

    source_ctx = ""
    if log_sources:
        src_list = ", ".join(log_sources)
        source_ctx = f" Available log sources for this hunt include: {src_list}."

    coverage_gaps = []
    required = technique.get("log_sources", [])
    for req in required:
        matched = any(
            r.lower() in req.lower() or req.lower() in r.lower()
            for r in log_sources
        )
        if not matched:
            coverage_gaps.append(req)

    gap_ctx = ""
    if coverage_gaps:
        gap_ctx = f"\n\n**Coverage note:** The following recommended log sources are not in scope for this hunt and may reduce detection confidence: {', '.join(coverage_gaps[:3])}."

    return env_ctx + base + source_ctx + gap_ctx


# ── Suggested log sources ──────────────────────────────────────────────────────

def _build_suggested_sources(technique: dict, env: str) -> list[dict]:
    sources = []
    raw = technique.get("log_sources", [])
    for src in raw:
        priority = "required"
        if "Sysmon" in src:
            desc = "Provides rich process, network, registry, and file events. Critical for high-fidelity detection."
            priority = "required"
        elif "Security" in src:
            desc = "Windows Security audit log — logon events, object access, account changes."
            priority = "required"
        elif "PowerShell" in src:
            desc = "Script Block Logging (Event 4104) is essential for catching obfuscated PowerShell."
            priority = "required"
        elif "System" in src:
            desc = "Windows System log — service installation, driver loading, system errors."
            priority = "recommended"
        elif "TaskScheduler" in src:
            desc = "Task Scheduler operational log — task creation, modification, execution."
            priority = "recommended"
        elif "DNS" in src.lower():
            desc = "DNS query/response logs for C2 beacon and exfil detection."
            priority = "recommended"
        elif "Firewall" in src.lower() or "network" in src.lower():
            desc = "Network flow/connection logs essential for lateral movement and C2 detection."
            priority = "recommended"
        elif "gateway" in src.lower() or "proxy" in src.lower():
            desc = "Web proxy or email gateway logs for phishing and web-based attack detection."
            priority = "optional"
        else:
            desc = f"Log source providing relevant telemetry for {src}."
            priority = "optional"

        sources.append({
            "name":        src,
            "description": desc,
            "priority":    priority,
        })

    return sources


# ── MITRE context builder ──────────────────────────────────────────────────────

def _build_mitre_context(technique: dict) -> dict:
    sub_techniques = []
    for sub_id in technique.get("sub_techniques", []):
        sub_tech = TECHNIQUES.get(sub_id)
        if sub_tech:
            sub_techniques.append({
                "id":          sub_id,
                "name":        sub_tech["name"],
                "description": sub_tech["description"][:200],
            })
        else:
            sub_techniques.append({"id": sub_id, "name": sub_id, "description": ""})

    related = []
    for rel_id in technique.get("related_techniques", []):
        rel_tech = TECHNIQUES.get(rel_id)
        if rel_tech:
            related.append({
                "id":     rel_id,
                "name":   rel_tech["name"],
                "tactic": rel_tech["tactic"],
            })
        else:
            related.append({"id": rel_id, "name": rel_id, "tactic": ""})

    tactic_info = TACTICS.get(technique["tactic_id"], {})

    return {
        "tactic_id":         technique["tactic_id"],
        "tactic_name":       technique["tactic"],
        "tactic_url":        f"https://attack.mitre.org/tactics/{technique['tactic_id']}/",
        "technique_url":     f"https://attack.mitre.org/techniques/{technique['id'].replace('.', '/')}/",
        "parent_id":         technique.get("parent_id"),
        "sub_techniques":    sub_techniques,
        "related_techniques": related,
        "detection_notes":   technique.get("detection_notes", ""),
    }


# ── Artifacts builder ──────────────────────────────────────────────────────────

def _build_artifacts(technique: dict) -> dict:
    return {
        "event_ids":   technique.get("event_ids", []),
        "log_sources": technique.get("log_sources", []),
        "field_names": technique.get("field_names", []),
        "processes":   technique.get("processes", []),
        "command_patterns": technique.get("command_patterns", []),
        "registry_keys": technique.get("registry_keys", []),
        "file_paths":  technique.get("file_paths", []),
        "network_ports": technique.get("network_ports", []),
        "raw_artifacts": technique.get("artifacts", {}),
    }


# ── PlaybookEngine ─────────────────────────────────────────────────────────────

class PlaybookEngine:
    """Core engine that generates and stores threat hunt playbooks."""

    def __init__(self, config: dict):
        self.config  = config
        self.storage = PlaybookStorage(config.get("db_path", "./huntforge.db"))
        self.qb      = QueryBuilder()
        logger.info("PlaybookEngine initialised")

    # ── Generate ───────────────────────────────────────────────────────────────

    def generate_playbook(
        self,
        technique_id: str,
        context: dict | None = None,
        output_format: str = "json",
        save: bool = True,
    ) -> dict:
        """
        Generate a complete hunt playbook for a MITRE technique.

        Args:
            technique_id:  MITRE ATT&CK technique ID (e.g., "T1059.001")
            context:       {"environment": "windows", "log_sources": [...]}
            output_format: "json" or "markdown"
            save:          Whether to persist the playbook to the database

        Returns: Full playbook dict
        """
        if context is None:
            context = {}

        technique = get_technique(technique_id.upper())
        if technique is None:
            return {
                "success": False,
                "error":   f"Technique '{technique_id}' not found in embedded database. "
                           f"Use /api/techniques to search available techniques.",
            }

        env  = context.get("environment", "windows")
        srcs = context.get("log_sources", [])

        # Check log source coverage
        required_sources = technique.get("log_sources", [])
        available_sources = [s.lower() for s in srcs]
        coverage = sum(
            1 for req in required_sources
            if any(a in req.lower() or req.lower() in a for a in available_sources)
        )
        coverage_pct = int((coverage / max(len(required_sources), 1)) * 100)

        # Adjust confidence based on available log sources
        base_confidence = technique.get("confidence_score", 5)
        adjusted_confidence = max(1, min(10, int(base_confidence * (0.5 + (coverage_pct / 200)))))
        if not srcs:
            adjusted_confidence = base_confidence  # No adjustment if no sources specified

        # Build playbook
        playbook = {
            "success":        True,
            "technique_id":   technique["id"],
            "technique_name": technique["name"],
            "tactic":         technique["tactic"],
            "tactic_id":      technique["tactic_id"],
            "description":    technique["description"],
            "hypothesis":     _build_hypothesis(technique, context),
            "context": {
                "environment": env,
                "log_sources": srcs,
            },
            "queries":        self.qb.build_all(technique, context),
            "artifacts":      _build_artifacts(technique),
            "mitre_context":  _build_mitre_context(technique),
            "suggested_log_sources": _build_suggested_sources(technique, env),
            "confidence": {
                "base_score":      base_confidence,
                "adjusted_score":  adjusted_confidence,
                "label":           _confidence_label(adjusted_confidence),
                "source_coverage": coverage_pct,
                "rationale":       technique.get("confidence_rationale", ""),
            },
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "generator":    "HuntForge v1.0.0",
        }

        if save:
            playbook = self.storage.save_playbook(playbook)

        logger.info(
            "Generated playbook for %s — %s (confidence: %d/10)",
            technique_id, technique["name"], adjusted_confidence
        )

        if output_format == "markdown":
            playbook["markdown"] = self.to_markdown(playbook)

        return playbook

    # ── Markdown export ────────────────────────────────────────────────────────

    def to_markdown(self, playbook: dict) -> str:
        tid   = playbook["technique_id"]
        name  = playbook["technique_name"]
        tactic = playbook["tactic"]
        conf  = playbook["confidence"]
        lines = [
            f"# Threat Hunt Playbook: {tid} — {name}",
            "",
            f"> **Tactic:** {tactic}  ",
            f"> **Confidence:** {conf['label']} ({conf['adjusted_score']}/10)  ",
            f"> **Generated:** {playbook['generated_at']}  ",
            f"> **Generator:** HuntForge v1.0.0",
            "",
            "---",
            "",
            "## Overview",
            "",
            playbook.get("description", ""),
            "",
            "## Hunt Hypothesis",
            "",
            playbook.get("hypothesis", ""),
            "",
            "---",
            "",
            "## Hunt Queries",
            "",
            "### Splunk SPL",
            "",
            "```spl",
            playbook["queries"].get("splunk", ""),
            "```",
            "",
            "### Wazuh / Elasticsearch JSON Filter",
            "",
            "```json",
            json.dumps(playbook["queries"].get("wazuh", {}), indent=2),
            "```",
            "",
            "### Sigma Rule",
            "",
            "```yaml",
            playbook["queries"].get("sigma", ""),
            "```",
            "",
            "### KQL (Microsoft Sentinel)",
            "",
            "```kql",
            playbook["queries"].get("kql", ""),
            "```",
            "",
            "---",
            "",
            "## Expected Artifacts",
            "",
            "### Windows Event IDs",
            "",
        ]

        event_ids = playbook["artifacts"].get("event_ids", [])
        if event_ids:
            for eid in event_ids:
                lines.append(f"- **{eid}** — {_event_id_description(eid)}")
        else:
            lines.append("- No specific Event IDs identified for this technique.")

        lines.extend(["", "### Log Sources", ""])
        for src in playbook["artifacts"].get("log_sources", []):
            lines.append(f"- `{src}`")

        lines.extend(["", "### Key Fields to Monitor", ""])
        for f in playbook["artifacts"].get("field_names", []):
            lines.append(f"- `{f}`")

        lines.extend(["", "### Processes of Interest", ""])
        procs = playbook["artifacts"].get("processes", [])
        if procs:
            for p in procs:
                lines.append(f"- `{p}`")
        else:
            lines.append("- No specific processes identified.")

        lines.extend(["", "### Command Patterns", ""])
        cmds = playbook["artifacts"].get("command_patterns", [])
        if cmds:
            for c in cmds:
                lines.append(f"- `{c}`")

        lines.extend(["", "### Registry Keys", ""])
        regs = playbook["artifacts"].get("registry_keys", [])
        if regs:
            for r in regs:
                lines.append(f"- `{r}`")

        lines.extend(["", "---", "", "## MITRE Context", ""])
        mc = playbook.get("mitre_context", {})

        lines.extend([
            f"- **Technique URL:** [{tid}]({mc.get('technique_url', '')})",
            f"- **Tactic:** [{tactic}]({mc.get('tactic_url', '')})",
        ])

        if mc.get("parent_id"):
            lines.append(f"- **Parent Technique:** [{mc['parent_id']}](https://attack.mitre.org/techniques/{mc['parent_id']}/)")

        sub_techs = mc.get("sub_techniques", [])
        if sub_techs:
            lines.extend(["", "### Sub-Techniques", ""])
            for st in sub_techs:
                lines.append(f"- **{st['id']}** — {st['name']}: {st.get('description', '')[:120]}")

        related = mc.get("related_techniques", [])
        if related:
            lines.extend(["", "### Related Techniques", ""])
            for rt in related:
                lines.append(f"- **{rt['id']}** — {rt['name']} ({rt.get('tactic', '')})")

        if mc.get("detection_notes"):
            lines.extend(["", "### Detection Notes", "", mc["detection_notes"]])

        lines.extend(["", "---", "", "## Suggested Log Sources", ""])
        for src in playbook.get("suggested_log_sources", []):
            priority_icon = {"required": "🔴", "recommended": "🟡", "optional": "🟢"}.get(
                src.get("priority", "optional"), "⚪"
            )
            lines.append(f"- {priority_icon} **{src['name']}** ({src['priority'].upper()})  ")
            lines.append(f"  {src['description']}")
            lines.append("")

        lines.extend([
            "---",
            "",
            "## Confidence Assessment",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Base Score | {conf['base_score']}/10 |",
            f"| Adjusted Score | {conf['adjusted_score']}/10 |",
            f"| Confidence Level | {conf['label']} |",
            f"| Log Source Coverage | {conf['source_coverage']}% |",
            "",
            conf.get("rationale", ""),
            "",
            "---",
            "",
            f"*Generated by HuntForge v1.0.0 — Rootless-Ghost / Nebula Forge Suite*",
        ])

        return "\n".join(lines)

    # ── Storage proxies ────────────────────────────────────────────────────────

    def get_playbooks(self, **kwargs) -> dict:
        return self.storage.list_playbooks(**kwargs)

    def get_playbook(self, playbook_id: str) -> dict | None:
        return self.storage.get_playbook(playbook_id)

    def delete_playbook(self, playbook_id: str) -> bool:
        return self.storage.delete_playbook(playbook_id)

    # ── Technique search proxy ─────────────────────────────────────────────────

    def search_techniques(self, query: str = "", tactic: str = "") -> list[dict]:
        if query:
            return search_techniques(query)
        return list_techniques(tactic)

    def get_technique(self, technique_id: str) -> dict | None:
        return get_technique(technique_id)


# ── Event ID descriptions ──────────────────────────────────────────────────────

def _event_id_description(eid: str) -> str:
    descriptions = {
        "1":    "Sysmon: Process Create",
        "3":    "Sysmon: Network Connection",
        "7":    "Sysmon: Image Loaded",
        "8":    "Sysmon: CreateRemoteThread",
        "10":   "Sysmon: ProcessAccess",
        "11":   "Sysmon: FileCreate",
        "12":   "Sysmon: RegistryEvent (Object create/delete)",
        "13":   "Sysmon: RegistryEvent (Value Set)",
        "14":   "Sysmon: RegistryEvent (Key and Value Rename)",
        "15":   "Sysmon: FileCreateStreamHash (ADS)",
        "17":   "Sysmon: PipeEvent (Created)",
        "18":   "Sysmon: PipeEvent (Connected)",
        "19":   "Sysmon: WmiEvent (WmiEventFilter activity)",
        "20":   "Sysmon: WmiEvent (WmiEventConsumer activity)",
        "21":   "Sysmon: WmiEvent (WmiEventConsumerToFilter)",
        "22":   "Sysmon: DNSEvent",
        "104":  "System: The System log file was cleared",
        "400":  "PowerShell: Engine state changed",
        "600":  "PowerShell: Provider lifecycle",
        "4103": "PowerShell: Module logging",
        "4104": "PowerShell: Script block logging",
        "4624": "Security: An account was successfully logged on",
        "4625": "Security: An account failed to log on",
        "4648": "Security: A logon was attempted using explicit credentials",
        "4656": "Security: A handle to an object was requested",
        "4657": "Security: A registry value was modified",
        "4663": "Security: An attempt was made to access an object",
        "4688": "Security: A new process has been created",
        "4697": "Security: A service was installed in the system",
        "4698": "Security: A scheduled task was created",
        "4699": "Security: A scheduled task was deleted",
        "4700": "Security: A scheduled task was enabled",
        "4701": "Security: A scheduled task was disabled",
        "4702": "Security: A scheduled task was updated",
        "4720": "Security: A user account was created",
        "4722": "Security: A user account was enabled",
        "4728": "Security: A member was added to a security-enabled global group",
        "4732": "Security: A member was added to a security-enabled local group",
        "4768": "Security: A Kerberos authentication ticket was requested",
        "4769": "Security: A Kerberos service ticket was requested",
        "4771": "Security: Kerberos pre-authentication failed",
        "4776": "Security: The domain controller attempted to validate credentials",
        "4778": "Security: A session was reconnected to a Window Station",
        "4779": "Security: A session was disconnected from a Window Station",
        "4798": "Security: A user's local group membership was enumerated",
        "4799": "Security: A security-enabled local group membership was enumerated",
        "5001": "Windows Defender: Real-time protection disabled",
        "5004": "Windows Defender: Real-time protection configuration changed",
        "5007": "Windows Defender: Antimalware platform configuration changed",
        "5140": "Security: A network share object was accessed",
        "5145": "Security: A network share object was checked for access",
        "5156": "Security: Windows Filtering Platform permitted a connection",
        "7040": "System: Service start type changed",
        "7045": "System: A new service was installed",
        "1102": "Security: The audit log was cleared",
    }
    return descriptions.get(str(eid), f"Event ID {eid}")
