"""
HuntForge — Query Builder
Generates Splunk SPL, Wazuh JSON filter, Sigma YAML, and KQL queries
from MITRE technique data and hunt context.
"""

import re
from datetime import datetime


class QueryBuilder:
    """Builds hunt queries for multiple SIEM/EDR platforms."""

    # ── Splunk SPL ─────────────────────────────────────────────────────────────

    def build_splunk_spl(self, technique: dict, context: dict) -> str:
        tid    = technique["id"]
        name   = technique["name"]
        env    = context.get("environment", "windows")
        sources = context.get("log_sources", [])

        processes   = technique.get("processes", [])
        event_ids   = technique.get("event_ids", [])
        cmd_patterns = technique.get("command_patterns", [])
        reg_keys     = technique.get("registry_keys", [])
        log_sources  = technique.get("log_sources", [])

        lines = [f"| comment \"Hunt: {tid} — {name}\""]

        # Build index/source filter
        sysmon_sources = [s for s in log_sources if "sysmon" in s.lower()]
        winevent_sources = [s for s in log_sources if "WinEventLog" in s]

        if event_ids:
            eid_str = " OR ".join(f"EventCode={e}" for e in event_ids)
            lines.append(f"index=* ({eid_str})")
        else:
            lines.append("index=*")

        # Process filter
        if processes:
            proc_str = " OR ".join(f'Image="*{p}*" OR process_name="{p}"' for p in processes)
            lines.append(f"| where ({proc_str})")

        # Command patterns
        if cmd_patterns:
            pattern_str = " OR ".join(
                f'CommandLine="*{p}*"' for p in cmd_patterns[:6]
            )
            lines.append(f"| where ({pattern_str})")

        # Registry key filter
        if reg_keys:
            reg_str = " OR ".join(f'TargetObject="*{r.split(chr(92))[-1]}*"' for r in reg_keys[:3])
            lines.append(f"| where ({reg_str})")

        # Network ports
        net_ports = technique.get("network_ports", [])
        if net_ports and "network" in str(sources).lower():
            port_str = " OR ".join(f"DestinationPort={p}" for p in net_ports)
            lines.append(f"| where ({port_str})")

        # Standard eval and output fields
        lines.extend([
            f'| eval technique="{tid}", technique_name="{name}"',
            "| eval hunt_timestamp=strftime(_time, \"%Y-%m-%d %H:%M:%S\")",
            "| table hunt_timestamp, host, EventCode, Image, CommandLine,",
            "        ParentImage, ParentCommandLine, User, technique",
            "| sort -_time",
        ])

        return "\n".join(lines)

    # ── Wazuh JSON filter ──────────────────────────────────────────────────────

    def build_wazuh_filter(self, technique: dict, context: dict) -> dict:
        tid        = technique["id"]
        name       = technique["name"]
        event_ids  = technique.get("event_ids", [])
        processes  = technique.get("processes", [])
        cmd_pats   = technique.get("command_patterns", [])
        reg_keys   = technique.get("registry_keys", [])

        must_clauses = []
        should_clauses = []

        # Event ID filter
        if event_ids:
            if len(event_ids) == 1:
                must_clauses.append({
                    "match": {"data.win.system.eventID": event_ids[0]}
                })
            else:
                should_clauses.extend([
                    {"match": {"data.win.system.eventID": eid}}
                    for eid in event_ids
                ])

        # Process name filter
        if processes:
            proc_should = [
                {"wildcard": {"data.win.eventdata.image": f"*{p}"}}
                for p in processes
            ]
            if proc_should:
                should_clauses.extend(proc_should)

        # Command line patterns
        if cmd_pats:
            cmd_should = [
                {"wildcard": {"data.win.eventdata.commandLine": f"*{p}*"}}
                for p in cmd_pats[:4]
            ]
            should_clauses.extend(cmd_should)

        # Registry keys
        if reg_keys:
            reg_should = [
                {"wildcard": {"data.win.eventdata.targetObject": f"*{r.split(chr(92))[-1]}*"}}
                for r in reg_keys[:2]
            ]
            should_clauses.extend(reg_should)

        query_body: dict = {"bool": {}}
        if must_clauses:
            query_body["bool"]["must"] = must_clauses
        if should_clauses:
            query_body["bool"]["should"] = should_clauses
            query_body["bool"]["minimum_should_match"] = 1

        return {
            "_comment": f"Wazuh/Elasticsearch hunt filter for {tid} — {name}",
            "query": query_body,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "size": 500,
            "_source": [
                "@timestamp", "agent.name", "agent.ip",
                "data.win.system.eventID", "data.win.system.message",
                "data.win.eventdata.commandLine", "data.win.eventdata.image",
                "data.win.eventdata.parentImage", "data.win.eventdata.targetObject",
                "rule.id", "rule.description", "rule.level"
            ]
        }

    # ── Sigma YAML ─────────────────────────────────────────────────────────────

    def build_sigma_rule(self, technique: dict, context: dict) -> str:
        tid        = technique["id"]
        name       = technique["name"]
        tactic     = technique["tactic"]
        tactic_id  = technique["tactic_id"]
        description = technique.get("description", "")[:200]
        event_ids  = technique.get("event_ids", [])
        processes  = technique.get("processes", [])
        cmd_pats   = technique.get("command_patterns", [])
        reg_keys   = technique.get("registry_keys", [])
        log_sources = technique.get("log_sources", [])
        score       = technique.get("confidence_score", 5)
        env         = context.get("environment", "windows")

        # Determine Sigma level from confidence score
        if score >= 8:
            sigma_level = "high"
        elif score >= 6:
            sigma_level = "medium"
        else:
            sigma_level = "low"

        # Determine logsource
        if any("PowerShell" in s for s in log_sources):
            product  = "windows"
            category = "ps_script"
            service  = "powershell"
        elif any("Sysmon" in s for s in log_sources):
            product  = "windows"
            category = "process_creation"
            service  = "sysmon"
        elif any("Security" in s for s in log_sources):
            product = "windows"
            category = ""
            service  = "security"
        else:
            product  = "windows"
            category = "process_creation"
            service  = ""

        # Build detection conditions
        detection_lines = ["    keywords:"]

        if processes:
            for proc in processes[:4]:
                detection_lines.append(f"        - '{proc}'")

        if cmd_pats:
            detection_lines = ["    selection:"]
            if event_ids:
                detection_lines.append(f"        EventID:")
                for eid in event_ids[:3]:
                    detection_lines.append(f"            - {eid}")
            detection_lines.append("        CommandLine|contains:")
            for pat in cmd_pats[:6]:
                safe_pat = pat.replace("'", "\\'")
                detection_lines.append(f"            - '{safe_pat}'")
        elif reg_keys:
            detection_lines = ["    selection:"]
            detection_lines.append("        TargetObject|contains:")
            for rk in reg_keys[:3]:
                last_part = rk.split("\\")[-1]
                detection_lines.append(f"            - '{last_part}'")
        elif event_ids and not cmd_pats:
            detection_lines = ["    selection:"]
            detection_lines.append("        EventID:")
            for eid in event_ids[:3]:
                detection_lines.append(f"            - {eid}")
            if processes:
                detection_lines.append("        Image|endswith:")
                for proc in processes[:3]:
                    detection_lines.append(f"            - '\\{proc}'")

        detection_condition = "keywords" if "keywords:" in "\n".join(detection_lines) else "selection"

        # Assemble logsource block
        logsource_block = "logsource:\n"
        logsource_block += f"    product: {product}\n"
        if category:
            logsource_block += f"    category: {category}\n"
        if service:
            logsource_block += f"    service: {service}\n"

        sigma_rule = f"""title: Hunt for {name} ({tid})
id: huntforge-{tid.lower().replace('.', '-')}-{datetime.utcnow().strftime('%Y%m%d')}
status: experimental
description: |
    {description[:180]}
    Generated by HuntForge for threat hunting purposes.
author: HuntForge / Rootless-Ghost
date: {datetime.utcnow().strftime('%Y/%m/%d')}
references:
    - https://attack.mitre.org/techniques/{tid.replace('.', '/')}
tags:
    - attack.{tactic.lower().replace(' ', '_')}
    - attack.{tid.lower()}
    - attack.{tactic_id.lower()}
{logsource_block}
detection:
{"chr(10)".join(detection_lines)}

    condition: {detection_condition}

falsepositives:
    - Legitimate administrative activity
    - Security tools and scanners
    - Automated deployment systems

level: {sigma_level}

# Hunt Notes:
# Technique: {tid} — {name}
# Tactic:    {tactic} ({tactic_id})
# Confidence Score: {score}/10
# Environment: {env}
"""
        return sigma_rule.replace("chr(10)", "\n")

    # ── KQL (Microsoft Sentinel) ───────────────────────────────────────────────

    def build_kql(self, technique: dict, context: dict) -> str:
        tid        = technique["id"]
        name       = technique["name"]
        tactic     = technique["tactic"]
        event_ids  = technique.get("event_ids", [])
        processes  = technique.get("processes", [])
        cmd_pats   = technique.get("command_patterns", [])
        reg_keys   = technique.get("registry_keys", [])
        log_sources = technique.get("log_sources", [])
        env        = context.get("environment", "windows")

        # Determine primary KQL table
        if any("PowerShell" in s for s in log_sources):
            table = "Event"
            id_field = "EventID"
        elif any("Sysmon" in s for s in log_sources) or any(
            eid in event_ids for eid in ["4688", "1"]
        ):
            table = "SecurityEvent"
            id_field = "EventID"
        elif any("Security" in s for s in log_sources):
            table = "SecurityEvent"
            id_field = "EventID"
        else:
            table = "SecurityEvent"
            id_field = "EventID"

        lines = [
            f"// Hunt Query: {tid} — {name}",
            f"// Tactic: {tactic}",
            f"// Generated by HuntForge | {datetime.utcnow().strftime('%Y-%m-%d')}",
            "",
        ]

        # Start table reference
        if any("PowerShell" in s for s in log_sources) and "4104" in event_ids:
            lines.extend([
                "// Primary: PowerShell Script Block Logging",
                "Event",
                f"| where TimeGenerated > ago(7d)",
                f"| where Source == \"Microsoft-Windows-PowerShell\"",
                f"| where EventID in (4103, 4104)",
            ])
            if cmd_pats:
                pats = ", ".join(f'"{p}"' for p in cmd_pats[:5])
                lines.append(f"| where RenderedDescription has_any ({pats})")
            lines.extend([
                "| extend ParsedMessage = parse_xml(EventData)",
                "| project TimeGenerated, Computer, EventID, RenderedDescription",
            ])
        else:
            lines.extend([
                table,
                f"| where TimeGenerated > ago(7d)",
            ])

            if event_ids:
                eid_str = ", ".join(event_ids)
                lines.append(f"| where EventID in ({eid_str})")

            if processes:
                proc_contains = " or ".join(
                    f'Process has "{p}"' for p in processes[:4]
                )
                lines.append(f"| where {proc_contains}")

            if cmd_pats:
                cmd_conditions = " or ".join(
                    f'CommandLine has "{p}"' for p in cmd_pats[:5]
                )
                lines.append(f"| where {cmd_conditions}")

            if reg_keys:
                reg_conditions = " or ".join(
                    f'ObjectName has "{rk.split(chr(92))[-1]}"' for rk in reg_keys[:3]
                )
                lines.append(f"| where {reg_conditions}")

            lines.extend([
                "| extend",
                f'    Technique = "{tid}",',
                f'    TechniqueName = "{name}",',
                f'    Tactic = "{tactic}"',
                "| project TimeGenerated, Computer, Account, EventID, Process,",
                "          CommandLine, ParentProcessName, Technique, TechniqueName",
                "| order by TimeGenerated desc",
            ])

        # Add summary block
        lines.extend([
            "",
            f"// ── Summary by host ──────────────────────────────",
            f"// Uncomment below to get counts per host",
            f"// | summarize HuntHits=count() by Computer, bin(TimeGenerated, 1h)",
            f"// | order by HuntHits desc",
        ])

        return "\n".join(lines).replace("chr(10)", "\\")

    # ── All queries ────────────────────────────────────────────────────────────

    def build_all(self, technique: dict, context: dict) -> dict:
        return {
            "splunk":  self.build_splunk_spl(technique, context),
            "wazuh":   self.build_wazuh_filter(technique, context),
            "sigma":   self.build_sigma_rule(technique, context),
            "kql":     self.build_kql(technique, context),
        }
