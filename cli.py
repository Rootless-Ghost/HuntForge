#!/usr/bin/env python3
"""
HuntForge CLI
Generate threat hunt playbooks from the command line.

Usage:
    python cli.py --technique T1059.001 --env windows --sources sysmon,wazuh --output playbook.md
    python cli.py --technique T1059.001 --format json
    python cli.py --search powershell
    python cli.py --list-tactics
"""

import argparse
import json
import os
import sys

# Allow running from project root
sys.path.insert(0, os.path.dirname(__file__))

from core.engine import PlaybookEngine
from core.mitre_data import list_techniques, TACTICS


def _print_table(items: list[dict], cols: list[tuple[str, str, int]]) -> None:
    """Print a formatted table. cols: [(header, field, width), ...]"""
    sep = "  "
    header = sep.join(h.ljust(w) for h, _, w in cols)
    print(header)
    print("-" * len(header))
    for item in items:
        row = sep.join(str(item.get(f, "")).ljust(w)[:w] for _, f, w in cols)
        print(row)


def cmd_generate(args: argparse.Namespace, engine: PlaybookEngine) -> None:
    technique_id = args.technique.strip().upper()
    env          = args.env or "windows"
    sources      = [s.strip() for s in (args.sources or "").split(",") if s.strip()]
    fmt          = args.format or "markdown"
    output       = args.output

    context = {"environment": env, "log_sources": sources}

    print(f"[+] Generating playbook for {technique_id} (env={env}, sources={sources or 'all'})")

    result = engine.generate_playbook(
        technique_id=technique_id,
        context=context,
        output_format=fmt,
        save=not args.no_save,
    )

    if not result.get("success"):
        print(f"[!] Error: {result.get('error')}", file=sys.stderr)
        sys.exit(1)

    print(f"[+] Generated: {result['technique_name']} ({result['tactic']})")
    print(f"[+] Confidence: {result['confidence']['label']} ({result['confidence']['adjusted_score']}/10)")

    if output:
        if fmt == "markdown":
            content = result.get("markdown", "")
            if not content:
                from core.engine import PlaybookEngine as PE
                content = engine._to_markdown(result)
        else:
            content = json.dumps(result, indent=2, ensure_ascii=False)

        with open(output, "w", encoding="utf-8") as fh:
            fh.write(content)
        print(f"[+] Saved to: {output}")
    else:
        if fmt == "markdown":
            content = result.get("markdown", "")
            if not content:
                content = engine._to_markdown(result)
            print("\n" + content)
        else:
            print("\n" + json.dumps(result, indent=2, ensure_ascii=False))


def cmd_search(args: argparse.Namespace, engine: PlaybookEngine) -> None:
    results = engine.search_techniques(query=args.search)
    if not results:
        print(f"No techniques found for: {args.search!r}")
        return

    print(f"\n{len(results)} technique(s) matching '{args.search}':\n")
    _print_table(results, [
        ("ID",         "id",             12),
        ("Name",       "name",           35),
        ("Tactic",     "tactic",         22),
        ("Confidence", "confidence_score", 10),
    ])


def cmd_list(args: argparse.Namespace) -> None:
    tactic = getattr(args, "tactic_filter", "")
    items  = list_techniques(tactic)
    print(f"\n{len(items)} technique(s):\n")
    _print_table(items, [
        ("ID",         "id",             12),
        ("Name",       "name",           35),
        ("Tactic",     "tactic",         22),
        ("Conf.",      "confidence_score", 6),
        ("Sub-techs",  "sub_techniques",  10),
    ])


def cmd_list_tactics() -> None:
    print("\nMITRE ATT&CK Tactics:\n")
    _print_table(list(TACTICS.values()), [
        ("ID",       "id",        8),
        ("Name",     "name",      28),
        ("Shortname","shortname", 25),
    ])


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="huntforge",
        description="HuntForge — Threat Hunt Playbook Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --technique T1059.001 --env windows --sources sysmon,wazuh
  %(prog)s --technique T1059.001 --format markdown --output playbook.md
  %(prog)s --search powershell
  %(prog)s --list
  %(prog)s --list --tactic Execution
  %(prog)s --list-tactics
        """,
    )

    # Mutually exclusive modes
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--technique", "-t", metavar="ID",
                      help="MITRE technique ID to hunt (e.g. T1059.001)")
    mode.add_argument("--search", "-s", metavar="QUERY",
                      help="Search techniques by keyword")
    mode.add_argument("--list", action="store_true",
                      help="List all available techniques")
    mode.add_argument("--list-tactics", action="store_true",
                      help="List all MITRE tactics")

    # Generation options
    parser.add_argument("--env", "-e", default="windows",
                        choices=["windows", "linux", "cloud"],
                        help="Target environment (default: windows)")
    parser.add_argument("--sources", metavar="SOURCES",
                        help="Comma-separated log sources (e.g. sysmon,wazuh,splunk)")
    parser.add_argument("--format", "-f", default="markdown",
                        choices=["json", "markdown"],
                        help="Output format (default: markdown)")
    parser.add_argument("--output", "-o", metavar="FILE",
                        help="Save output to file")
    parser.add_argument("--no-save", action="store_true",
                        help="Do not save playbook to database")

    # Filtering options for --list
    parser.add_argument("--tactic", dest="tactic_filter", metavar="TACTIC",
                        help="Filter by tactic name when using --list")

    # App config
    parser.add_argument("--config", default="config.yaml",
                        help="Path to config.yaml (default: config.yaml)")

    args = parser.parse_args()

    if args.list_tactics:
        cmd_list_tactics()
        return

    if args.list:
        cmd_list(args)
        return

    if args.search:
        # Search doesn't need engine/DB
        sys.path.insert(0, os.path.dirname(__file__))
        from core.engine import PlaybookEngine
        engine = PlaybookEngine({"db_path": ":memory:"})
        cmd_search(args, engine)
        return

    if not args.technique:
        parser.print_help()
        sys.exit(0)

    # Load config
    import yaml
    config = {
        "port":    5007,
        "db_path": "./huntforge.db",
        "output_dir": "./output",
    }
    if os.path.exists(args.config):
        try:
            with open(args.config, encoding="utf-8") as fh:
                loaded = yaml.safe_load(fh) or {}
            config.update(loaded)
        except Exception:
            pass

    engine = PlaybookEngine(config)
    cmd_generate(args, engine)


if __name__ == "__main__":
    main()
