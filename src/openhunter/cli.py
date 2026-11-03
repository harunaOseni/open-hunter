"""Command-line interface for the same operations the MCP server exposes."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys

from openhunter import __version__
from openhunter.errors import InputError, OpenHunterError
from openhunter.server import main as serve_mcp
from openhunter.service import OpenHunter


def main(argv: list[str] | None = None) -> int:
    _configure_logging()
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        return _run(args)
    except InputError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except OpenHunterError as exc:
        print(str(exc), file=sys.stderr)
        return 1


def _run(args: argparse.Namespace) -> int:
    if args.command == "mcp":
        serve_mcp()
        return 0
    if args.command == "leads" and args.lead_command == "save":
        if not args.email and not args.name and not args.first:
            print("A lead needs an email or a name.", file=sys.stderr)
            raise SystemExit(2)
    service = OpenHunter.from_env()
    try:
        payload = _dispatch(service, args)
    finally:
        service.close()
    if payload is None:
        return 0
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        _print_human(args, payload)
    return 0


def _dispatch(service: OpenHunter, args: argparse.Namespace) -> dict[str, object] | None:
    if args.command == "domain-search":
        return service.domain_search(args.query, limit=args.limit, refresh=args.refresh)
    if args.command == "pattern":
        return service.email_pattern(args.query, refresh=args.refresh)
    if args.command == "find":
        return service.email_finder(args.first, args.last, args.domain)
    if args.command == "verify":
        return service.email_verifier(args.email, refresh=args.refresh)
    if args.command == "leads" and args.lead_command == "save":
        return service.save_lead(
            email=args.email,
            name=args.name,
            first_name=args.first,
            last_name=args.last,
            role=args.role,
            company=args.company,
            domain=args.domain,
            source_url=args.source,
            notes=args.notes,
        )
    if args.command == "leads" and args.lead_command == "list":
        return service.list_leads(domain=args.domain, limit=args.limit)
    if args.command == "leads" and args.lead_command == "export":
        return service.export_leads(args.path, domain=args.domain)
    raise SystemExit(2)


def _print_human(args: argparse.Namespace, payload: dict[str, object]) -> None:
    if args.command == "domain-search":
        _print_search(payload)
        return
    if args.command == "pattern":
        _print_pattern(payload)
        return
    if args.command == "find":
        _print_candidates(payload)
        return
    if args.command == "verify":
        _print_verification(payload)
        return
    if args.command == "leads" and args.lead_command == "list":
        _print_leads(payload)
        return
    if args.command == "leads" and args.lead_command == "save":
        print(f"Saved {payload.get('email') or payload.get('full_name')}")
        return
    if args.command == "leads" and args.lead_command == "export":
        print(f"Wrote {payload.get('count')} leads to {payload.get('path')}")
        return
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def _print_search(payload: dict[str, object]) -> None:
    domain = payload.get("domain") or "(unresolved)"
    company = payload.get("company") or ""
    cached = "cached" if payload.get("from_cache") else "live"
    print(f"{domain}  {company}  ({cached})")
    pattern = payload.get("pattern")
    if isinstance(pattern, dict) and pattern.get("pattern"):
        print(
            f"pattern: {pattern.get('pattern')}  confidence {pattern.get('confidence')}  "
            f"({pattern.get('method')}, {pattern.get('matched_count')}/{pattern.get('sample_count')})"
        )
    people = payload.get("people")
    if not isinstance(people, list) or not people:
        print("No public people or emails found.")
    else:
        for person in people:
            if not isinstance(person, dict):
                continue
            seen = ""
            first_seen = person.get("first_seen")
            if isinstance(first_seen, str) and first_seen:
                seen = f"  seen {first_seen[:10]}"
            print(
                "  "
                + "  ".join(
                    str(person.get(key) or "-")
                    for key in ("name", "role", "email", "confidence", "source", "source_url")
                )
                + seen
            )
    notes = payload.get("notes")
    if isinstance(notes, list):
        for note in notes:
            print(f"note: {note}")


def _print_pattern(payload: dict[str, object]) -> None:
    if not payload.get("pattern"):
        print(f"No pattern inferred for {payload.get('domain')}.")
    else:
        print(
            f"{payload.get('domain')}: {payload.get('pattern')}  "
            f"confidence {payload.get('confidence')}  method {payload.get('method')}"
        )
    notes = payload.get("notes")
    if isinstance(notes, list):
        for note in notes:
            print(f"note: {note}")


def _print_candidates(payload: dict[str, object]) -> None:
    candidates = payload.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        print("No candidates.")
        return
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        print(
            f"{candidate.get('rank')}. {candidate.get('email')}  "
            f"{candidate.get('pattern')}  score {candidate.get('score')}  {candidate.get('reason')}"
        )


def _print_verification(payload: dict[str, object]) -> None:
    print(
        f"{payload.get('email')}  {payload.get('status')}  score {payload.get('score')}  "
        f"disposable={payload.get('is_disposable')}  role={payload.get('is_role')}"
    )
    notes = payload.get("notes")
    if isinstance(notes, list):
        for note in notes:
            print(f"note: {note}")


def _print_leads(payload: dict[str, object]) -> None:
    leads = payload.get("leads")
    if not isinstance(leads, list) or not leads:
        print("No saved leads.")
        return
    for lead in leads:
        if not isinstance(lead, dict):
            continue
        print(
            f"{lead.get('email') or '-'}  {lead.get('full_name') or ''}  "
            f"{lead.get('role') or ''}  {lead.get('domain') or ''}"
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="openhunter",
        description="Find public company emails and rank likely addresses. No paid APIs.",
    )
    parser.add_argument("--version", action="version", version=f"openhunter {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    search = commands.add_parser("domain-search", help="Find public people and emails at a domain or company")
    search.add_argument("query")
    search.add_argument("--limit", type=int, default=25)
    search.add_argument("--refresh", action="store_true")
    _json_flag(search)

    pattern = commands.add_parser("pattern", help="Infer the company mailbox pattern")
    pattern.add_argument("query")
    pattern.add_argument("--refresh", action="store_true")
    _json_flag(pattern)

    find = commands.add_parser("find", help="Rank likely addresses for one person")
    find.add_argument("--first", required=True)
    find.add_argument("--last", required=True)
    find.add_argument("--domain", required=True)
    _json_flag(find)

    verify = commands.add_parser("verify", help="Check syntax, MX, and SMTP RCPT without sending mail")
    verify.add_argument("email")
    verify.add_argument("--refresh", action="store_true")
    _json_flag(verify)

    leads = commands.add_parser("leads", help="Save and export the local lead list")
    lead_commands = leads.add_subparsers(dest="lead_command", required=True)
    save = lead_commands.add_parser("save")
    save.add_argument("--email")
    save.add_argument("--name")
    save.add_argument("--first")
    save.add_argument("--last")
    save.add_argument("--role")
    save.add_argument("--company")
    save.add_argument("--domain")
    save.add_argument("--source")
    save.add_argument("--notes")
    _json_flag(save)
    listing = lead_commands.add_parser("list")
    listing.add_argument("--domain")
    listing.add_argument("--limit", type=int, default=100)
    _json_flag(listing)
    export = lead_commands.add_parser("export")
    export.add_argument("path")
    export.add_argument("--domain")
    _json_flag(export)

    commands.add_parser("mcp", help="Run the MCP stdio server")
    return parser


def _json_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="Print the raw result as JSON")


def _configure_logging() -> None:
    level = _log_level()
    logging.basicConfig(level=level, stream=sys.stderr, format="%(levelname)s %(name)s: %(message)s")


def _log_level() -> int:
    name = os.environ.get("OPENHUNTER_LOG", "WARNING").upper()
    return getattr(logging, name, logging.WARNING)
