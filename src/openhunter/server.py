"""MCP stdio server. The same operations are available from the CLI."""

from __future__ import annotations

import logging
import sys
from typing import Any

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from openhunter import __version__
from openhunter.errors import InputError
from openhunter.service import OpenHunter

INSTRUCTIONS = """
OpenHunter finds public professional contact data for targeted outreach.
It does not log into websites and it does not send email.

Use domain_search with a company domain (runpod.io) or a company name.
email_pattern reports the mailbox format those public addresses support.
email_finder ranks likely addresses for one person; a candidate is not a confirmed mailbox.
email_verifier checks syntax, MX, disposable and role inboxes, then probes SMTP RCPT
without sending mail. status unknown usually means outbound port 25 is blocked or the
server gave a temporary answer. status accept_all means the domain accepts every
address, so a positive RCPT does not prove the person exists.
Save people you intend to contact with save_lead. Verification results and searches
are cached in a local SQLite file.
""".strip()

_READ = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=True,
)
_LOCAL = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=False,
)
_WRITE = ToolAnnotations(
    read_only_hint=False,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=False,
)


def build_server() -> MCPServer:
    server = MCPServer(
        "openhunter",
        title="OpenHunter",
        instructions=INSTRUCTIONS,
        version=__version__,
        log_level="WARNING",
    )

    @server.tool(annotations=_READ)
    def domain_search(domain: str, limit: int = 25, refresh: bool = False) -> dict[str, Any]:
        """Find public people and emails for a company domain or company name.

        Sources are the company website (team, about, contact, security.txt) and
        the GitHub organization linked from that site or matching the domain:
        public members, public profile emails, and commit author emails. GitHub
        noreply addresses are omitted. Returns name, role, email, source URL,
        and confidence. Email may be null when a person is public but no mailbox
        is. Set GITHUB_TOKEN to raise the GitHub rate limit.
        """
        return _call(lambda service: service.domain_search(domain, limit=limit, refresh=refresh))

    @server.tool(annotations=_READ)
    def email_pattern(domain: str, refresh: bool = False) -> dict[str, Any]:
        """Infer the company mailbox pattern from public addresses already found.

        Patterns look like first.last or flast. Confidence falls quickly when
        only one or two named addresses agree, and a structural guess without
        names never exceeds 0.34. Role inboxes such as info@ are not evidence.
        """
        return _call(lambda service: service.email_pattern(domain, refresh=refresh))

    @server.tool(annotations=_READ)
    def email_finder(first_name: str, last_name: str, domain: str) -> dict[str, Any]:
        """Rank likely email addresses for one person at a domain.

        The inferred company pattern is ranked first when one exists. Other
        common corporate patterns are included as lower-scored fallbacks.
        This does not verify the addresses; call email_verifier on the ones
        you might use.
        """
        return _call(lambda service: service.email_finder(first_name, last_name, domain))

    @server.tool(annotations=_READ)
    def email_verifier(email: str, refresh: bool = False) -> dict[str, Any]:
        """Check an address without sending mail.

        Runs syntax, MX lookup, disposable-domain and role-address detection,
        then an SMTP RCPT probe with a catch-all check. status is valid,
        invalid, accept_all, or unknown. unknown with a port 25 note means the
        probe could not reach the mail server. accept_all means the domain
        accepted a nonexistent mailbox too.
        """
        return _call(lambda service: service.email_verifier(email, refresh=refresh))

    @server.tool(annotations=_WRITE)
    def save_lead(
        email: str | None = None,
        name: str | None = None,
        first_name: str | None = None,
        last_name: str | None = None,
        role: str | None = None,
        company: str | None = None,
        domain: str | None = None,
        source_url: str | None = None,
        confidence: float | None = None,
        notes: str | None = None,
    ) -> dict[str, Any]:
        """Save a person to the local lead list. The same email and domain updates the existing row."""
        return _call(
            lambda service: service.save_lead(
                email=email,
                name=name,
                first_name=first_name,
                last_name=last_name,
                role=role,
                company=company,
                domain=domain,
                source_url=source_url,
                confidence=confidence,
                notes=notes,
            )
        )

    @server.tool(annotations=_LOCAL)
    def list_leads(domain: str | None = None, limit: int = 100) -> dict[str, Any]:
        """List saved leads, optionally limited to one domain."""
        return _call(lambda service: service.list_leads(domain=domain, limit=limit))

    @server.tool(annotations=_WRITE)
    def export_leads(path: str, domain: str | None = None) -> dict[str, Any]:
        """Write saved leads to a CSV file and return the path and row count."""
        return _call(lambda service: service.export_leads(path, domain=domain))

    return server


def main() -> None:
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr, format="%(levelname)s %(name)s: %(message)s")
    build_server().run(transport="stdio")


def _call(action):
    service = OpenHunter.from_env()
    try:
        return action(service)
    except InputError as exc:
        raise ToolError(str(exc)) from exc
    finally:
        service.close()


if __name__ == "__main__":
    main()
