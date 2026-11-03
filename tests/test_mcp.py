"""The stdio server registers the outreach tools and can save a lead."""

from __future__ import annotations

import sys
from pathlib import Path

import anyio
import pytest
from mcp import Client, StdioServerParameters

from openhunter.server import build_server

EXPECTED = {
    "domain_search",
    "email_pattern",
    "email_finder",
    "email_verifier",
    "save_lead",
    "list_leads",
    "export_leads",
}


def test_in_memory_server_lists_tools_and_saves_a_lead(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("OPENHUNTER_DB", str(tmp_path / "mcp.db"))
    server = build_server()

    async def run() -> None:
        async with Client(server) as client:
            listed = await client.list_tools()
            names = {tool.name for tool in listed.tools}
            assert names == EXPECTED
            for tool in listed.tools:
                assert tool.description
            saved = await client.call_tool(
                "save_lead",
                {
                    "email": "ada@example.com",
                    "name": "Ada Lovelace",
                    "domain": "example.com",
                    "role": "Engineer",
                    "source_url": "https://example.com/team",
                },
            )
            payload = saved.structured_content
            assert payload is not None
            assert payload["email"] == "ada@example.com"
            leads = await client.call_tool("list_leads", {"domain": "example.com"})
            assert leads.structured_content is not None
            assert leads.structured_content["count"] == 1

    anyio.run(run)


@pytest.mark.skipif(not Path(sys.executable).exists(), reason="need the test interpreter")
def test_stdio_process_lists_tools(tmp_path) -> None:
    db_path = tmp_path / "stdio.db"

    async def run() -> None:
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "openhunter.server"],
            env={"OPENHUNTER_DB": str(db_path)},
            cwd=str(Path(__file__).resolve().parents[1]),
        )
        async with Client(params) as client:
            listed = await client.list_tools()
            assert {tool.name for tool in listed.tools} == EXPECTED

    anyio.run(run)
