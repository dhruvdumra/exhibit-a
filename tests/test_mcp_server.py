"""The MCP server exposes ExhibitA's pipeline as agent tools."""

import asyncio

from exhibita.mcp_server import server


def _tools():
    return {t.name: t for t in asyncio.run(server.list_tools())}


def test_three_tools_registered():
    assert set(_tools()) == {"scan", "verify", "threat_model"}


def test_tools_have_descriptions_and_schemas():
    for name, tool in _tools().items():
        assert tool.description, f"{name} has no description"
        assert tool.input_schema, f"{name} has no input schema"
        assert "path" in str(tool.input_schema) or "image_path" in str(tool.input_schema)


def test_server_identity():
    assert server.name == "exhibita"
