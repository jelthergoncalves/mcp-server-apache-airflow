"""Tests for the MCP_MAX_OUTPUT_CHARS output cap."""

import mcp.types as types
import pytest
from fastmcp.tools import Tool

from src.airflow.taskinstance import get_log
from src.main import cap_output


def _text(n: int) -> list:
    return [types.TextContent(type="text", text="H" * (n // 2) + "M" * (n - n // 2 * 2) + "T" * (n // 2))]


async def _big(dag_id: str, count: int = 1) -> list:
    return _text(1000)


def _big_sync(dag_id: str) -> list:
    return _text(1000)


@pytest.mark.asyncio
async def test_over_cap_keeps_head_marker_tail():
    out = await cap_output(_big, 100)("d")
    text = out[0].text
    assert text.startswith("H" * 50) and text.endswith("T" * 50)
    assert "TRUNCATED: showing 100 of 1000 chars" in text
    assert "finops-developer-explorer" in text
    assert len(text) < 300


@pytest.mark.asyncio
async def test_under_cap_unchanged():
    assert (await cap_output(_big, 5000)("d"))[0].text == _text(1000)[0].text


def test_cap_zero_returns_same_function():
    assert cap_output(_big, 0) is _big


def test_sync_tool_supported():
    assert "TRUNCATED" in cap_output(_big_sync, 100)("d")[0].text


@pytest.mark.asyncio
async def test_non_list_result_passthrough():
    async def f() -> str:
        return "x" * 1000

    assert await cap_output(f, 10)() == "x" * 1000


def test_tool_schema_unchanged_by_wrapper():
    plain = Tool.from_function(get_log, name="get_log", description="d")
    capped = Tool.from_function(cap_output(get_log, 100), name="get_log", description="d")
    assert plain.parameters == capped.parameters
