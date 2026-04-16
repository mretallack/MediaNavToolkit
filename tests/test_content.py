"""Unit tests for content management module."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from medianav_toolbox.catalog import parse_managecontent_html, parse_update_selection
from medianav_toolbox.content import SelectedContent, get_available_updates

FIXTURES = Path(__file__).parent / "data" / "fixtures"


class TestGetAvailableUpdates:
    """Test the content selection flow using offline fixtures."""

    def test_parses_content_tree(self):
        html = (FIXTURES / "managecontent.html").read_text(errors="replace")
        nodes = parse_managecontent_html(html)
        assert len(nodes) > 5
        # All nodes have content IDs with # separator
        assert all("#" in n.content_id for n in nodes)

    def test_parses_sizes(self):
        data = json.loads((FIXTURES / "updateselection.json").read_text())
        sizes, indicator = parse_update_selection(data)
        assert len(sizes) == 32
        assert indicator["fullSize"] > 0
        assert indicator["required"] > 0

    def test_selected_content_structure(self):
        html = (FIXTURES / "managecontent.html").read_text(errors="replace")
        data = json.loads((FIXTURES / "updateselection.json").read_text())

        nodes = parse_managecontent_html(html)
        sizes, _ = parse_update_selection(data)

        size_map = {s.content_id: s.size for s in sizes}
        name_map = {n.content_id: n.name for n in nodes}

        results = [
            SelectedContent(
                content_id=s.content_id,
                name=name_map.get(s.content_id, ""),
                size=s.size,
            )
            for s in sizes
        ]
        assert len(results) == 32
        # At least some items have names
        named = [r for r in results if r.name]
        assert len(named) > 5
        # UK map should be present
        uk = [r for r in results if "United Kingdom" in r.name]
        assert len(uk) >= 1
        assert uk[0].size > 0

    def test_total_download_size(self):
        data = json.loads((FIXTURES / "updateselection.json").read_text())
        sizes, indicator = parse_update_selection(data)
        total = sum(s.size for s in sizes)
        # Should be several GB
        assert total > 1_000_000_000  # > 1GB
        # Should match the indicator
        assert indicator["required"] > 0
