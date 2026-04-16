"""Unit tests for catalog and content parsers using offline fixtures."""

import json
from pathlib import Path

import pytest

from medianav_toolbox.catalog import (
    parse_catalog_html,
    parse_licenses_response,
    parse_managecontent_html,
    parse_senddevicestatus_response,
    parse_update_selection,
)

FIXTURES = Path(__file__).parent / "data" / "fixtures"


@pytest.fixture
def catalog_html():
    return (FIXTURES / "cataloglist.html").read_text(errors="replace")


@pytest.fixture
def managecontent_html():
    return (FIXTURES / "managecontent.html").read_text(errors="replace")


@pytest.fixture
def updateselection_json():
    return json.loads((FIXTURES / "updateselection.json").read_text())


@pytest.fixture
def licenses_data():
    return (FIXTURES / "licenses_decoded.bin").read_bytes()


@pytest.fixture
def devicestatus_data():
    return (FIXTURES / "senddevicestatus_decoded.bin").read_bytes()


class TestParseCatalogHtml:
    def test_finds_items(self, catalog_html):
        items = parse_catalog_html(catalog_html)
        assert len(items) > 5

    def test_item_has_package_code(self, catalog_html):
        items = parse_catalog_html(catalog_html)
        assert all(item.package_code > 0 for item in items)

    def test_item_has_name(self, catalog_html):
        items = parse_catalog_html(catalog_html)
        named = [i for i in items if i.name]
        assert len(named) > 5

    def test_finds_uk_map(self, catalog_html):
        items = parse_catalog_html(catalog_html)
        uk = [i for i in items if "United Kingdom" in i.name]
        assert len(uk) >= 1
        assert uk[0].release  # has a version

    def test_finds_provider_tags(self, catalog_html):
        items = parse_catalog_html(catalog_html)
        nng = [i for i in items if i.provider == "NNG Maps"]
        assert len(nng) > 0

    def test_finds_content_types(self, catalog_html):
        items = parse_catalog_html(catalog_html)
        classes = {i.css_class for i in items}
        assert "content-osm" in classes  # map content


class TestParseManagecontentHtml:
    def test_finds_nodes(self, managecontent_html):
        nodes = parse_managecontent_html(managecontent_html)
        assert len(nodes) > 5

    def test_node_has_content_id(self, managecontent_html):
        nodes = parse_managecontent_html(managecontent_html)
        assert all("#" in n.content_id for n in nodes)

    def test_node_has_name(self, managecontent_html):
        nodes = parse_managecontent_html(managecontent_html)
        named = [n for n in nodes if n.name]
        assert len(named) > 5

    def test_finds_uk_map(self, managecontent_html):
        nodes = parse_managecontent_html(managecontent_html)
        uk = [n for n in nodes if "United Kingdom" in n.name]
        assert len(uk) >= 1

    def test_has_snapshot_codes(self, managecontent_html):
        nodes = parse_managecontent_html(managecontent_html)
        with_snap = [n for n in nodes if n.snapshot_code]
        assert len(with_snap) > 0


class TestParseUpdateSelection:
    def test_returns_sizes(self, updateselection_json):
        sizes, indicator = parse_update_selection(updateselection_json)
        assert len(sizes) == 32

    def test_size_has_id(self, updateselection_json):
        sizes, _ = parse_update_selection(updateselection_json)
        assert all("#" in s.content_id for s in sizes)

    def test_size_has_bytes(self, updateselection_json):
        sizes, _ = parse_update_selection(updateselection_json)
        assert all(s.size >= 0 for s in sizes)
        assert any(s.size > 0 for s in sizes)

    def test_returns_space_indicator(self, updateselection_json):
        _, indicator = parse_update_selection(updateselection_json)
        assert isinstance(indicator, dict)


class TestParseLicensesResponse:
    def test_finds_licenses(self, licenses_data):
        licenses = parse_licenses_response(licenses_data)
        assert len(licenses) == 3

    def test_license_has_lyc_file(self, licenses_data):
        licenses = parse_licenses_response(licenses_data)
        assert all(lic.lyc_file.endswith(".lyc") for lic in licenses)

    def test_license_has_swid(self, licenses_data):
        licenses = parse_licenses_response(licenses_data)
        assert all(lic.swid.startswith("CW-") for lic in licenses)

    def test_finds_uk_license(self, licenses_data):
        licenses = parse_licenses_response(licenses_data)
        uk = [l for l in licenses if "UK" in l.lyc_file]
        assert len(uk) == 1


class TestParseSenddevicestatusResponse:
    def test_has_process_id(self, devicestatus_data):
        result = parse_senddevicestatus_response(devicestatus_data)
        assert len(result["process_id"]) == 36  # UUID

    def test_has_task_id(self, devicestatus_data):
        result = parse_senddevicestatus_response(devicestatus_data)
        assert len(result["task_id"]) == 36

    def test_has_requested_paths(self, devicestatus_data):
        result = parse_senddevicestatus_response(devicestatus_data)
        assert len(result["requested_paths"]) > 0

    def test_requests_device_status_ini(self, devicestatus_data):
        result = parse_senddevicestatus_response(devicestatus_data)
        paths = result["requested_paths"]
        assert any("device_status.ini" in p for p in paths)

    def test_requests_nng_files(self, devicestatus_data):
        result = parse_senddevicestatus_response(devicestatus_data)
        paths = result["requested_paths"]
        assert any(".nng" in p for p in paths)
