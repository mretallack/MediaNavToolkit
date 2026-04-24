"""Test USB layout generation and senddevicestatus body against reference.

Uses analysis/usb-images-latest as the reference layout (created by the real
head unit + Toolbox). Verifies that:
1. build_live_senddevicestatus produces a structurally valid body
2. License installation creates the correct file layout
3. The body structure matches the captured run34 reference
"""

import hashlib
import shutil
import struct
from pathlib import Path

import pytest

from medianav_toolbox.crypto import snakeoil

REF_USB = Path("analysis/usb-images-latest")
RUN34_WIRE = Path("analysis/captures/run34/wire_19_1236.bin")


@pytest.fixture
def usb_copy(tmp_path):
    """Create a writable copy of the reference USB image."""
    if not REF_USB.exists():
        pytest.skip("Reference USB image not available")
    dst = tmp_path / "usb"
    shutil.copytree(REF_USB, dst)
    return dst


@pytest.fixture
def ref_body():
    """Decrypt the run34 senddevicestatus body (known to return 200)."""
    if not RUN34_WIRE.exists():
        pytest.skip("Run34 capture not available")
    wire = RUN34_WIRE.read_bytes()
    return snakeoil(wire[35:], 0x000ACAB6C9FB66F8)


def parse_entries(body, start):
    """Parse file entries from body, return list of (marker, filename) tuples."""
    entries = []
    p = start
    while p < len(body) - 10:
        marker = body[p]
        if marker == 0xE0:
            p += 1
            l = body[p]
            p += 1 + l  # content md5
            p += 2  # sub-marker
            l = body[p]
            p += 1 + l  # file md5
            l = body[p]
            fname = body[p + 1 : p + 1 + l]
            p += 1 + l
            l = body[p]
            p += 1 + l  # mount
            l = body[p]
            p += 1 + l  # path
            p += 24  # 3x int64
            entries.append((0xE0, fname.decode("ascii")))
        elif marker == 0x22:
            p += 1
            l = body[p]
            name = body[p + 1 : p + 1 + l]
            p += 1 + l
            l = body[p]
            p += 1 + l
            l = body[p]
            p += 1 + l
            p += 24
            entries.append((0x22, name.decode("ascii")))
        elif marker == 0xA0:
            p += 1
            l = body[p]
            p += 1 + l  # md5
            l = body[p]
            fname = body[p + 1 : p + 1 + l]
            p += 1 + l
            l = body[p]
            p += 1 + l
            l = body[p]
            p += 1 + l
            p += 24
            entries.append((0xA0, fname.decode("ascii")))
        else:
            break
    return entries, p


class TestReferenceUSBLayout:
    """Verify the reference USB image has the expected structure."""

    @pytest.fixture(autouse=True)
    def _require_ref(self):
        if not REF_USB.exists():
            pytest.skip("Reference USB image not available")

    def test_device_nng_exists(self):
        assert (REF_USB / "NaviSync/license/device.nng").exists()

    def test_brand_txt_exists(self):
        assert (REF_USB / "NaviSync/content/brand.txt").exists()

    def test_device_checksum_exists(self):
        assert (REF_USB / "NaviSync/device_checksum.md5").exists()

    def test_license_files(self):
        lyc_files = list((REF_USB / "NaviSync/license").glob("*.lyc"))
        assert len(lyc_files) >= 3

    def test_stm_files(self):
        stm_files = list((REF_USB / "NaviSync/content").rglob("*.stm"))
        assert len(stm_files) > 100


class TestBodyStructure:
    """Verify build_live_senddevicestatus produces correct structure."""

    def test_body_header(self, usb_copy):
        from medianav_toolbox.device_status import build_live_senddevicestatus

        body = build_live_senddevicestatus(usb_copy, variant=0x02)
        assert body[0] == 0xD8
        assert body[1] == 0x02
        assert body[2:4] == b"\x1f\x40"

    def test_body_variant_03(self, usb_copy):
        from medianav_toolbox.device_status import build_live_senddevicestatus

        body = build_live_senddevicestatus(usb_copy, variant=0x03)
        assert body[1] == 0x03
        assert body[2:4] == b"\x1e\x40"

    def test_body_contains_brand(self, usb_copy):
        from medianav_toolbox.device_status import build_live_senddevicestatus

        body = build_live_senddevicestatus(usb_copy, variant=0x02)
        assert b"DaciaAutomotive" in body

    def test_body_contains_serial(self, usb_copy):
        from medianav_toolbox.device_status import build_live_senddevicestatus

        body = build_live_senddevicestatus(usb_copy, variant=0x02)
        assert b"UU1DJF00869579646" in body

    def test_body_drive_path_default(self, usb_copy):
        from medianav_toolbox.device_status import build_live_senddevicestatus

        body = build_live_senddevicestatus(usb_copy, variant=0x02)
        assert b"E:\\" in body

    def test_e0_sub_marker_is_0x08(self, usb_copy):
        """The E0 sub-marker must be 0x08, not 0x0A (the bug that caused 409)."""
        from medianav_toolbox.device_status import build_live_senddevicestatus

        body = build_live_senddevicestatus(usb_copy, variant=0x02)
        e0_idx = body.index(b"\xe0")
        # After E0 marker + content_md5 string (1+32+1=34 bytes), the sub-marker
        l = body[e0_idx + 1]  # md5 string length
        sub_offset = e0_idx + 1 + 1 + l  # marker + len + md5
        assert body[sub_offset] == 0x08, f"E0 sub-marker is 0x{body[sub_offset]:02X}, expected 0x08"
        assert body[sub_offset + 1] == 0xA0

    def test_file_ordering_device_nng_before_lyc(self, usb_copy):
        """device.nng must appear before .lyc files in the entry list."""
        from medianav_toolbox.device_status import build_live_senddevicestatus

        body = build_live_senddevicestatus(usb_copy, variant=0x02)
        entries, _ = parse_entries(body, 202)
        filenames = [name for _, name in entries]
        dn_idx = filenames.index("device.nng")
        lyc_indices = [i for i, n in enumerate(filenames) if n.endswith(".lyc")]
        assert lyc_indices, "No .lyc files found"
        assert dn_idx < min(
            lyc_indices
        ), f"device.nng at {dn_idx}, first .lyc at {min(lyc_indices)}"


class TestBodyMatchesReference:
    """Compare our body structure against the run34 reference."""

    def test_same_entry_count(self, usb_copy, ref_body):
        from medianav_toolbox.device_status import build_live_senddevicestatus

        our = build_live_senddevicestatus(usb_copy, variant=0x02)
        our_entries, _ = parse_entries(our, 202)
        ref_entries, _ = parse_entries(ref_body, 202)
        assert len(our_entries) == len(ref_entries)

    def test_same_entry_types(self, usb_copy, ref_body):
        from medianav_toolbox.device_status import build_live_senddevicestatus

        our = build_live_senddevicestatus(usb_copy, variant=0x02)
        our_entries, _ = parse_entries(our, 202)
        ref_entries, _ = parse_entries(ref_body, 202)
        our_types = [(t, n) for t, n in our_entries]
        ref_types = [(t, n) for t, n in ref_entries]
        assert our_types == ref_types

    def test_same_file_md5s(self, usb_copy, ref_body):
        """File MD5 hashes should match (same files on both)."""
        from medianav_toolbox.device_status import build_live_senddevicestatus

        our = build_live_senddevicestatus(usb_copy, variant=0x02)
        # The file MD5s are the same because the file contents are identical
        # (we copied from the same base image)
        # Check that brand.txt MD5 matches
        ref_brand_md5 = ref_body[237:269]  # file MD5 in E0 entry
        our_brand_md5 = our[237:269]
        assert our_brand_md5 == ref_brand_md5

    def test_same_body_size(self, usb_copy, ref_body):
        from medianav_toolbox.device_status import build_live_senddevicestatus

        our = build_live_senddevicestatus(usb_copy, variant=0x02)
        assert len(our) == len(ref_body)


class TestLicenseInstall:
    """Test that license installation creates the correct layout."""

    def test_install_creates_lyc_and_md5(self, usb_copy):
        from medianav_toolbox.installer import install_license

        install_license(usb_copy, "TestLicense.lyc", b"\x00" * 100)

        lyc_path = usb_copy / "NaviSync/license/TestLicense.lyc"
        md5_path = usb_copy / "NaviSync/license/TestLicense.lyc.md5"
        assert lyc_path.exists()
        assert md5_path.exists()
        assert lyc_path.read_bytes() == b"\x00" * 100
        expected_md5 = hashlib.md5(b"\x00" * 100).hexdigest().upper()
        assert md5_path.read_text().strip() == expected_md5

    def test_installed_license_appears_in_body(self, usb_copy):
        """After installing a license, it should appear in the senddevicestatus body."""
        from medianav_toolbox.device_status import build_live_senddevicestatus
        from medianav_toolbox.installer import install_license

        install_license(usb_copy, "NewContent.lyc", b"\xde\xad" * 50)

        body = build_live_senddevicestatus(usb_copy, variant=0x02)
        assert b"NewContent.lyc" in body
        assert b"NewContent.lyc.md5" in body
