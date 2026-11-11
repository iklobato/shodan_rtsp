"""A malformed brands.yaml fails at load, naming the line it broke on (T039).

A signature file is edited by hand, so the error has to point at the entry that
is wrong. Failing later, at the first camera, would leave the operator with a
run that names nothing and no clue which line to fix.
"""

from pathlib import Path

import pytest

from scanners.brand_probe import BrandBook, BrandsFileError

_NO_BRANDS_KEY = """
signatures:
  hikvision:
    match: ["Hikvision"]
    vendor: hikvision
    product: ip_camera
"""
_NO_VENDOR = """
brands:
  hikvision:
    match: ["Hikvision"]
    product: ip_camera
  dahua:
    match: ["Dahua"]
    vendor: dahua
    product: ip_camera
"""
_NO_PATTERNS = """
brands:
  hikvision:
    vendor: hikvision
    product: ip_camera
"""
_EMPTY_PATTERNS = """
brands:
  hikvision:
    match: []
    vendor: hikvision
    product: ip_camera
"""
_BROKEN_REGEX = """
brands:
  hikvision:
    match: ["Hikvision("]
    vendor: hikvision
    product: ip_camera
"""
_NOT_A_MAPPING = """
brands:
  hikvision: hikvision
"""


class TestMalformedFile:
    """One reason to fail per case, and the message has to name where."""

    @pytest.fixture
    def write(self, tmp_path: Path) -> Path:
        """The path the tests below fill with the case they exercise."""
        return tmp_path / "brands.yaml"

    def test_a_file_without_the_brands_key_is_refused(self, write: Path) -> None:
        write.write_text(_NO_BRANDS_KEY)

        with pytest.raises(BrandsFileError, match="brands") as refused:
            BrandBook.load(str(write))

        assert "brands.yaml" in str(refused.value), (
            f"the error must name the file, got {refused.value}"
        )

    def test_a_brand_without_a_vendor_names_its_line(self, write: Path) -> None:
        write.write_text(_NO_VENDOR)

        with pytest.raises(BrandsFileError) as refused:
            BrandBook.load(str(write))

        assert "brands.yaml:3" in str(refused.value), (
            f"the hikvision entry starts at line 3, got {refused.value}"
        )
        assert "hikvision" in str(refused.value), (
            f"the error must name the entry, got {refused.value}"
        )

    def test_a_brand_without_patterns_is_refused(self, write: Path) -> None:
        write.write_text(_NO_PATTERNS)

        with pytest.raises(BrandsFileError, match="match"):
            BrandBook.load(str(write))

    def test_an_empty_pattern_list_is_refused(self, write: Path) -> None:
        """A signature with nothing to match on can never fire."""
        write.write_text(_EMPTY_PATTERNS)

        with pytest.raises(BrandsFileError, match="match"):
            BrandBook.load(str(write))

    def test_an_uncompilable_pattern_names_its_line(self, write: Path) -> None:
        write.write_text(_BROKEN_REGEX)

        with pytest.raises(BrandsFileError) as refused:
            BrandBook.load(str(write))

        assert "brands.yaml:3" in str(refused.value), (
            f"the hikvision entry starts at line 3, got {refused.value}"
        )

    def test_a_brand_that_is_not_a_mapping_is_refused(self, write: Path) -> None:
        write.write_text(_NOT_A_MAPPING)

        with pytest.raises(BrandsFileError, match="hikvision"):
            BrandBook.load(str(write))

    def test_a_missing_file_is_refused(self, tmp_path: Path) -> None:
        missing = tmp_path / "absent.yaml"

        with pytest.raises(BrandsFileError, match="absent.yaml"):
            BrandBook.load(str(missing))
