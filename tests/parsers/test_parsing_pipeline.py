"""Tests for LDAP Search BOF parser."""
from bofhound.parsers import (
    ParsingPipeline, ParsingResult, BoundaryDetector, BoundaryResult,
    LdapSearchBofParser
)
from bofhound.parsers.data_sources import FileDataSource
from tests.test_data import (
    ldapsearchpy_standard_file_516
)

def test_parse_file_ldapsearchpy_normal_file(ldapsearchpy_standard_file_516):
    """Test parsing of a normal LDAP search file (pyldapsearch)."""
    pipeline = ParsingPipeline()
    pipeline.register_parser(LdapSearchBofParser())
    data_source = FileDataSource(ldapsearchpy_standard_file_516)
    parsed_objects: ParsingResult = pipeline.process_data_source(data_source)
    assert len(parsed_objects.get_ldap_objects()) == 451

def test_boundary_detection():
    """Test the BoundaryDetector with various scenarios."""
    detector = BoundaryDetector("-" * 20)

    # Test exact boundary
    assert detector.process_line("--------------------") == BoundaryResult.COMPLETE_BOUNDARY

    # Test split boundary
    assert detector.process_line("----------") == BoundaryResult.PARTIAL_BOUNDARY
    assert detector.process_line("----------") == BoundaryResult.COMPLETE_BOUNDARY

    # Test invalid sequences
    assert detector.process_line("----------") == BoundaryResult.PARTIAL_BOUNDARY
    assert detector.process_line("some text") == BoundaryResult.NOT_BOUNDARY

    # Test overshooting
    assert detector.process_line("---------------------") == BoundaryResult.NOT_BOUNDARY

    detector = BoundaryDetector("* Test Multi-char Boundary $$$")
    assert detector.process_line("* Test ") == BoundaryResult.PARTIAL_BOUNDARY
    assert detector.process_line("Multi-char ") == BoundaryResult.PARTIAL_BOUNDARY
    assert detector.process_line("Boundary $$$") == BoundaryResult.COMPLETE_BOUNDARY
    assert (detector.process_line("* Test Multi-char Boundary $$$ Extra")
            == BoundaryResult.NOT_BOUNDARY)
    assert detector.process_line("Random text") == BoundaryResult.NOT_BOUNDARY
    assert detector.process_line("") == BoundaryResult.NOT_BOUNDARY
    assert detector.process_line("   ") == BoundaryResult.NOT_BOUNDARY
    assert detector.process_line("* Test Multi-char Boundary") == BoundaryResult.PARTIAL_BOUNDARY
    assert detector.process_line(" $$$") == BoundaryResult.COMPLETE_BOUNDARY
    assert (detector.process_line("* Test Multi-char Boundary $$$")
            == BoundaryResult.COMPLETE_BOUNDARY)
    assert detector.process_line(" * Test Multi-char Boundary $$$") == BoundaryResult.NOT_BOUNDARY
