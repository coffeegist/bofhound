"""Tests for OutflankC2 parser."""
from bofhound.parsers import OutflankC2JsonParser
from tests.test_data import outflankc2_standard_file


def test_parse_file_outflankc2_standard_file(outflankc2_standard_file):
    """Test parsing of the OutflankC2 standard file."""
    parser = OutflankC2JsonParser()
    with open(outflankc2_standard_file, 'r', encoding='utf-8') as f:
        for line in f:
            parser.process_line(line)
    parsed_objects = parser.get_results()
    assert len(parsed_objects) == 2052
