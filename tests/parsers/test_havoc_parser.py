"""Tests for Havoc parser."""
from bofhound.parsers import LdapSearchBofParser
from tests.test_data import havoc_standard_file


def test_parse_file_havoc_standard_file(havoc_standard_file):
    """Test parsing of the Havoc standard file."""
    parser = LdapSearchBofParser()
    with open(havoc_standard_file, 'r', encoding='utf-8') as f:
        for line in f:
            parser.process_line(line)
    parsed_objects = parser.get_results()
    assert len(parsed_objects) == 239
