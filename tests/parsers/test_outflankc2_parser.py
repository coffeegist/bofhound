"""Tests for OutflankC2 parser."""
from bofhound.parsers import LdapSearchBofParser
from bofhound.parsers.data_sources import FileDataSource, OutflankDataStream
from tests.test_data import outflankc2_standard_file


def test_parse_file_outflankc2_standard_file(outflankc2_standard_file):
    """Test parsing of the OutflankC2 standard file."""
    parser = LdapSearchBofParser()
    data_source = FileDataSource(outflankc2_standard_file,
                                 stream_type=OutflankDataStream)
    for stream in data_source.get_data_streams():
        for line in stream.lines():
            parser.process_line(line)
    parsed_objects = parser.get_results()
    assert len(parsed_objects) == 2052
