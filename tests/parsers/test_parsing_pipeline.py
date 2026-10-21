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


def test_parallel_outflank_streams_match_sequential(tmp_path):
    from pathlib import Path
    import shutil
    from bofhound.parsers import ParsingPipelineFactory, ParserType
    from bofhound.parsers.data_sources import OutflankDataStream
    sample = Path(__file__).parents[1] / 'test_data/outflankc2_logs/ldapsearchbof/beacon_2052.json'
    for name in ['a.json', 'b.json']:
        shutil.copyfile(sample, tmp_path / name)
    results = []
    for workers in [1, 2]:
        pipeline = ParsingPipelineFactory.create_pipeline(ParserType.OUTFLANKC2)
        results.append(pipeline.process_data_source(
            FileDataSource(str(tmp_path), '*.json', stream_type=OutflankDataStream),
            num_workers=workers).get_ldap_objects())
    assert len(results[0]) == 4104
    assert results[0] == results[1]


def test_parallel_split_record_preserves_cross_file_state(tmp_path):
    import os
    (tmp_path / 'a.log').write_text('--------------------\ndistinguishedname: CN=Example,DC=example,DC=test\n')
    (tmp_path / 'b.log').write_text('samaccountname: example\nRetrieved 1 results\n')
    os.utime(tmp_path / 'a.log', (1, 1))
    os.utime(tmp_path / 'b.log', (2, 2))
    outputs = []
    for workers in [1, 2]:
        pipeline = ParsingPipeline()
        pipeline.register_parser(LdapSearchBofParser())
        outputs.append(pipeline.process_data_source(FileDataSource(str(tmp_path)), num_workers=workers).get_ldap_objects())
    assert outputs[0] == outputs[1]
    assert outputs[0][0]['samaccountname'] == 'example'


def test_parallel_file_order_is_input_order(tmp_path):
    import os
    for index, name in enumerate(['first', 'second']):
        file = tmp_path / (name + '.log')
        file.write_text(f'--------------------\nsamaccountname: {name}\nRetrieved 1 results\n')
        os.utime(file, (index + 1, index + 1))
    pipeline = ParsingPipeline()
    pipeline.register_parser(LdapSearchBofParser())
    objects = pipeline.process_data_source(FileDataSource(str(tmp_path)), num_workers=2).get_ldap_objects()
    assert [obj['samaccountname'] for obj in objects] == ['first', 'second']


def test_parallel_workers_preserve_parser_configuration(tmp_path):
    for name in ['a.log', 'b.log']:
        (tmp_path / name).write_text('--------------------\nNOISE\nsamaccountname: example\nRetrieved 1 results\n')
    parser = LdapSearchBofParser()
    parser._skippable_patterns.append('^NOISE$')
    pipeline = ParsingPipeline()
    pipeline.register_parser(parser)
    result = pipeline.process_data_source(FileDataSource(str(tmp_path)), num_workers=2)
    assert len(result.get_ldap_objects()) == 2
    assert all(obj['samaccountname'] == 'example' for obj in result.get_ldap_objects())


def test_parallel_split_boundary_falls_back_without_losing_record(tmp_path):
    import os
    (tmp_path / 'a.log').write_text('----------\n')
    (tmp_path / 'b.log').write_text('----------\nsamaccountname: example\nRetrieved 1 results\n')
    os.utime(tmp_path / 'a.log', (1, 1))
    os.utime(tmp_path / 'b.log', (2, 2))
    pipeline = ParsingPipeline()
    pipeline.register_parser(LdapSearchBofParser())
    result = pipeline.process_data_source(FileDataSource(str(tmp_path)), num_workers=2)
    assert result.get_ldap_objects() == [{'samaccountname': 'example'}]


def test_custom_stateful_parser_uses_sequential_contract(tmp_path):
    from bofhound.parsers.types import ToolParser, ObjectType

    class CountingParser(ToolParser):
        tool_name = 'counter'
        produces_object_type = ObjectType.LDAP_OBJECT

        def __init__(self):
            self.count = 0

        def process_line(self, line):
            self.count += 1

        def get_results(self):
            return [{'lines': self.count}]

    for name in ['a.log', 'b.log']:
        (tmp_path / name).write_text('line\n')
    pipeline = ParsingPipeline()
    parser = CountingParser()
    pipeline.register_parser(parser)
    result = pipeline.process_data_source(FileDataSource(str(tmp_path)), num_workers=2)
    assert result.get_ldap_objects() == [{'lines': 2}]
    assert parser.count == 2
