"""Tests for LDAP Search BOF parser."""
import pytest
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


@pytest.mark.parametrize('workers', [1, 2])
def test_unreadable_file_aborts_instead_of_returning_partial_results(tmp_path, workers):
    (tmp_path / 'a.log').write_text('--------------------\nsamaccountname: example\nRetrieved 1 results\n')
    (tmp_path / 'bad.log').write_bytes(b'\xff\xfe\x80')
    pipeline = ParsingPipeline()
    pipeline.register_parser(LdapSearchBofParser())
    with pytest.raises((UnicodeDecodeError, RuntimeError)):
        pipeline.process_data_source(FileDataSource(str(tmp_path)), num_workers=workers)


@pytest.mark.parametrize('first_entry_point', ['file', 'source'])
@pytest.mark.parametrize('first_workers,second_workers', [(1, 2), (2, 1), (2, 2)])
def test_reused_pipeline_preserves_serial_accumulation(tmp_path, first_entry_point, first_workers, second_workers):
    import os
    for index, name in enumerate(['a', 'b', 'c']):
        path = tmp_path / f'{name}.log'
        path.write_text(f'--------------------\nsamaccountname: {name}\nRetrieved 1 results\n')
        os.utime(path, (index + 1, index + 1))

    def run(workers_a, workers_b):
        pipeline = ParsingPipeline()
        parser = LdapSearchBofParser()
        pipeline.register_parser(parser)
        if first_entry_point == 'file':
            first = pipeline.process_file(str(tmp_path / 'a.log'))
            second = pipeline.process_data_source(FileDataSource(str(tmp_path)), num_workers=workers_b)
        else:
            first = pipeline.process_data_source(FileDataSource(str(tmp_path)), num_workers=workers_a)
            second = pipeline.process_data_source(FileDataSource(str(tmp_path / 'a.log')), num_workers=workers_b)
        names = lambda result: [obj['samaccountname'] for obj in result.get_ldap_objects()]
        return names(first), names(second), [obj['samaccountname'] for obj in parser.get_results()]

    expected = run(1, 1)
    assert run(first_workers, second_workers) == expected
    assert expected[1] == (['a', 'a', 'b', 'c'] if first_entry_point == 'file' else ['a', 'b', 'c', 'a'])


def test_prepopulated_parser_is_not_copied_into_each_worker(tmp_path):
    parser = LdapSearchBofParser()
    for line in ['--------------------', 'samaccountname: prior', 'Retrieved 1 results']:
        parser.process_line(line)
    for name in ['a', 'b']:
        (tmp_path / f'{name}.log').write_text(f'--------------------\nsamaccountname: {name}\nRetrieved 1 results\n')
    pipeline = ParsingPipeline()
    pipeline.register_parser(parser)
    result = pipeline.process_data_source(FileDataSource(str(tmp_path)), num_workers=2)
    assert len(result.get_ldap_objects()) == 3
    assert sum(obj['samaccountname'] == 'prior' for obj in result.get_ldap_objects()) == 1


def test_custom_boundary_parser_keeps_its_cross_file_state(tmp_path):
    class CountingLdapParser(LdapSearchBofParser):
        def __init__(self):
            super().__init__()
            self.line_count = 0

        def process_line(self, line):
            self.line_count += 1
            super().process_line(line)

    for name in ['a', 'b']:
        (tmp_path / f'{name}.log').write_text(f'--------------------\nsamaccountname: {name}\nRetrieved 1 results\n')
    parser = CountingLdapParser()
    pipeline = ParsingPipeline()
    pipeline.register_parser(parser)
    result = pipeline.process_data_source(FileDataSource(str(tmp_path)), num_workers=2)
    assert len(result.get_ldap_objects()) == 2
    assert parser.line_count == 6


def test_brc4_split_record_matches_sequential_parsing(tmp_path):
    """Rotated log files must not turn one complete object into two fragments."""
    import os
    from bofhound.parsers import ParsingPipelineFactory, ParserType

    first = tmp_path / 'b-first.log'
    second = tmp_path / 'b-second.log'
    first.write_text(
        '[+] objectClass : top; person; organizationalPerson; user\n'
        '[+] distinguishedName : CN=Alice,CN=Users,DC=example,DC=test\n',
        encoding='utf-8',
    )
    second.write_text(
        '[+] objectSid : S-1-5-21-111-222-333-1001\n'
        '[+] sAMAccountName : Alice\n'
        '[+] sAMAccountType : 805306368\n'
        '+-------------------------------------------------------------------+\n',
        encoding='utf-8',
    )
    os.utime(first, (1, 1))
    os.utime(second, (2, 2))
    expected = [{
        'objectclass': 'top, person, organizationalPerson, user',
        'distinguishedname': 'CN=Alice,CN=Users,DC=example,DC=test',
        'objectsid': 'S-1-5-21-111-222-333-1001',
        'samaccountname': 'Alice',
        'samaccounttype': '805306368',
    }]

    for workers in (1, 2):
        pipeline = ParsingPipelineFactory.create_pipeline(ParserType.BRC4)
        objects = pipeline.process_data_source(
            FileDataSource(str(tmp_path), 'b-*.log'), num_workers=workers,
        ).get_ldap_objects()
        assert objects == expected, f'Incorrect BRC4 results with {workers} workers'


def test_brc4_date_order_survives_complete_file_boundaries(tmp_path):
    """Parallel workers must retain the date interpretation established earlier."""
    import os
    from bofhound.parsers import ParsingPipelineFactory, ParserType

    for index, (name, timestamp) in enumerate([
        ('Alice', '17/10/2026 19:32:50'),
        ('Bob', '04/05/2026 19:32:50'),
    ], start=1):
        path = tmp_path / f'b-{index}.log'
        path.write_text(
            '[+] objectClass : top; person; organizationalPerson; user\n'
            f'[+] sAMAccountName : {name}\n'
            f'[+] whenCreated : {timestamp}\n'
            '+-------------------------------------------------------------------+\n',
            encoding='utf-8',
        )
        os.utime(path, (index, index))

    expected = [
        ('Alice', '20261017193250.0Z'),
        ('Bob', '20260504193250.0Z'),
    ]
    for workers in (1, 2):
        pipeline = ParsingPipelineFactory.create_pipeline(ParserType.BRC4)
        objects = pipeline.process_data_source(
            FileDataSource(str(tmp_path), 'b-*.log'), num_workers=workers,
        ).get_ldap_objects()
        assert [(obj['samaccountname'], obj['whencreated']) for obj in objects] == expected
