"""Test Data Sources for parsers"""

import json
from unittest.mock import patch
from pathlib import Path
import pytest
from bofhound.parsers.data_sources import MythicDataSource, FileDataSource
from bofhound.parsers import ParsingPipeline, LdapSearchBofParser
from tests.mocks.mock_mythic_api import MockMythicAPI

def test_file_glob_data_source(tmp_path):
    """Test FileDataSource with local files."""
    # Create test files
    file1 = tmp_path / "test1.log"
    file1.write_text("line1\nline2\nline3\n")

    file2 = tmp_path / "test2.log"
    file2.write_text("entryA\nentryB\n")

    # Initialize FileDataSource
    data_source = FileDataSource(str(tmp_path), filename_pattern="*.log")

    data_streams = list(data_source.get_data_streams())

    # Verify two data streams
    assert len(data_streams) == 2

    file_lines = []
    for stream in data_streams:
        assert stream.identifier in {str(file1), str(file2)}
        file_lines.extend(list(stream.lines()))

    assert sorted(file_lines) == sorted(["line1", "line2", "line3", "entryA", "entryB"])

def test_single_file_data_source(tmp_path):
    """Test FileDataSource with a single file."""
    # Create test file
    file1 = tmp_path / "single.log"
    file1.write_text("onlyline1\nonlyline2\n")

    # Initialize FileDataSource with single file
    data_source = FileDataSource(str(file1))

    data_streams = list(data_source.get_data_streams())

    # Verify one data stream
    assert len(data_streams) == 1

    # Verify contents of the file
    lines = list(data_streams[0].lines())
    assert lines == ["onlyline1", "onlyline2"]


@pytest.fixture
def mock_mythic_api():
    """Create mock mythic API with test data."""
    test_data_path = "tests/test_data/mythic_logs/test_mythic_data.json"
    return MockMythicAPI(test_data_path)

@pytest.fixture
def mock_mythic_module(mock_mythic_api):
    """Patch the mythic module with mock implementation."""
    with patch('bofhound.parsers.data_sources.mythic') as mock_mythic:
        # Wire up the mock methods from your MockMythicAPI
        mock_mythic.login = mock_mythic_api.login
        mock_mythic.get_all_callbacks = mock_mythic_api.get_all_callbacks
        mock_mythic.get_all_tasks = mock_mythic_api.get_all_tasks
        mock_mythic.get_all_task_output_by_id = mock_mythic_api.get_all_task_output_by_id
        mock_mythic.get_all_task_output = mock_mythic_api.get_all_task_output
        yield mock_mythic

@pytest.fixture
def test_mythic_data():
    """Load test data for assertions."""
    test_data_path = Path("tests/test_data/mythic_logs/test_mythic_data.json")
    with open(test_data_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def test_mythic_data_source(mock_mythic_module, test_mythic_data):
    """Test MythicDataSource connection and callback retrieval."""

    # Test connection
    data_source = MythicDataSource("fake-server", "fake-token")

    data_streams = list(data_source.get_data_streams())

    # Verify callbacks were loaded
    assert len(data_streams) == len(test_mythic_data["outputs"])

    # Verify callback data
    first_stream = data_streams[0]
    expected_output = test_mythic_data["outputs"][0]
    assert first_stream.identifier == f"mythic_output_{expected_output['id']}"


def test_mythic_data_stream_lines(mock_mythic_module, test_mythic_data):
    """Test getting lines from MythicDataStream."""

    # Setup data source
    data_source = MythicDataSource("fake-server", "fake-token")

    # Get first stream
    streams = list(data_source.get_data_streams())
    first_stream = streams[0]

    # Get lines from the stream
    lines = list(first_stream.lines())

    # Should have some lines (depends on your test data)
    assert len(lines) > 0

    # Lines should be strings
    for line in lines:
        assert isinstance(line, str)
        assert len(line.strip()) > 0  # Non-empty lines

def test_mythic_integration_full_pipeline(mock_mythic_module):
    """Test full integration: connection -> streams -> lines."""

    # Full pipeline test
    data_source = MythicDataSource("fake-server", "fake-token")

    total_lines = 0
    stream_count = 0

    for stream in data_source.get_data_streams():
        stream_count += 1
        lines = list(stream.lines())
        total_lines += len(lines)

        print(f"Stream {stream.identifier}: {len(lines)} lines")

    print(f"Total: {stream_count} streams, {total_lines} lines")

    pipeline = ParsingPipeline()
    pipeline.register_parser(LdapSearchBofParser())
    result = pipeline.process_data_source(data_source)

    # Should have processed some data
    assert len(result.get_ldap_objects()) == 237
    assert stream_count == 16
    assert total_lines == 4587


def test_mock_mythic_api_structure():
    """Test that mock API returns data in expected structure."""
    test_data_path = "tests/test_data/mythic_logs/test_mythic_data.json"
    mock_api = MockMythicAPI(test_data_path)

    # Test data loading
    assert "callbacks" in mock_api.test_data
    assert "tasks" in mock_api.test_data
    assert "outputs" in mock_api.test_data

    # Test data types
    assert isinstance(mock_api.test_data["callbacks"], list)
    assert isinstance(mock_api.test_data["tasks"], list)
    assert isinstance(mock_api.test_data["outputs"], list)
