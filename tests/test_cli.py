"""CLI upload lifecycle regressions; network calls are mocked."""
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from bofhound import __main__ as cli

ARGS = ['--quiet', '--bh-token-id', 'id', '--bh-token-key', 'key']


@pytest.fixture
def uploader(monkeypatch):
    instance = Mock()
    instance.preflight.return_value = True
    instance.create_upload_job.return_value = True
    instance.upload_file.return_value = True
    instance.close_upload_job.return_value = True
    monkeypatch.setattr(cli, 'BloodHoundUploader', Mock(return_value=instance))
    return instance


@pytest.mark.parametrize('zip_files', [False, True])
def test_upload_only_skips_parsing_and_directories(tmp_path, monkeypatch, uploader, zip_files):
    suffix = '.zip' if zip_files else '.json'
    file = tmp_path / ('users' + suffix)
    file.write_bytes(b'{}')
    (tmp_path / ('directory' + suffix)).mkdir()
    (tmp_path / ('ignored.json' if zip_files else 'ignored.zip')).write_bytes(b'{}')
    source = Mock(side_effect=AssertionError('must not parse'))
    monkeypatch.setattr(cli, 'FileDataSource', source)
    result = CliRunner().invoke(cli.app, ARGS + ['--upload-only', '-o', str(tmp_path)] + (['--zip'] if zip_files else []))
    assert result.exit_code == 0, result.output
    uploader.upload_file.assert_called_once_with(file)
    uploader.close_upload_job.assert_called_once()
    source.assert_not_called()


@pytest.mark.parametrize('failure', ['create_upload_job', 'upload_file', 'close_upload_job'])
def test_upload_only_failure_exit(tmp_path, uploader, failure):
    (tmp_path / 'users.json').write_text('{}')
    getattr(uploader, failure).return_value = False
    result = CliRunner().invoke(cli.app, ARGS + ['--upload-only', '-o', str(tmp_path)])
    assert result.exit_code != 0
    if failure == 'create_upload_job':
        uploader.close_upload_job.assert_not_called()
    else:
        uploader.close_upload_job.assert_called_once()


@pytest.mark.parametrize('credentials', [[], ['--bh-token-id', 'id'], ['--bh-token-key', 'key']])
def test_upload_only_requires_credentials(tmp_path, uploader, credentials):
    (tmp_path / 'users.json').write_text('{}')
    result = CliRunner().invoke(cli.app, ['--quiet', '--upload-only', '-o', str(tmp_path)] + credentials)
    assert result.exit_code != 0
    uploader.create_upload_job.assert_not_called()


def test_directory_only_is_not_uploadable(tmp_path, uploader):
    (tmp_path / 'directory.json').mkdir()
    result = CliRunner().invoke(cli.app, ARGS + ['--upload-only', '-o', str(tmp_path)])
    assert result.exit_code != 0
    uploader.create_upload_job.assert_not_called()


@pytest.mark.parametrize('preflight_ok', [False, True])
def test_preflight_before_parsing_without_job(monkeypatch, uploader, preflight_ok):
    uploader.preflight.return_value = preflight_ok
    source = Mock(side_effect=RuntimeError('input failed'))
    monkeypatch.setattr(cli, 'FileDataSource', source)
    result = CliRunner().invoke(cli.app, ARGS)
    assert result.exit_code != 0
    assert source.called is preflight_ok
    uploader.preflight.assert_called_once()
    uploader.create_upload_job.assert_not_called()


def test_upload_exception_still_closes_job(uploader):
    uploader.upload_file.side_effect = RuntimeError('unexpected')
    with pytest.raises(RuntimeError):
        cli.upload_files('server', 'id', 'key', ['users.json'], uploader=uploader)
    uploader.close_upload_job.assert_called_once()


def test_normal_parse_writes_before_starting_upload(tmp_path, monkeypatch, uploader):
    from pathlib import Path
    output = tmp_path / 'users.json'
    writer = Mock(return_value=[output])
    monkeypatch.setattr(cli.BloodHoundWriter, 'write', writer)

    def start():
        writer.assert_called_once()
        return True

    uploader.create_upload_job.side_effect = start
    result = CliRunner().invoke(cli.app, ARGS + ['-i', str(Path(__file__).parent / 'test_data/ldapsearchbof_logs/minimal-ou-gplink.log'), '-o', str(tmp_path)])
    assert result.exit_code == 0, (result.output, result.exception)
    uploader.preflight.assert_called_once()
    uploader.create_upload_job.assert_called_once()
    uploader.upload_file.assert_called_once_with(output)
    uploader.close_upload_job.assert_called_once()
