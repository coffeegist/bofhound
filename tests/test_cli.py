"""CLI upload lifecycle regressions; network calls are mocked."""
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from bofhound import __main__ as cli

ARGS = ['--quiet', '--no-cache', '--bh-token-id', 'id', '--bh-token-key', 'key']


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


def _export_snapshot(folder):
    import json
    return {
        path.name.split('_')[0]: json.loads(path.read_text())
        for path in folder.glob('*.json')
    }


def test_repeated_cache_run_preserves_complete_export(tmp_path):
    from pathlib import Path
    sample = Path(__file__).parent / 'test_data/ldapsearchbof_logs/beacon_257-objects.log'
    cache_path = tmp_path / 'cache.db'
    snapshots = []
    for run, workers in [('first', '1'), ('second', '2'), ('uncached', '2')]:
        output = tmp_path / run
        result = CliRunner().invoke(cli.app, [
            '--quiet', '--workers', workers, '-i', str(sample), '-o', str(output),
            '--cache-file', str(cache_path),
        ] + (['--no-cache'] if run == 'uncached' else []))
        assert result.exit_code == 0, (result.output, result.exception)
        snapshots.append(_export_snapshot(output))
    assert snapshots[0] == snapshots[1] == snapshots[2]
    assert snapshots[1]['computers']['meta']['count'] == 4
    assert snapshots[1]['domains']['meta']['count'] == 1


def test_output_failure_keeps_previous_snapshot(tmp_path, monkeypatch):
    from bofhound.cache import ObjectCache
    from pathlib import Path
    cache_path = tmp_path / 'cache.db'
    prior = {'distinguishedname': 'CN=Prior,DC=example,DC=test', 'name': 'Prior'}
    with ObjectCache(str(cache_path)) as cache:
        cache.store_object(prior)
    monkeypatch.setattr(cli.BloodHoundWriter, 'write', Mock(side_effect=OSError('disk full')))
    sample = Path(__file__).parent / 'test_data/ldapsearchbof_logs/minimal-ou-gplink.log'
    result = CliRunner().invoke(cli.app, [
        '--quiet', '--workers', '1', '-i', str(sample), '-o', str(tmp_path / 'output'),
        '--cache-file', str(cache_path),
    ])
    assert result.exit_code != 0
    with ObjectCache(str(cache_path)) as cache:
        assert cache.get_all_cached_objects() == [cache._normalize_object(prior)]



def test_parallel_input_failure_writes_no_output_and_keeps_cache(tmp_path):
    from bofhound.cache import ObjectCache
    cache_path = tmp_path / 'cache.db'
    prior = {'distinguishedname': 'CN=Prior,DC=example,DC=test', 'name': 'Prior'}
    with ObjectCache(str(cache_path)) as cache:
        cache.store_object(prior)
    logs = tmp_path / 'logs'
    logs.mkdir()
    (logs / 'good.log').write_text('--------------------\nsamaccountname: example\nRetrieved 1 results\n')
    (logs / 'bad.log').write_bytes(b'\xff\xfe\x80')
    output = tmp_path / 'output'
    result = CliRunner().invoke(cli.app, [
        '--quiet', '--workers', '2', '-i', str(logs), '-o', str(output),
        '--cache-file', str(cache_path),
    ])
    assert result.exit_code != 0
    assert list(output.glob('*.json')) == []
    with ObjectCache(str(cache_path)) as cache:
        assert cache.get_all_cached_objects() == [prior]



def test_changed_cached_user_is_updated_in_export(tmp_path):
    sample = tmp_path / 'input.log'
    cache_path = tmp_path / 'cache.db'
    sid = 'S-1-5-21-111-222-333-5678'
    for description in ['old', 'new']:
        sample.write_text(
            '--------------------\nobjectclass: top, domain\n'
            'distinguishedname: DC=example,DC=test\nobjectsid: S-1-5-21-111-222-333\n'
            '--------------------\nsamaccounttype: 805306368\nsamaccountname: example\n'
            'distinguishedname: CN=Example,DC=example,DC=test\n'
            f'objectsid: {sid}\ndescription: {description}\nRetrieved 2 results\n'
        )
        output = tmp_path / description
        result = CliRunner().invoke(cli.app, [
            '--quiet', '--workers', '1', '-i', str(sample), '-o', str(output),
            '--cache-file', str(cache_path),
        ])
        assert result.exit_code == 0, (result.output, result.exception)
        users = _export_snapshot(output)['users']['data']
        user = next(user for user in users if user['ObjectIdentifier'] == sid)
        assert user['Properties']['description'] == description
