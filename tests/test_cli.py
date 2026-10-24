"""CLI upload lifecycle regressions; network calls are mocked."""
from importlib import metadata
from unittest.mock import Mock

from click import unstyle
import pytest
from typer.testing import CliRunner

from bofhound import __main__ as cli

ARGS = ['--quiet', '--no-cache', '--bh-token-id', 'id', '--bh-token-key', 'key']


@pytest.mark.parametrize('flag', ['--version', '-V'])
@pytest.mark.parametrize('flag_first', [False, True], ids=['last', 'first'])
def test_version_exits_before_validating_or_processing_input(tmp_path, monkeypatch, flag, flag_first):
    lookup = Mock(return_value='9.8.7')
    monkeypatch.setattr(metadata, 'version', lookup)
    blocked = Mock(side_effect=AssertionError('Version must exit before processing'))
    for name in ('ObjectCache', 'FileDataSource', 'BloodHoundUploader', 'banner'):
        monkeypatch.setattr(cli, name, blocked)
    output = tmp_path / 'must-not-be-created'
    args = [
        '--quiet', '--input', str(tmp_path / 'does-not-exist'),
        '--output', str(output), '--parser', 'invalid-parser',
        '--bh-token-id', 'id', '--bh-token-key', 'key',
    ]
    args = [flag, *args] if flag_first else [*args, flag]

    result = CliRunner().invoke(cli.app, args)

    assert result.exit_code == 0, (result.output, result.exception)
    assert result.output == 'v9.8.7\n'
    lookup.assert_called_once_with('bofhound')
    blocked.assert_not_called()
    assert not output.exists()


def test_version_without_installed_package_metadata(monkeypatch):
    monkeypatch.setattr(metadata, 'version', Mock(side_effect=metadata.PackageNotFoundError('bofhound')))

    result = CliRunner().invoke(cli.app, ['--version'])

    assert result.exit_code == 0, (result.output, result.exception)
    assert result.output == 'unknown\n'


@pytest.mark.parametrize('quiet', [False, True], ids=['banner', 'quiet'])
def test_banner_reports_installed_version_unless_quiet(tmp_path, monkeypatch, quiet):
    class StopAfterDispatch(Exception):
        pass

    lookup = Mock(return_value='9.8.7')
    monkeypatch.setattr(metadata, 'version', lookup)
    pipeline = Mock()
    pipeline.process_data_source.side_effect = StopAfterDispatch
    monkeypatch.setattr(cli.ParsingPipelineFactory, 'create_pipeline', Mock(return_value=pipeline))
    args = ['--no-cache', '--input', str(tmp_path), '--output', str(tmp_path)]
    if quiet:
        args.append('--quiet')

    result = CliRunner().invoke(cli.app, args)

    assert isinstance(result.exception, StopAfterDispatch)
    if quiet:
        assert 'bofhound v9.8.7' not in result.output
        assert '@coffeegist' not in result.output
        lookup.assert_not_called()
    else:
        assert 'bofhound v9.8.7' in result.output
        assert '<< @coffeegist | @Tw1sm >>' in result.output
        lookup.assert_called_once_with('bofhound')


def test_help_lists_version_option():
    result = CliRunner().invoke(cli.app, ['--help'])

    assert result.exit_code == 0, result.output
    output = unstyle(result.output)
    assert '--version' in output
    assert '-V' in output


def test_ldif_parser_uses_ldif_file_patterns(tmp_path, monkeypatch):
    class StopAfterDispatch(Exception):
        pass

    data_source = Mock()
    source_factory = Mock(return_value=data_source)
    pipeline = Mock()
    pipeline.process_data_source.side_effect = StopAfterDispatch
    pipeline_factory = Mock(return_value=pipeline)
    monkeypatch.setattr(cli, 'FileDataSource', source_factory)
    monkeypatch.setattr(cli.ParsingPipelineFactory, 'create_pipeline', pipeline_factory)

    result = CliRunner().invoke(cli.app, [
        '--quiet', '--no-cache', '--parser', 'ldif',
        '--input', str(tmp_path), '--output', str(tmp_path),
    ])

    assert isinstance(result.exception, StopAfterDispatch)
    source_factory.assert_called_once_with(str(tmp_path), cli.LDIF_PATTERNS)
    pipeline_factory.assert_called_once_with(parser_type=cli.ParserType.LDIF)
    pipeline.process_data_source.assert_called_once()


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



def test_cached_rename_replaces_old_dn_context(tmp_path):
    from bofhound.cache import ObjectCache
    sample = tmp_path / 'input.log'
    cache_path = tmp_path / 'cache.db'
    sid = 'S-1-5-21-111-222-333-5678'
    for name in ['Old', 'New']:
        sample.write_text(
            '--------------------\nsamaccounttype: 805306368\nsamaccountname: example\n'
            f'distinguishedname: CN={name},DC=example,DC=test\nobjectsid: {sid}\nRetrieved 1 results\n'
        )
        result = CliRunner().invoke(cli.app, [
            '--quiet', '--workers', '1', '-i', str(sample), '-o', str(tmp_path / name),
            '--cache-file', str(cache_path),
        ])
        assert result.exit_code == 0, (result.output, result.exception)
    with ObjectCache(str(cache_path)) as cache:
        mappings = cache.get_all_dn_mappings()
        assert 'CN=OLD,DC=EXAMPLE,DC=TEST' not in mappings
        assert mappings['CN=NEW,DC=EXAMPLE,DC=TEST']['sid'] == sid


@pytest.mark.parametrize('retired_first', [False, True])
def test_guid_rename_collision_exports_only_current_identity_across_runs(tmp_path, retired_first):
    from bofhound.cache import ObjectCache
    from tests.ad.test_inherited_acls import make_acl_entry
    current = {
        'objectsid': 'S-1-5-21-111-222-333-1001',
        'objectguid': '11111111-1111-1111-1111-111111111111',
        'distinguishedname': 'CN=Current,DC=example,DC=test',
        'samaccounttype': '805306368', 'samaccountname': 'current',
    }
    retired = {
        **current, 'objectsid': 'S-1-5-21-111-222-333-1002',
        'objectguid': '22222222-2222-2222-2222-222222222222',
        'distinguishedname': 'CN=Reused,DC=example,DC=test', 'samaccountname': 'retired',
        'ntsecuritydescriptor': make_acl_entry().RawAces,
    }
    partial = {'objectguid': current['objectguid'], 'distinguishedname': retired['distinguishedname']}
    records = [retired, current] if retired_first else [current, retired]
    source = tmp_path / 'input.log'
    cache_path = tmp_path / 'cache.db'
    snapshots = []
    for name, incoming in [('initial', records), ('rename', [partial]), ('repeat', [])]:
        text = ''.join('--------------------\n' + ''.join(f'{key}: {value}\n' for key, value in raw.items())
                       for raw in incoming)
        source.write_text(text + f'Retrieved {len(incoming)} results\n')
        output = tmp_path / name
        result = CliRunner().invoke(cli.app, [
            '--quiet', '--workers', '1', '-i', str(source), '-o', str(output),
            '--cache-file', str(cache_path),
        ])
        assert result.exit_code == 0, (result.output, result.exception)
        if name != 'initial':
            snapshot = _export_snapshot(output)
            users = {user['ObjectIdentifier']: user for user in snapshot['users']['data']}
            assert retired['objectsid'] not in users
            assert users[current['objectsid']]['Aces'] == []
            assert users[current['objectsid']]['Properties']['distinguishedname'] == partial['distinguishedname'].upper()
            snapshots.append(snapshot)
    assert snapshots[0] == snapshots[1]
    with ObjectCache(str(cache_path)) as cache:
        assert cache.get_all_cached_objects() == [{**current, **partial}]
