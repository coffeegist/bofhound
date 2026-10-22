"""Release validation and recovery tests; all publishing services are mocked."""
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


spec = importlib.util.spec_from_file_location('release', Path(__file__).parents[1] / '.github/scripts/release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)
COMMIT = 'a' * 40


def uploaded(files):
    return {name: {'filename': name, 'digests': {'sha256': checksum},
                   'url': f'https://test-files.pythonhosted.org/{name}'}
            for name, checksum in files.items()}


@pytest.fixture(autouse=True)
def retry_delays(monkeypatch):
    """Exercise retries without sleeping, using a small test retry budget."""
    delays = []
    monkeypatch.setattr(release, 'VISIBILITY_ATTEMPTS', 3)
    monkeypatch.setattr(release.time, 'sleep', delays.append)
    return delays


@pytest.fixture
def bundle(tmp_path, monkeypatch):
    monkeypatch.setenv('GITHUB_RUN_ID', '123')
    monkeypatch.setenv('GITHUB_REPOSITORY', 'coffeegist/bofhound')
    args = SimpleNamespace(version='0.5.0', commit=COMMIT, bundle=str(tmp_path), complete=False, index='pypi')
    (tmp_path / 'dist').mkdir()
    (tmp_path / 'dist/bofhound-0.5.0-py3-none-any.whl').write_bytes(b'wheel')
    (tmp_path / 'dist/bofhound-0.5.0.tar.gz').write_bytes(b'source')
    release.manifest(args)
    return args


@pytest.mark.parametrize('version,commit', [
    ('v0.5.0', COMMIT), ('0.5.0rc1', COMMIT), ('01.5.0', COMMIT),
    ('0.5.0\nmalicious', COMMIT), ('0.5.0', 'main'), ('0.5.0', 'A' * 40),
    ('0.5.0', COMMIT + '; echo injected'),
])
def test_reject_ambiguous_release_inputs(version, commit):
    with pytest.raises(ValueError):
        release.identity(version, commit)


def test_changelog_validation_requires_the_selected_version():
    changelog = '# Changes\n## [Unreleased]\nLater\n## [0.5.0] - 2026-10-21\n### Added\nThis release\n## [0.4.25]\nOld\n'
    assert release.changelog_section(changelog, '0.5.0') == '### Added\nThis release\n'
    with pytest.raises(ValueError, match='nonempty'):
        release.changelog_section(changelog, '0.6.0')


@pytest.mark.parametrize('target', ['dist/bofhound-0.5.0.tar.gz', 'dist/bofhound-0.5.0-py3-none-any.whl'])
def test_refuse_modified_saved_artifacts(bundle, target):
    (Path(bundle.bundle) / target).write_bytes(b'tampered')
    with pytest.raises(ValueError, match='checksum mismatch'):
        release.verify(bundle)


def test_refuse_unexpected_distribution(bundle):
    (Path(bundle.bundle) / 'dist/unexpected.whl').write_bytes(b'extra')
    with pytest.raises(ValueError, match='unexpected'):
        release.verify(bundle)


@pytest.mark.parametrize('field,value', [('version', '0.5.1'), ('commit', 'b' * 40), ('run_id', '456')])
def test_refuse_artifacts_from_different_release_or_run(bundle, field, value):
    path = Path(bundle.bundle) / 'release-manifest.json'
    data = json.loads(path.read_text())
    data[field] = value
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match='identity'):
        release.verify(bundle)


def test_partial_pypi_upload_retries_only_identical_missing_files(bundle, monkeypatch):
    files = release.verify(bundle)['files']
    wheel = 'bofhound-0.5.0-py3-none-any.whl'
    monkeypatch.setattr(release, 'pypi_files', lambda version, index='pypi': uploaded({wheel: files[wheel]}))
    release.check_pypi(bundle)
    assert [p.name for p in (Path(bundle.bundle) / 'pending-pypi').iterdir()] == ['bofhound-0.5.0.tar.gz']
    bundle.complete = True
    with pytest.raises(RuntimeError, match='incomplete'):
        release.check_pypi(bundle)


@pytest.mark.parametrize('remote', [
    {'bofhound-0.5.0.tar.gz': 'different'}, {'unexpected.whl': 'anything'},
])
def test_pypi_conflict_never_overwrites_or_skips_different_bytes(bundle, monkeypatch, remote):
    monkeypatch.setattr(release, 'pypi_files', lambda version, index='pypi': uploaded(remote))
    with pytest.raises(ValueError):
        release.check_pypi(bundle)
    assert not (Path(bundle.bundle) / 'pending-pypi').exists()


def test_completed_pypi_upload_is_safe_to_retry(bundle, monkeypatch, capsys):
    monkeypatch.setattr(release, 'pypi_files', lambda version, index='pypi': uploaded(release.verify(bundle)['files']))
    release.check_pypi(bundle)
    assert 'needed=false' in capsys.readouterr().out
    assert list((Path(bundle.bundle) / 'pending-pypi').iterdir()) == []


def test_pypi_network_error_is_not_treated_as_available_version(monkeypatch):
    from urllib.error import HTTPError
    def unavailable(*args, **kwargs):
        raise HTTPError('https://pypi.org', 503, 'Unavailable', {}, None)
    monkeypatch.setattr(release.urllib.request, 'urlopen', unavailable)
    with pytest.raises(HTTPError):
        release.pypi_files('0.5.0')


@pytest.fixture
def planned(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('GITHUB_REF', 'refs/heads/main')
    monkeypatch.setenv('GITHUB_REPOSITORY', 'coffeegist/bofhound')
    monkeypatch.setenv('GITHUB_RUN_ID', '123')
    monkeypatch.setattr(release.subprocess, 'run', lambda *args, **kwargs: None)
    def git(*args):
        return '[tool.poetry]\nversion = "0.5.0"' if args[-1].endswith('pyproject.toml') else '## [0.5.0]\nNotes\n'
    monkeypatch.setattr(release, 'run', git)
    monkeypatch.setattr(release, 'pypi_files', lambda version, index='pypi': {})
    return SimpleNamespace(version='0.5.0', commit=COMMIT)


def test_plan_rejects_branch_other_than_main(planned, monkeypatch):
    monkeypatch.setenv('GITHUB_REF', 'refs/heads/other')
    with pytest.raises(ValueError, match='from main'):
        release.plan(planned)


def test_plan_refuses_rebuild_of_existing_tag(planned, monkeypatch):
    def github(path, **kwargs):
        if path.endswith('/artifacts'):
            return {'artifacts': []}
        if '/commits/' in path:
            return {'sha': COMMIT}
        return {'object': {'sha': COMMIT}}
    monkeypatch.setattr(release, 'github', github)
    with pytest.raises(ValueError, match='Re-run failed jobs'):
        release.plan(planned)


def test_plan_reuses_current_runs_saved_build(planned, monkeypatch, capsys):
    def github(path, **kwargs):
        if path.endswith('/artifacts'):
            return {'artifacts': [{'name': release.ARTIFACT, 'expired': False}]}
        return None
    monkeypatch.setattr(release, 'github', github)
    release.plan(planned)
    assert 'reuse=true' in capsys.readouterr().out


def test_tag_collision_prevents_any_release_mutation(bundle, monkeypatch):
    calls = []
    def github(path, **kwargs):
        calls.append((path, kwargs))
        return {'sha': 'b' * 40}
    monkeypatch.setattr(release, 'github', github)
    with pytest.raises(ValueError, match='move an existing'):
        release.stage(bundle)
    assert all(not kwargs for _, kwargs in calls)


def test_draft_from_another_run_is_not_modified(bundle, monkeypatch):
    def github(path, **kwargs):
        if '/commits/' in path:
            return {'sha': COMMIT}
        if '/releases/' in path:
            return {'body': '<!-- bofhound-release-run: 999 -->', 'draft': True, 'assets': []}
        return {'object': {'sha': COMMIT}}
    monkeypatch.setattr(release, 'github', github)
    with pytest.raises(ValueError, match='another run'):
        release.stage(bundle)


def test_partial_draft_upload_only_adds_missing_assets(bundle, monkeypatch):
    manifest = Path(bundle.bundle) / 'release-manifest.json'
    commands = []
    def github(path, **kwargs):
        assert not path.endswith('/generate-notes'), 'Retry must preserve the existing draft notes'
        if '/commits/' in path:
            return {'sha': COMMIT}
        if '/releases/' in path:
            return {'body': '<!-- bofhound-release-run: 123 -->', 'draft': True,
                    'assets': [{'name': manifest.name}]}
        return {'object': {'sha': COMMIT}}
    def run(*args):
        commands.append(args)
        if args[2] == 'download':
            Path(args[-1], manifest.name).write_bytes(manifest.read_bytes())
        return ''
    monkeypatch.setattr(release, 'github', github)
    monkeypatch.setattr(release, 'run', run)
    release.stage(bundle)
    uploads = [args for args in commands if args[2] == 'upload']
    assert len(uploads) == 2
    assert all('release-manifest.json' not in args[4] for args in uploads)
    assert all('--clobber' not in args for args in commands)


def test_new_draft_waits_for_visibility_without_creating_duplicates(bundle, monkeypatch, retry_delays):
    generated = (
        "## What's Changed\n"
        '* Fix ACL filtering by @contributor in https://github.com/coffeegist/bofhound/pull/66\n\n'
        '## New Contributors\n* @contributor made their first contribution\n\n'
        '**Full Changelog**: https://github.com/coffeegist/bofhound/compare/v0.4.25...v0.5.0\n'
    )
    draft = None
    hidden_reads = 0
    requests = []
    commands = []

    def github(path, **fields):
        nonlocal hidden_reads
        requests.append((path, fields))
        if path.endswith('/generate-notes'):
            return {'name': 'v0.5.0', 'body': generated}
        if '/commits/' in path:
            return {'sha': COMMIT}
        if '/releases/tags/' in path:
            return None  # GitHub's tag endpoint omits draft releases.
        if '/releases?' in path:
            if draft is not None:
                hidden_reads += 1
                if hidden_reads < 3:
                    return []
            return [draft] if draft is not None else []
        return {'object': {'sha': COMMIT}}

    def run(*args):
        nonlocal draft
        commands.append(args)
        if args[2] == 'create':
            body = Path(args[-1]).read_text()
            assert body == generated + '\n<!-- bofhound-release-run: 123 -->\n'
            assert '--draft' in args
            draft = {'tag_name': 'v0.5.0', 'body': body, 'draft': True, 'assets': []}
        return ''

    monkeypatch.setattr(release, 'github', github)
    monkeypatch.setattr(release, 'run', run)
    release.stage(bundle)

    assert ('repos/coffeegist/bofhound/releases/generate-notes',
            {'tag_name': 'v0.5.0', 'target_commitish': COMMIT}) in requests
    assert len([args for args in commands if args[2] == 'create']) == 1
    assert retry_delays == [10, 10]


def test_note_generation_failure_does_not_create_a_draft(bundle, monkeypatch):
    commands = []

    def github(path, **fields):
        if path.endswith('/generate-notes'):
            raise RuntimeError('GitHub unavailable')
        if '/commits/' in path:
            return {'sha': COMMIT}
        if '/releases/tags/' in path:
            return None
        if '/releases?' in path:
            return []
        return {'object': {'sha': COMMIT}}

    monkeypatch.setattr(release, 'github', github)
    monkeypatch.setattr(release, 'run', lambda *args: commands.append(args))
    with pytest.raises(RuntimeError, match='GitHub unavailable'):
        release.stage(bundle)
    assert commands == []


def test_draft_lookup_searches_past_first_page(monkeypatch):
    draft = {'tag_name': 'v0.5.0', 'draft': True, 'assets': []}
    requests = []

    def github(path, **kwargs):
        requests.append(path)
        if '/tags/' in path:
            return None
        if path.endswith('page=1'):
            return [{'tag_name': f'other-{i}'} for i in range(100)]
        return [draft]

    monkeypatch.setattr(release, 'github', github)
    assert release.find_release('coffeegist/bofhound', 'v0.5.0') == draft
    assert requests[-1].endswith('page=2')


def test_draft_lookup_does_not_treat_permission_failure_as_absence(monkeypatch):
    monkeypatch.setattr(release, 'github', lambda *args, **kwargs: None)
    with pytest.raises(RuntimeError, match='permissions'):
        release.find_release('coffeegist/bofhound', 'v0.5.0')


def test_github_release_is_not_published_before_pypi_is_complete(bundle, monkeypatch):
    commands = []
    monkeypatch.setattr(release, 'stage', lambda args, **kwargs: None)
    monkeypatch.setattr(release, 'pypi_files', lambda version, index='pypi': {})
    monkeypatch.setattr(release, 'run', lambda *args: commands.append(args))
    with pytest.raises(RuntimeError, match='incomplete'):
        release.finish(bundle)
    assert commands == []


@pytest.mark.parametrize('index,host', [('pypi', 'pypi.org'), ('testpypi', 'test.pypi.org')])
def test_package_metadata_uses_only_selected_index(monkeypatch, index, host):
    requests = []
    files = uploaded({'bofhound-0.5.0.tar.gz': 'checksum'})

    def open_url(url, **kwargs):
        requests.append(url)
        return io.BytesIO(json.dumps({'urls': list(files.values())}).encode())

    monkeypatch.setattr(release.urllib.request, 'urlopen', open_url)
    assert release.pypi_files('0.5.0', index) == files
    assert requests == [f'https://{host}/pypi/bofhound/0.5.0/json']


def test_plan_refuses_new_build_for_version_already_on_testpypi(planned, monkeypatch):
    def github(path, **kwargs):
        return {'artifacts': []} if path.endswith('/artifacts') else None

    monkeypatch.setattr(release, 'github', github)
    monkeypatch.setattr(release, 'pypi_files', lambda version, index='pypi':
                        uploaded({'bofhound-0.5.0.tar.gz': 'existing'}) if index == 'testpypi' else {})
    with pytest.raises(ValueError, match='Re-run failed jobs'):
        release.plan(planned)


def test_partial_testpypi_upload_only_prepares_missing_files(bundle, monkeypatch):
    bundle.index = 'testpypi'
    files = release.verify(bundle)['files']
    wheel = 'bofhound-0.5.0-py3-none-any.whl'
    requested = []

    def remote(version, index='pypi'):
        requested.append(index)
        return uploaded({wheel: files[wheel]})

    monkeypatch.setattr(release, 'pypi_files', remote)
    release.check_pypi(bundle)
    assert requested == ['testpypi']
    assert [p.name for p in (Path(bundle.bundle) / 'pending-testpypi').iterdir()] == ['bofhound-0.5.0.tar.gz']
    assert not (Path(bundle.bundle) / 'pending-pypi').exists()


def test_testpypi_hash_conflict_blocks_upload_and_install(bundle, monkeypatch):
    bundle.index = 'testpypi'
    monkeypatch.setattr(release, 'pypi_files', lambda version, index='pypi':
                        uploaded({'bofhound-0.5.0.tar.gz': 'different'}))
    with pytest.raises(ValueError, match='TestPyPI file differs'):
        release.download(bundle)
    assert not (Path(bundle.bundle) / 'downloaded-testpypi').exists()


def test_download_retrieves_testpypi_bytes_instead_of_using_local_build(bundle, monkeypatch):
    bundle.index = 'testpypi'
    files = release.verify(bundle)['files']
    requests = []
    monkeypatch.setattr(release, 'pypi_files', lambda version, index='pypi': uploaded(files))

    def open_url(url, **kwargs):
        requests.append(url)
        return io.BytesIO(b'wheel' if url.endswith('.whl') else b'source')

    monkeypatch.setattr(release.urllib.request, 'urlopen', open_url)
    release.download(bundle)
    assert set(requests) == {f'https://test-files.pythonhosted.org/{name}' for name in files}
    for name, checksum in files.items():
        assert release.digest(Path(bundle.bundle) / 'downloaded-testpypi' / name) == checksum


def test_corrupted_download_blocks_rehearsal_even_when_index_hash_matches(bundle, monkeypatch):
    bundle.index = 'testpypi'
    monkeypatch.setattr(release, 'pypi_files', lambda version, index='pypi':
                        uploaded(release.verify(bundle)['files']))
    monkeypatch.setattr(release.urllib.request, 'urlopen', lambda *args, **kwargs: io.BytesIO(b'corrupted'))
    with pytest.raises(ValueError, match='Downloaded package checksum mismatch'):
        release.download(bundle)


def test_incomplete_rehearsal_upload_is_not_installed(bundle, monkeypatch):
    bundle.index = 'testpypi'
    monkeypatch.setattr(release, 'pypi_files', lambda version, index='pypi': {})
    with pytest.raises(RuntimeError, match='TestPyPI upload incomplete'):
        release.download(bundle)
    assert not (Path(bundle.bundle) / 'downloaded-testpypi').exists()


@pytest.mark.parametrize('index', ['testpypi', 'pypi'])
def test_uploaded_files_can_appear_in_stages_before_verification_passes(bundle, monkeypatch, retry_delays, index):
    bundle.index = index
    bundle.complete = True
    files = release.verify(bundle)['files']
    wheel = 'bofhound-0.5.0-py3-none-any.whl'
    snapshots = iter([{}, uploaded({wheel: files[wheel]}), uploaded(files)])
    requested = []

    def metadata(version, requested_index):
        requested.append(requested_index)
        return next(snapshots)

    monkeypatch.setattr(release, 'pypi_files', metadata)
    assert release.check_pypi(bundle) == uploaded(files)
    assert requested == [index, index, index]
    assert retry_delays == [10, 10]
    assert not (Path(bundle.bundle) / f'pending-{index}').exists()


def test_incomplete_upload_wait_is_bounded_and_preserves_original_run_recovery(bundle, monkeypatch, retry_delays):
    bundle.complete = True
    calls = []
    monkeypatch.setattr(release, 'pypi_files', lambda *args: calls.append(args) or {})
    with pytest.raises(RuntimeError, match='after 3 attempts.*Re-run failed jobs'):
        release.check_pypi(bundle)
    assert len(calls) == 3
    assert retry_delays == [10, 10]


def test_conflict_after_visibility_delay_still_fails_immediately(bundle, monkeypatch, retry_delays):
    bundle.complete = True
    snapshots = iter([{}, uploaded({'bofhound-0.5.0.tar.gz': 'different'})])
    monkeypatch.setattr(release, 'pypi_files', lambda *args: next(snapshots))
    with pytest.raises(ValueError, match='file differs'):
        release.check_pypi(bundle)
    assert retry_delays == [10]


@pytest.mark.parametrize('status', [401, 403])
@pytest.mark.parametrize('backend', ['registry', 'github'])
def test_permission_errors_are_never_retried(monkeypatch, retry_delays, status, backend):
    from urllib.error import HTTPError
    error = (HTTPError('https://pypi.org', status, 'Denied', {}, None)
             if backend == 'registry' else release.GitHubError(f'Denied (HTTP {status})'))
    calls = []

    def read():
        calls.append(1)
        raise error

    with pytest.raises(type(error)):
        release.wait_for_visibility('protected read', read)
    assert calls == [1]
    assert retry_delays == []


@pytest.mark.parametrize('backend', ['registry', 'github', 'timeout'])
def test_temporary_read_failure_retries_until_visible(retry_delays, backend):
    from urllib.error import HTTPError
    error = (HTTPError('https://pypi.org', 503, 'Unavailable', {}, None) if backend == 'registry'
             else release.GitHubError('Unavailable (HTTP 503)') if backend == 'github'
             else TimeoutError('read timed out'))
    calls = []

    def read():
        calls.append(1)
        if len(calls) == 1:
            raise error
        return 'visible'

    assert release.wait_for_visibility('uploaded record', read) == 'visible'
    assert calls == [1, 1]
    assert retry_delays == [10]


def test_finalization_waits_for_draft_assets_and_pypi_without_repeating_writes(bundle, monkeypatch, retry_delays):
    root = Path(bundle.bundle)
    expected = [root / 'release-manifest.json', *sorted((root / 'dist').iterdir())]
    assets = [{'name': path.name} for path in expected]
    record = {'tag_name': 'v0.5.0', 'body': '<!-- bofhound-release-run: 123 -->',
              'draft': True, 'assets': assets}
    snapshots = iter([None, dict(record, assets=assets[:1]), record])
    files = release.verify(bundle)['files']
    index_snapshots = iter([{}, uploaded({next(iter(files)): next(iter(files.values()))}), uploaded(files)])
    commands = []

    def github(path, **fields):
        assert not fields, 'Finalization must not create a tag, notes, release, or upload assets'
        if '/git/ref/' in path or '/commits/' in path:
            return {'sha': COMMIT}
        raise AssertionError(path)

    def run(*args):
        commands.append(args)
        if args[2] == 'download':
            name = args[args.index('--pattern') + 1]
            path = root / 'release-manifest.json' if name == 'release-manifest.json' else root / 'dist' / name
            Path(args[-1], name).write_bytes(path.read_bytes())
        else:
            assert args[2] == 'edit'
        return ''

    monkeypatch.setattr(release, 'github', github)
    monkeypatch.setattr(release, 'find_release', lambda *args: next(snapshots))
    monkeypatch.setattr(release, 'pypi_files', lambda *args: next(index_snapshots))
    monkeypatch.setattr(release, 'run', run)
    release.finish(bundle)
    assert retry_delays == [10, 10, 10, 10]
    assert [args[2] for args in commands] == ['download', 'download', 'download', 'edit']


def test_finalization_never_uploads_missing_github_assets(bundle, monkeypatch, retry_delays):
    monkeypatch.setattr(release, 'github', lambda *args, **kwargs: {'sha': COMMIT})
    monkeypatch.setattr(release, 'find_release', lambda *args: {
        'body': '<!-- bofhound-release-run: 123 -->', 'draft': True, 'assets': []})
    commands = []
    monkeypatch.setattr(release, 'run', lambda *args: commands.append(args))
    with pytest.raises(RuntimeError, match='after 3 attempts'):
        release.finish(bundle)
    assert commands == []
    assert retry_delays == [10, 10]


@pytest.mark.parametrize('conflict', ['unexpected-asset', 'changed-bytes'])
def test_github_integrity_conflicts_block_publication_without_waiting(bundle, monkeypatch, retry_delays, conflict):
    root = Path(bundle.bundle)
    assets = [{'name': path.name} for path in [root / 'release-manifest.json', *(root / 'dist').iterdir()]]
    if conflict == 'unexpected-asset':
        assets.append({'name': 'unexpected.whl'})
    monkeypatch.setattr(release, 'github', lambda *args, **kwargs: {'sha': COMMIT})
    monkeypatch.setattr(release, 'find_release', lambda *args: {
        'body': '<!-- bofhound-release-run: 123 -->', 'draft': True, 'assets': assets})
    commands = []

    def read_asset(*args):
        commands.append(args)
        assert args[2] == 'download', 'No writes allowed after an integrity conflict'
        Path(args[-1], args[args.index('--pattern') + 1]).write_bytes(b'changed')
        return ''

    monkeypatch.setattr(release, 'run', read_asset)
    with pytest.raises(ValueError, match='unexpected assets|asset differs'):
        release.finish(bundle)
    assert retry_delays == []
