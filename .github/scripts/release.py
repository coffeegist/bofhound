"""Validation and retry-safe publication helpers for the manual release workflow."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

try:
    import tomllib
except ModuleNotFoundError:  # Project regression tests also run on Python 3.10.
    import tomli as tomllib


ARTIFACT = 'bofhound-release'
VISIBILITY_ATTEMPTS = 13
VISIBILITY_DELAY = 10


class NotVisibleYet(RuntimeError):
    """A successful write has not propagated to a read endpoint yet."""


class GitHubError(RuntimeError):
    def __init__(self, message):
        super().__init__(message)
        match = re.search(r'HTTP (\d{3})', message)
        self.status = int(match[1]) if match else None


def wait_for_visibility(description, read):
    """Retry reads only; integrity and permission errors must not be retried."""
    for attempt in range(1, VISIBILITY_ATTEMPTS + 1):
        try:
            return read()
        except (NotVisibleYet, urllib.error.URLError, TimeoutError, GitHubError) as error:
            if isinstance(error, urllib.error.HTTPError) and error.code not in (429, 500, 502, 503, 504):
                raise
            if isinstance(error, GitHubError) and error.status not in (429, 500, 502, 503, 504):
                raise
            if attempt == VISIBILITY_ATTEMPTS:
                raise RuntimeError(
                    f'{description} could not be verified after {attempt} attempts: {error}. '
                    'Re-run failed jobs in this original run; do not rebuild the version.'
                ) from error
            print(f'{description}: {error}; retry {attempt}/{VISIBILITY_ATTEMPTS - 1} '
                  f'in {VISIBILITY_DELAY}s', flush=True)
            time.sleep(VISIBILITY_DELAY)


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def github(path, **fields):
    command = ['gh', 'api', path]
    if fields:
        command += ['--method', 'POST']
        for key, value in fields.items():
            command += ['-f', f'{key}={value}']
    result = subprocess.run(command, text=True, capture_output=True)
    if result.returncode:
        if not fields and 'HTTP 404' in result.stderr:
            return None
        raise GitHubError(result.stderr)
    return json.loads(result.stdout)


def output(key, value):
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as handle:
            handle.write(f'{key}={value}\n')
    print(f'{key}={value}')


def identity(version, commit):
    if not re.fullmatch(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)', version):
        raise ValueError('Use a stable version such as 0.5.0, without the v prefix.')
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('Use the complete, lowercase 40-character commit SHA.')


def pypi_files(version, index='pypi'):
    host = {'pypi': 'pypi.org', 'testpypi': 'test.pypi.org'}[index]
    try:
        with urllib.request.urlopen(f'https://{host}/pypi/bofhound/{version}/json', timeout=10) as response:
            return {item['filename']: item for item in json.load(response)['urls']}
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return {}
        raise


def changelog_section(changelog, version):
    match = re.search(rf'^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## |\Z)', changelog, re.M | re.S)
    if not match or not match[1].strip():
        raise ValueError(f'Add a nonempty [{version}] section to CHANGELOG.md before releasing.')
    return match[1].strip() + '\n'


def plan(args):
    identity(args.version, args.commit)
    if os.environ['GITHUB_REF'] != 'refs/heads/main':
        raise ValueError('Run the release workflow from main.')
    subprocess.run(['git', 'merge-base', '--is-ancestor', args.commit, 'origin/main'], check=True)
    metadata = tomllib.loads(run('git', 'show', f'{args.commit}:pyproject.toml'))
    if metadata['tool']['poetry']['version'] != args.version:
        raise ValueError('Requested version does not match pyproject.toml at the selected commit.')
    repo = os.environ['GITHUB_REPOSITORY']
    run_id = os.environ['GITHUB_RUN_ID']
    artifacts = github(f'repos/{repo}/actions/runs/{run_id}/artifacts')['artifacts']
    reuse = any(item['name'] == ARTIFACT and not item['expired'] for item in artifacts)
    tag = github(f'repos/{repo}/git/ref/tags/v{args.version}')
    if tag:
        tagged = github(f'repos/{repo}/commits/v{args.version}')
        if tagged['sha'] != args.commit:
            raise ValueError('Release tag already points to a different commit.')
    if not reuse and (tag or pypi_files(args.version) or pypi_files(args.version, 'testpypi')):
        raise ValueError('Version already exists. Re-run failed jobs in the original release run; do not rebuild it.')
    changelog_section(run('git', 'show', f'{args.commit}:CHANGELOG.md'), args.version)
    output('reuse', str(reuse).lower())
    output('commit', args.commit)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest(args):
    identity(args.version, args.commit)
    bundle = Path(args.bundle)
    expected = {f'bofhound-{args.version}-py3-none-any.whl', f'bofhound-{args.version}.tar.gz'}
    files = {path.name: digest(path) for path in (bundle / 'dist').iterdir() if path.is_file()}
    if set(files) != expected:
        raise ValueError('Expected exactly one bofhound wheel and one source archive for this version.')
    document = {'version': args.version, 'commit': args.commit, 'run_id': os.environ['GITHUB_RUN_ID'],
                'files': files}
    (bundle / 'release-manifest.json').write_text(json.dumps(document, indent=2) + '\n')


def verify(args):
    identity(args.version, args.commit)
    bundle = Path(args.bundle)
    document = json.loads((bundle / 'release-manifest.json').read_text())
    expected = {f'bofhound-{args.version}-py3-none-any.whl', f'bofhound-{args.version}.tar.gz'}
    if (document['version'], document['commit'], str(document['run_id'])) != (
            args.version, args.commit, os.environ['GITHUB_RUN_ID']):
        raise ValueError('Artifact identity does not match this release run.')
    if set(document['files']) != expected or {p.name for p in (bundle / 'dist').iterdir()} != expected:
        raise ValueError('Artifact contains unexpected distribution files.')
    for name, checksum in document['files'].items():
        if digest(bundle / 'dist' / name) != checksum:
            raise ValueError(f'Artifact checksum mismatch: {name}')
    return document


def check_pypi(args):
    document = verify(args)
    index = args.index
    label = 'TestPyPI' if index == 'testpypi' else 'PyPI'

    def read():
        remote = pypi_files(args.version, index)
        if not remote.keys() <= document['files'].keys():
            raise ValueError(f'{label} has unexpected files for this version.')
        for name, item in remote.items():
            if item['digests']['sha256'] != document['files'][name]:
                raise ValueError(f'{label} file differs from the tested artifact: {name}')
        missing = document['files'].keys() - remote.keys()
        if args.complete and missing:
            raise NotVisibleYet(f'{label} upload incomplete: {sorted(missing)}')
        return remote

    remote = wait_for_visibility(f'{label} uploaded files', read) if args.complete else read()
    missing = document['files'].keys() - remote.keys()
    if not args.complete:
        pending = Path(args.bundle) / f'pending-{index}'
        pending.mkdir(exist_ok=True)
        if list(pending.iterdir()):
            raise ValueError('Pending upload directory must be empty.')
        for name in missing:
            shutil.copyfile(Path(args.bundle) / 'dist' / name, pending / name)
        output('needed', str(bool(missing)).lower())
    return remote


def download(args):
    """Retrieve the actual uploaded files, verifying bytes before installation."""
    args.complete = True
    remote = check_pypi(args)
    document = verify(args)
    destination = Path(args.bundle) / f'downloaded-{args.index}'
    destination.mkdir(exist_ok=False)
    for name, item in remote.items():
        with urllib.request.urlopen(item['url'], timeout=60) as response:
            target = destination / name
            with target.open('wb') as handle:
                shutil.copyfileobj(response, handle)
        if digest(target) != document['files'][name]:
            raise ValueError(f'Downloaded package checksum mismatch: {name}')


def find_release(repo, tag):
    """The tag endpoint finds published releases; list releases to find drafts."""
    published = github(f'repos/{repo}/releases/tags/{tag}')
    if published is not None:
        return published
    page = 1
    while True:
        releases = github(f'repos/{repo}/releases?per_page=100&page={page}')
        if releases is None:
            raise RuntimeError('Unable to list releases; check repository permissions.')
        for release in releases:
            if release['tag_name'] == tag:
                return release
        if len(releases) < 100:
            return None
        page += 1


def stage(args, *, complete=False):
    verify(args)
    repo = os.environ['GITHUB_REPOSITORY']
    tag = f'v{args.version}'
    run_id = os.environ['GITHUB_RUN_ID']
    marker = f'<!-- bofhound-release-run: {run_id} -->'
    existing_tag = github(f'repos/{repo}/git/ref/tags/{tag}')
    if existing_tag:
        if github(f'repos/{repo}/commits/{tag}')['sha'] != args.commit:
            raise ValueError('Refusing to move an existing release tag.')
    elif complete:
        raise NotVisibleYet('Release tag is not visible yet.')
    else:
        github(f'repos/{repo}/git/refs', ref=f'refs/tags/{tag}', sha=args.commit)

    def read_release():
        release = find_release(repo, tag)
        if release is None:
            raise NotVisibleYet('GitHub draft release is not visible yet.')
        return release

    release = read_release() if complete else find_release(repo, tag)
    if release is None:
        generated = github(f'repos/{repo}/releases/generate-notes',
                           tag_name=tag, target_commitish=args.commit)
        notes = Path(args.bundle) / 'github-notes.md'
        notes.write_text(generated['body'].rstrip() + '\n\n' + marker + '\n')
        run('gh', 'release', 'create', tag, '--repo', repo, '--draft', '--verify-tag',
            '--title', tag, '--notes-file', str(notes))
        release = wait_for_visibility('Created GitHub draft', read_release)
    if marker not in (release['body'] or ''):
        raise ValueError('Existing release belongs to another run; resume that original run.')
    expected = [Path(args.bundle) / 'release-manifest.json', *sorted((Path(args.bundle) / 'dist').iterdir())]
    assets = {asset['name']: asset for asset in release['assets']}
    if not assets.keys() <= {path.name for path in expected}:
        raise ValueError('Release contains unexpected assets.')
    missing = {path.name for path in expected} - assets.keys()
    if complete and missing:
        raise NotVisibleYet(f'GitHub release assets not visible yet: {sorted(missing)}')
    for path in expected:
        if path.name in assets:
            with tempfile.TemporaryDirectory() as directory:
                run('gh', 'release', 'download', tag, '--repo', repo, '--pattern', path.name, '--dir', directory)
                if digest(Path(directory) / path.name) != digest(path):
                    raise ValueError(f'Existing release asset differs: {path.name}')
        else:
            if not release['draft']:
                raise ValueError('Refusing to alter assets of a published release.')
            run('gh', 'release', 'upload', tag, str(path), '--repo', repo)


def finish(args):
    # Revalidate all assets/tag and confirm PyPI before making the release public.
    wait_for_visibility('GitHub release assets', lambda: stage(args, complete=True))
    args.complete = True
    args.index = 'pypi'
    check_pypi(args)
    run('gh', 'release', 'edit', f'v{args.version}', '--repo', os.environ['GITHUB_REPOSITORY'],
        '--draft=false', '--latest')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['plan', 'manifest', 'verify', 'stage', 'pypi', 'download', 'finish'])
    parser.add_argument('--version', default=os.environ.get('RELEASE_VERSION'))
    parser.add_argument('--commit', default=os.environ.get('RELEASE_COMMIT'))
    parser.add_argument('--bundle', default='bundle')
    parser.add_argument('--complete', action='store_true')
    parser.add_argument('--index', choices=['pypi', 'testpypi'], default='pypi')
    args = parser.parse_args()
    {'plan': plan, 'manifest': manifest, 'verify': verify, 'stage': stage,
     'pypi': check_pypi, 'download': download, 'finish': finish}[args.command](args)


if __name__ == '__main__':
    main()
