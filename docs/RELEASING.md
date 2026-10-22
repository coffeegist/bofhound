# Releasing BOFHound

Releases use `.github/workflows/release.yml`. A maintainer starts the workflow,
which tests and builds the selected commit once, uploads those packages to
TestPyPI, downloads and installs them, and then waits for production approval.
After approval it tags the commit, stages a GitHub release, uploads the same saved
packages to production PyPI, and publishes the GitHub release.

This workflow supports stable `major.minor.patch` versions. It does not bump
versions or publish automatically when a PR is merged.

## One-time setup

Configure these GitHub environments with deployment restricted to `main`:

| Environment | Approval | Purpose |
| --- | --- | --- |
| `testpypi` | No additional approval | Real rehearsal upload to TestPyPI |
| `pypi` | Required maintainer review | All production tag/release/PyPI changes |

For `pypi`, allow the maintainer to approve their own deployment if they also
start releases. Otherwise a second maintainer must approve. Disable administrator
bypass to keep the approval gate in effect.

PyPI and TestPyPI use separate accounts and publisher settings. On each registry,
add a GitHub Trusted Publisher for the existing `bofhound` project:

| Field | Production PyPI | TestPyPI |
| --- | --- | --- |
| Owner | `coffeegist` | `coffeegist` |
| Repository | `bofhound` | `bofhound` |
| Workflow filename | `release.yml` | `release.yml` |
| Environment | `pypi` | `testpypi` |

Production publishing settings:
https://pypi.org/manage/project/bofhound/settings/publishing/

Test publishing settings:
https://test.pypi.org/manage/project/bofhound/settings/publishing/

If the project does not exist on TestPyPI, add a pending publisher at
https://test.pypi.org/manage/account/publishing/ with project name `bofhound`.
If the existing name is owned by someone else, resolve that before using this
workflow; publishing the same distribution requires the same project name.

No package-index API tokens are needed. Only the two upload jobs receive
`id-token: write`. The TestPyPI installation job has no publishing permissions.
The protected production job receives `contents: write` to manage its tag and
GitHub release. It runs no build or package-install commands. Actions are pinned
to commit SHAs.

References: [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/adding-a-publisher/),
[TestPyPI](https://packaging.python.org/en/latest/guides/using-testpypi/), and
[Python packaging release guidance](https://packaging.python.org/en/latest/guides/publishing-package-distribution-releases-using-github-actions-ci-cd-workflows/).

## Prepare a release

1. Open a normal PR changing `tool.poetry.version` in `pyproject.toml`.
2. Move the changes under `[Unreleased]` into a dated section such as
   `## [0.5.0] - 2026-10-21`, leaving a new Unreleased section above it.
   The workflow validates this section exists. GitHub release notes are generated
   separately from the merged PRs, using GitHub's standard release-note format.
3. Review and merge after CI passes. Copy the full merge commit SHA from `main`.
   Include the release workflow implementation in this commit's history.

## Publish

In GitHub Actions → Release → Run workflow, select **main** and supply:

- `version`: the committed package version, without `v`, for example `0.5.0`.
- `commit`: the exact, lowercase, 40-character SHA to release. It must be on main.

Or use:

```sh
gh workflow run release.yml --repo coffeegist/bofhound --ref main \
  -f version=0.5.0 -f commit=FULL_40_CHARACTER_COMMIT_SHA
```

The workflow validates the selected commit, version, changelog section, and
availability of the release version. It runs the full suite on Python 3.10,
builds a wheel and source archive, checks package metadata, and installs the
wheel with its declared dependencies in a clean environment outside the checkout.
It checks the installed CLI and dependency consistency.

The tested files and their SHA-256 hashes are saved as the `bofhound-release`
Actions artifact for 90 days. No further build is performed for this version.

## TestPyPI rehearsal and production approval

Every release must pass the TestPyPI rehearsal:

1. The `testpypi` job compares any existing TestPyPI files with the saved build,
   uploads only missing files using Trusted Publishing, and checks both hashes.
2. The separate `rehearsal` job downloads both uploaded files from TestPyPI and
   checks the downloaded bytes against the saved manifest. It installs that
   downloaded wheel into a fresh Python 3.10 environment, obtains dependencies
   only from production PyPI, checks dependency consistency and installed version,
   and runs the CLI outside the checkout. No mixed package indexes are used.
3. A summary identifies the rehearsed version and source commit. The `publish`
   job pauses for your `pypi` environment approval. At this point **no production
   tag, GitHub release, or production PyPI upload has been created by this run**.
4. Approve to continue with the same saved packages. The job rechecks TestPyPI
   hashes, tags the selected commit, creates the draft GitHub release, publishes
   to production PyPI, verifies its hashes, and makes the GitHub release public.

To stop after the rehearsal, reject or cancel the pending production deployment.
To continue later, rerun failed jobs in that original run and approve the new
production deployment request. Do not dispatch a new run for the same version:
that would rebuild packages after a real TestPyPI upload, which is rejected.

The GitHub draft uses generated notes matching past releases: What's Changed
with PR links and author credits, New Contributors when applicable, and the full
changelog comparison link. Notes target the selected release commit, with GitHub
selecting the previous tag automatically. They are generated when creating the
draft, after production approval; retries preserve the draft notes.

TestPyPI has its own version history. Testing `0.5.0` there does not use up that
version on production PyPI. If the packages change after a rehearsal upload,
prepare a new version rather than replacing files. If only the workflow needs
repair, rerun the failed jobs in the original run with its saved artifacts when
possible; reruns use the original workflow revision.

This rehearsal verifies real TestPyPI authentication, upload, and package
installation. Production PyPI has a separate publisher configuration, which is
only fully exercised on the first approved production upload.

After completion, check the GitHub release assets and install the released version
in a fresh environment:

```sh
python -m pip install bofhound==0.5.0
bofhound --help
```

## Resume a failed release

Use **Re-run failed jobs** on the original run, or:

```sh
gh run rerun RUN_ID --repo coffeegist/bofhound --failed
```

Do not start a new workflow for the same version once it exists on either
package index or its production tag exists. Successful
build jobs stay complete when rerunning failed jobs. If all jobs are rerun, the
build job reuses that run's saved artifact rather than rebuilding. Missing or
expired saved artifacts cannot be rebuilt after the version has been uploaded
to TestPyPI/PyPI or its release tag exists.

Partial GitHub uploads resume by adding only missing assets. Existing assets
must match byte for byte; the workflow never replaces them. Partial PyPI uploads
resume by uploading only missing files, after comparing all existing hashes.
Conflicting tags, versions, assets, or hashes stop the release. If PyPI succeeds
but the final GitHub step fails, rerun that step to finish publication.

GitHub supports reruns for 30 days. Retain the Actions artifact and staged GitHub
assets throughout recovery. If recovery is no longer possible, investigate the
published state and prepare a new version; do not move tags or replace packages.
A rejected production approval leaves only the TestPyPI rehearsal upload.
If production has already started, the tag/draft and any uploaded files remain
for recovery. Nothing is automatically rolled back after a partial publication.

## Fix a problem after publication

Keep existing release tags and package files unchanged. Fix or revert the affected
code through a normal PR, bump to a new patch version (for example `0.5.1`), and
run the same rehearsal/approval process. The original tag continues to identify
exactly what was published as `0.5.0`.

For a badly broken release, a maintainer can yank that version from PyPI with a
clear reason while preparing the patch. Yanking discourages new installations;
it does not change existing installations, and exact version pins can still
select the yanked version. Do not delete and try to reuse a package filename.
Users can explicitly install an earlier known-good version while waiting:

```sh
python -m pip install 'bofhound==0.4.25'
```

See [PyPI yanking guidance](https://docs.pypi.org/project-management/yanking/).
