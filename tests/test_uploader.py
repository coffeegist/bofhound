"""BloodHound HTTP results and bounded request regressions."""
from unittest.mock import Mock

import pytest
import requests

from bofhound.uploader import BloodHoundUploader


@pytest.mark.parametrize('operation,status', [('preflight', 200), ('create_upload_job', 201), ('upload_file', 202), ('close_upload_job', 200)])
@pytest.mark.parametrize('failure', [None, 401, 500, 'timeout'])
def test_http_results(monkeypatch, tmp_path, operation, status, failure):
    uploader = BloodHoundUploader('http://bloodhound', 'id', 'key')
    file = tmp_path / 'users.json'
    file.write_text('{}')
    response = Mock(status_code=failure or status)
    response.json.return_value = {'data': {'id': 42}, 'errors': [{'message': 'rejected'}]}
    request = Mock(return_value=response)
    if failure == 'timeout':
        request.side_effect = requests.Timeout('timed out')
    monkeypatch.setattr('bofhound.uploader.requests.request', request)
    args = [file] if operation == 'upload_file' else []
    assert getattr(uploader, operation)(*args) is (failure is None)
    assert request.call_args.kwargs['timeout'] == (10, 300)
    if operation == 'preflight':
        assert request.call_args.kwargs['method'] == 'GET'
        assert request.call_args.kwargs['url'].endswith('/api/v2/file-upload')
        assert uploader.upload_job_id is None


def test_missing_file_returns_failure(tmp_path):
    assert BloodHoundUploader('http://bloodhound', 'id', 'key').upload_file(tmp_path / 'missing.json') is False
