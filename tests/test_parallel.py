"""Process scheduling must not queue an entire large directory in memory."""
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from bofhound import parallel


def test_submission_window_is_bounded_and_output_ordered():
    consumed = []

    def items():
        for index in range(100):
            consumed.append(index)
            yield index

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = parallel.ordered_parallel_map(executor, int, items(), max_pending=4)
        first = next(results)
        assert len(consumed) == 4
        assert [first] + list(results) == list(range(100))


def test_worker_error_propagates():
    with ThreadPoolExecutor(max_workers=2) as executor:
        with pytest.raises(ValueError):
            list(parallel.ordered_parallel_map(executor, int, ['1', 'bad', '3'], max_pending=2))


@pytest.mark.parametrize('platform,requested,tasks,expected', [
    ('win32', 72, 100, 61), ('darwin', 72, 100, 72),
    ('win32', 72, 2, 2), ('darwin', 8, 0, 1),
])
def test_worker_count_respects_platform_and_workload(monkeypatch, platform, requested, tasks, expected):
    monkeypatch.setattr(parallel, 'sys', SimpleNamespace(platform=platform))
    assert parallel.worker_limit(requested, tasks) == expected
