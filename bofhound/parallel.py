"""Bounded, ordered scheduling for process workers."""
from collections import deque
from itertools import islice
import sys


def ordered_parallel_map(executor, function, items, max_pending):
    """Keep a small submission window; propagate failures before yielding later work."""
    if max_pending < 1:
        raise ValueError("max_pending must be positive")
    items = iter(items)
    pending = deque(executor.submit(function, item) for item in islice(items, max_pending))
    try:
        while pending:
            result = pending.popleft().result()
            yield result
            for item in islice(items, 1):
                pending.append(executor.submit(function, item))
    finally:
        for future in pending:
            future.cancel()


def worker_limit(requested, task_count):
    # ProcessPoolExecutor requires max_workers <= 61 on Windows (Python 3.10+).
    platform_limit = 61 if sys.platform == 'win32' else requested
    return max(1, min(requested, max(1, task_count), platform_limit))
