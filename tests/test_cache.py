"""Cache persistence must be safe even if its contents have been replaced."""
import pickle
import sqlite3

import pytest

from bofhound.cache import ObjectCache
from bofhound.ad.models import BloodHoundUser


RAW_USER = {
    'distinguishedname': 'CN=Example,DC=example,DC=test',
    'objectsid': 'S-1-5-21-111-222-333-5678',
    'samaccountname': 'example', 'description': 'old',
}


def test_cache_stores_data_only(tmp_path):
    with ObjectCache(str(tmp_path / 'cache.db')) as cache:
        obj = BloodHoundUser(RAW_USER)
        cache.store_object(obj)
        assert cache.get_cached_object(sid=obj.ObjectIdentifier)['data'] == obj.Properties
        assert cache.get_all_cached_objects() == [obj.Properties]


def test_old_cache_is_rejected_without_migration(tmp_path):
    path = tmp_path / 'old.db'
    with sqlite3.connect(path) as connection:
        connection.execute('CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT)')
        connection.execute("INSERT INTO metadata VALUES ('cache_version', '1.1.0')")
    before = path.read_bytes()
    with pytest.raises(ValueError, match='rebuild'):
        ObjectCache(str(path))
    assert path.read_bytes() == before


class PrintMarker:
    def __reduce__(self):
        # A harmless function invocation would still prove unsafe deserialization.
        return print, ('UNSAFE_CACHE_MARKER',)


def test_tampered_cache_never_executes_pickle(tmp_path, capsys):
    with ObjectCache(str(tmp_path / 'cache.db')) as cache:
        cache.store_object(BloodHoundUser(RAW_USER))
        cache.conn.execute('UPDATE objects SET data = ?', (pickle.dumps(PrintMarker()),))
        with pytest.raises((ValueError, UnicodeDecodeError)):
            cache.get_cached_object(sid=RAW_USER['objectsid'])
        with pytest.raises((ValueError, UnicodeDecodeError)):
            cache.get_all_cached_objects()
    assert 'UNSAFE_CACHE_MARKER' not in capsys.readouterr().out
