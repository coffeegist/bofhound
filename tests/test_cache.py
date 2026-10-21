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
        cache.store_object(RAW_USER)
        assert cache.get_cached_object(sid=obj.ObjectIdentifier)['data'] == cache._normalize_object(RAW_USER)
        assert cache.get_all_cached_objects() == [cache._normalize_object(RAW_USER)]


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
        cache.store_object(RAW_USER)
        cache.conn.execute('UPDATE objects SET data = ?', (pickle.dumps(PrintMarker()),))
        with pytest.raises((ValueError, UnicodeDecodeError)):
            cache.get_cached_object(sid=RAW_USER['objectsid'])
        with pytest.raises((ValueError, UnicodeDecodeError)):
            cache.get_all_cached_objects()
    assert 'UNSAFE_CACHE_MARKER' not in capsys.readouterr().out


@pytest.mark.parametrize('attribute,value', [
    ('description', 'new'), ('lastlogon', '12345'), ('whenchanged', 'now'),
    ('ntsecuritydescriptor', 'changed ACL'), ('description', ''),
])
def test_changed_attributes_are_not_skipped(tmp_path, attribute, value):
    with ObjectCache(str(tmp_path / 'cache.db')) as cache:
        cache.store_object(RAW_USER)
        assert cache.get_changed_objects([RAW_USER]) == []
        changed = dict(RAW_USER, **{attribute: value})
        assert cache.get_changed_objects([changed]) == [changed]


def test_incremental_snapshot_retains_old_objects_and_updates_partial_attributes(tmp_path):
    with ObjectCache(str(tmp_path / 'cache.db')) as cache:
        cache.store_object(RAW_USER)
        updated = {'objectsid': RAW_USER['objectsid'], 'description': ''}
        other = {'distinguishedname': 'CN=Other,DC=example,DC=test', 'name': 'Other'}
        objects = cache.merge_ldap_objects([updated, other])
        assert len(objects) == 2
        assert objects[0]['samaccountname'] == 'example'
        assert objects[0]['description'] == ''
        assert objects[1]['name'] == 'Other'


def test_rename_replaces_old_dn_without_duplicate(tmp_path):
    with ObjectCache(str(tmp_path / 'cache.db')) as cache:
        cache.store_object(RAW_USER)
        renamed = dict(RAW_USER, distinguishedname='CN=Renamed,DC=example,DC=test')
        merged = cache.merge_ldap_objects([renamed])
        assert len(merged) == 1
        cache.store_object(merged[0])
        assert len(cache.get_all_cached_objects()) == 1
        assert cache.get_all_cached_objects()[0]['distinguishedname'].startswith('CN=Renamed,')


def test_failed_transaction_does_not_advance_objects_or_context(tmp_path):
    path = str(tmp_path / 'cache.db')
    with pytest.raises(RuntimeError):
        with ObjectCache(path) as cache:
            cache.store_object(RAW_USER)
            cache.store_sid_mappings_bulk([('sid', 'name', 'User', 'domain')])
            raise RuntimeError('output failed')
    with ObjectCache(path) as cache:
        assert cache.get_all_cached_objects() == []
        assert cache.get_all_sid_mappings() == {}



def test_partial_dn_only_update_keeps_identity_and_replaces_empty_attributes(tmp_path):
    with ObjectCache(str(tmp_path / 'cache.db')) as cache:
        cache.store_object(RAW_USER)
        merged = cache.merge_ldap_objects([{
            'distinguishedname': RAW_USER['distinguishedname'].upper(),
            'description': '',
        }])
        assert len(merged) == 1
        assert merged[0]['objectsid'] == RAW_USER['objectsid']
        assert merged[0]['description'] == ''


def test_new_identity_at_same_dn_supersedes_old_snapshot(tmp_path):
    with ObjectCache(str(tmp_path / 'cache.db')) as cache:
        cache.store_object(RAW_USER)
        replacement = dict(RAW_USER, objectsid='S-1-5-21-111-222-333-9999')
        merged = cache.merge_ldap_objects([replacement])
        assert merged == [replacement]
        cache.store_object(merged[0])
        assert cache.get_all_cached_objects() == [replacement]
