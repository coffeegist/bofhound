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


@pytest.mark.parametrize('identity_attribute', ['objectsid', 'objectguid'])
def test_replacement_identity_does_not_inherit_old_security_attributes(tmp_path, identity_attribute):
    from bofhound.ad import ADDS
    from tests.ad.test_inherited_acls import make_acl_entry
    old_identity, new_identity = (
        ('S-1-5-21-111-222-333-1001', 'S-1-5-21-111-222-333-1002')
        if identity_attribute == 'objectsid' else
        ('11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222')
    )
    old = {
        'distinguishedname': RAW_USER['distinguishedname'],
        identity_attribute: old_identity,
        'ntsecuritydescriptor': make_acl_entry().RawAces,
        'memberof': 'CN=Domain Admins,DC=example,DC=test',
        'admincount': '1', 'samaccounttype': '805306368',
        'samaccountname': 'old-account',
    }
    replacement = {
        'distinguishedname': old['distinguishedname'], identity_attribute: new_identity,
        'samaccounttype': '805306368', 'samaccountname': 'replacement',
    }
    with ObjectCache(str(tmp_path / 'cache.db')) as cache:
        cache.store_object(old)
        merged = cache.merge_ldap_objects([replacement])
        assert merged == [replacement]
        cache.store_object(merged[0])
        assert cache.get_all_cached_objects() == [replacement]
    if identity_attribute == 'objectsid':
        adds = ADDS()
        adds.import_objects(merged)
        adds.parse_acl(adds.users[0])
        assert adds.users[0].Aces == []
        assert adds.users[0].RawAces is None



@pytest.mark.parametrize('initial_has_sid', [False, True])
def test_partial_guid_collection_preserves_identity_and_attributes(tmp_path, initial_has_sid):
    guid = '11111111-1111-1111-1111-111111111111'
    sid = RAW_USER['objectsid']
    old = {**RAW_USER, 'objectguid': guid, 'samaccounttype': '805306368'}
    if not initial_has_sid:
        old.pop('objectsid')
    partial = {'objectguid': guid.upper(), 'distinguishedname': old['distinguishedname']}
    if not initial_has_sid:
        partial['objectsid'] = sid
    with ObjectCache(str(tmp_path / 'cache.db')) as cache:
        cache.store_object(old)
        merged = cache.merge_ldap_objects([partial])
        assert merged == [{**old, **partial}]
        assert merged[0]['objectsid'] == sid
        cache.store_object(merged[0])
        assert cache.get_all_cached_objects() == merged



@pytest.mark.parametrize('incoming_sid', [False, True])
def test_guid_alias_follows_rename_and_persists_one_identity(tmp_path, incoming_sid):
    from bofhound.ad import ADDS
    guid = '11111111-1111-1111-1111-111111111111'
    old = {**RAW_USER, 'objectguid': guid, 'samaccounttype': '805306368'}
    partial = {'objectguid': guid, 'distinguishedname': 'CN=Renamed,DC=example,DC=test', 'description': 'new'}
    if incoming_sid:
        old.pop('objectsid')
        partial['objectsid'] = RAW_USER['objectsid']
    path = str(tmp_path / 'cache.db')
    with ObjectCache(path) as cache:
        cache.store_object(old)
        merged = cache.merge_ldap_objects([partial])
        assert merged == [{**old, **partial}]
        cache.store_object(merged[0])
        assert cache.get_all_cached_objects() == merged
        adds = ADDS()
        adds.import_objects(merged)
        assert len(adds.users) == 1
        assert adds.users[0].ObjectIdentifier == RAW_USER['objectsid']
        assert adds.users[0].Properties['distinguishedname'] == partial['distinguishedname'].upper()
        assert adds.users[0].Properties['description'] == 'new'
    with ObjectCache(path) as cache:
        assert cache.merge_ldap_objects([]) == merged


def test_sid_and_guid_partial_records_join_without_losing_fields(tmp_path):
    guid = '11111111-1111-1111-1111-111111111111'
    with ObjectCache(str(tmp_path / 'cache.db')) as cache:
        cache.store_object({**RAW_USER, 'distinguishedname': 'CN=Old,DC=example,DC=test'})
        cache.store_object({'objectguid': guid, 'distinguishedname': 'CN=New,DC=example,DC=test', 'displayname': 'Example'})
        update = {'objectsid': RAW_USER['objectsid'], 'objectguid': guid, 'distinguishedname': 'CN=New,DC=example,DC=test'}
        merged = cache.merge_ldap_objects([update])
        assert len(merged) == 1
        assert merged[0]['samaccountname'] == 'example'
        assert merged[0]['displayname'] == 'Example'


@pytest.mark.parametrize('retired_first', [False, True])
def test_rename_into_retired_dn_keeps_current_identity_and_acl_isolation(tmp_path, retired_first):
    from bofhound.ad import ADDS
    from tests.ad.test_inherited_acls import make_acl_entry
    current = {**RAW_USER, 'objectguid': '11111111-1111-1111-1111-111111111111', 'samaccounttype': '805306368'}
    retired = {
        **current, 'objectsid': 'S-1-5-21-111-222-333-9999',
        'objectguid': '22222222-2222-2222-2222-222222222222',
        'distinguishedname': 'CN=Reused,DC=example,DC=test',
        'samaccountname': 'retired', 'ntsecuritydescriptor': make_acl_entry().RawAces,
    }
    path = str(tmp_path / 'cache.db')
    with ObjectCache(path) as cache:
        for raw in ([retired, current] if retired_first else [current, retired]):
            cache.store_object(raw)
        update = {'objectsid': current['objectsid'], 'distinguishedname': retired['distinguishedname']}
        merged = cache.merge_ldap_objects([update])
        assert merged == [{**current, **update}]
        adds = ADDS()
        adds.import_objects(merged)
        assert len(adds.users) == 1
        adds.parse_acl(adds.users[0])
        assert adds.users[0].ObjectIdentifier == current['objectsid']
        assert adds.users[0].Aces == []
        assert adds.users[0].RawAces is None
        for raw in merged:
            cache.store_object(raw)
        assert cache.get_all_cached_objects() == merged
    with ObjectCache(path) as cache:
        assert cache.merge_ldap_objects([]) == merged


def test_displaced_identity_can_move_later_with_its_own_attributes(tmp_path):
    current = {**RAW_USER, 'objectguid': '11111111-1111-1111-1111-111111111111'}
    retired = {**current, 'objectsid': 'S-1-5-21-111-222-333-9999',
               'objectguid': '22222222-2222-2222-2222-222222222222',
               'distinguishedname': 'CN=Reused,DC=example,DC=test', 'description': 'retired'}
    with ObjectCache(str(tmp_path / 'cache.db')) as cache:
        cache.store_object(current)
        cache.store_object(retired)
        merged = cache.merge_ldap_objects([
            {'objectsid': current['objectsid'], 'distinguishedname': retired['distinguishedname']},
            {'objectguid': retired['objectguid'], 'distinguishedname': 'CN=Elsewhere,DC=example,DC=test'},
        ])
        assert len(merged) == 2
        by_dn = {obj['distinguishedname']: obj for obj in merged}
        assert by_dn[retired['distinguishedname']]['objectsid'] == current['objectsid']
        assert by_dn['CN=Elsewhere,DC=example,DC=test']['description'] == 'retired'
        assert by_dn['CN=Elsewhere,DC=example,DC=test']['objectsid'] == retired['objectsid']


@pytest.mark.parametrize('reverse_order', [False, True])
@pytest.mark.parametrize('swap', [False, True])
def test_multiple_partial_renames_preserve_each_identity_independent_of_order(tmp_path, reverse_order, swap):
    from bofhound.ad import ADDS
    from tests.ad.test_inherited_acls import make_acl_entry
    a = {**RAW_USER, 'samaccounttype': '805306368', 'samaccountname': 'a'}
    b = {**a, 'objectsid': 'S-1-5-21-111-222-333-1002', 'samaccountname': 'b',
         'distinguishedname': 'CN=B,DC=example,DC=test', 'ntsecuritydescriptor': make_acl_entry().RawAces}
    updates = [
        {'objectsid': a['objectsid'], 'distinguishedname': b['distinguishedname']},
        {'objectsid': b['objectsid'], 'distinguishedname': a['distinguishedname'] if swap else 'CN=C,DC=example,DC=test'},
    ]
    if reverse_order:
        updates.reverse()
    path = str(tmp_path / 'cache.db')
    with ObjectCache(path) as cache:
        cache.store_object(a)
        cache.store_object(b)
        merged = cache.merge_ldap_objects(updates)
        adds = ADDS()
        adds.import_objects(merged)
        assert len(adds.users) == 2
        users = {user.ObjectIdentifier: user for user in adds.users}
        assert users[a['objectsid']].Properties['samaccountname'] == 'a'
        assert users[a['objectsid']].RawAces is None
        assert users[b['objectsid']].Properties['samaccountname'] == 'b'
        assert users[b['objectsid']].RawAces == b['ntsecuritydescriptor']
        assert users[a['objectsid']].Properties['distinguishedname'] == b['distinguishedname'].upper()
        expected_b_dn = a['distinguishedname'] if swap else 'CN=C,DC=example,DC=test'
        assert users[b['objectsid']].Properties['distinguishedname'] == expected_b_dn.upper()
        for obj in merged:
            cache.store_object(obj)
        assert cache.get_all_cached_objects() == merged
    with ObjectCache(path) as cache:
        assert cache.merge_ldap_objects([]) == merged



@pytest.mark.parametrize('fresh_group', [False, True])
def test_cached_membership_does_not_transfer_to_new_dn_occupant(tmp_path, fresh_group):
    from bofhound.ad import ADDS
    a = {**RAW_USER, 'samaccounttype': '805306368'}
    b = {**a, 'objectsid': 'S-1-5-21-111-222-333-1002', 'distinguishedname': 'CN=B,DC=example,DC=test'}
    group = {'objectsid': 'S-1-5-21-111-222-333-2000', 'samaccounttype': '268435456',
             'samaccountname': 'privileged', 'distinguishedname': 'CN=Privileged,DC=example,DC=test',
             'member': b['distinguishedname']}
    with ObjectCache(str(tmp_path / 'cache.db')) as cache:
        for raw in [a, b, group]:
            cache.store_object(raw)
        incoming = [{'objectsid': a['objectsid'], 'distinguishedname': b['distinguishedname']}]
        if fresh_group:
            incoming.append(group)
        merged = cache.merge_ldap_objects(incoming)
        adds = ADDS()
        adds.import_objects(merged)
        adds.resolve_group_members()
        assert adds.groups[0].Members == ([{'ObjectIdentifier': a['objectsid'], 'ObjectType': 'User'}]
                                         if fresh_group else [])
        for raw in merged:
            cache.store_object(raw)
        assert cache.merge_ldap_objects([]) == merged


def test_cached_membership_follows_same_identity_rename(tmp_path):
    from bofhound.ad import ADDS
    user = {**RAW_USER, 'samaccounttype': '805306368', 'memberof': 'CN=Group,DC=example,DC=test'}
    group = {'objectsid': 'S-1-5-21-111-222-333-2000', 'samaccounttype': '268435456',
             'samaccountname': 'group', 'distinguishedname': user['memberof'], 'member': user['distinguishedname']}
    with ObjectCache(str(tmp_path / 'cache.db')) as cache:
        cache.store_object(user)
        cache.store_object(group)
        merged = cache.merge_ldap_objects([
            {'objectsid': user['objectsid'], 'distinguishedname': 'CN=Renamed,DC=example,DC=test'},
            {'objectsid': group['objectsid'], 'distinguishedname': 'CN=RenamedGroup,DC=example,DC=test'},
        ])
        by_sid = {raw['objectsid']: raw for raw in merged}
        assert by_sid[user['objectsid']]['memberof'] == 'CN=RenamedGroup,DC=example,DC=test'
        assert by_sid[group['objectsid']]['member'] == 'CN=Renamed,DC=example,DC=test'
        adds = ADDS()
        adds.import_objects(merged)
        adds.resolve_group_members()
        assert adds.groups[0].Members == [{'ObjectIdentifier': user['objectsid'], 'ObjectType': 'User'}]
