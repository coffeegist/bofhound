"""LDIF parser integration with the normalized LDAP cache and user export."""
import base64

import pytest

from bofhound.ad import ADDS
from bofhound.ad.helpers import PropertiesLevel
from bofhound.cache import ObjectCache
from bofhound.parsers import ParserType, ParsingPipelineFactory


@pytest.mark.parametrize('use_cache', [False, True], ids=['no-cache', 'cache-reopened'])
def test_ldif_user_sid_history_reaches_export(tmp_path, use_cache):
    """Migrated-user SID history must survive parsing, caching, and JSON export."""
    historical_sid = bytes.fromhex(
        '0105000000000005150000006f000000de0000004d0100005c110000'
    )
    current_sid = bytes.fromhex(
        '010500000000000515000000bc0100002b0200009a020000e9030000'
    )
    encoded_sid = base64.b64encode(historical_sid).decode('ascii')
    encoded_current_sid = base64.b64encode(current_sid).decode('ascii')
    path = tmp_path / 'users.ldif'
    path.write_text(
        'dn: CN=Alice,DC=example,DC=test\n'
        'objectClass: top\n'
        'objectClass: person\n'
        'objectClass: organizationalPerson\n'
        'objectClass: user\n'
        f'objectSid:: {encoded_current_sid}\n'
        'sAMAccountName: alice\n'
        'sAMAccountType: 805306368\n'
        f'sIDHistory:: {encoded_sid}\n',
        encoding='utf-8',
    )
    pipeline = ParsingPipelineFactory.create_pipeline(ParserType.LDIF)
    objects = pipeline.process_file(str(path)).get_ldap_objects()
    assert len(objects) == 1
    assert objects[0]['objectsid'] == 'S-1-5-21-444-555-666-1001'
    assert objects[0]['sidhistory'] == [historical_sid]

    if use_cache:
        cache_path = str(tmp_path / 'cache.db')
        with ObjectCache(cache_path) as cache:
            for raw in cache.merge_ldap_objects(objects):
                cache.store_object(raw)
            cache.commit()
        with ObjectCache(cache_path) as cache:
            objects = cache.merge_ldap_objects([])

    adds = ADDS()
    adds.import_objects(objects)
    assert len(adds.users) == 1
    exported = adds.users[0].to_json(PropertiesLevel.Standard)
    assert exported['Properties']['sidhistory'] == ['S-1-5-21-111-222-333-4444']
