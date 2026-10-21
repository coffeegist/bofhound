"""Regression coverage for class-restricted ACEs in schema-free LDAP dumps."""

import base64

import pytest
from impacket.ldap.ldaptypes import (
    ACE, ACL, ACCESS_MASK, ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_OBJECT_ACE,
    LDAP_SID, SR_SECURITY_DESCRIPTOR,
)
from impacket.uuid import string_to_bin

from bofhound.ad import ADDS
from bofhound.ad.models import (
    BloodHoundUser, BloodHoundComputer, BloodHoundGroup, BloodHoundOU,
    BloodHoundDomain, BloodHoundGPO, BloodHoundContainer,
)


USER_GUID = "bf967aba-0de6-11d0-a285-00aa003049e2"
COMPUTER_GUID = "bf967a86-0de6-11d0-a285-00aa003049e2"
RESET_PASSWORD_GUID = "00299570-246d-11d0-a768-00aa006e0529"
TRUSTEE_SID = "S-1-5-21-111-222-333-1234"


def make_acl_entry(entry_type="User", inherited_guid=USER_GUID, right_guid=None,
               mask=0x00040000, inherited=True, inherit_only=False,
               object_ace=True):
    """Build a synthetic descriptor; no engagement data or secrets are used."""
    trustee = LDAP_SID()
    trustee.fromCanonical(TRUSTEE_SID)
    ace = ACE()
    ace["AceFlags"] = 0x02 | (0x10 if inherited else 0) | (0x08 if inherit_only else 0)
    if object_ace:
        ace["AceType"] = ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE
        body = ACCESS_ALLOWED_OBJECT_ACE()
        body["Flags"] = (1 if right_guid else 0) | (2 if inherited_guid else 0)
        body["ObjectType"] = string_to_bin(right_guid) if right_guid else b""
        body["InheritedObjectType"] = string_to_bin(inherited_guid) if inherited_guid else b""
    else:
        ace["AceType"] = ACCESS_ALLOWED_ACE.ACE_TYPE
        body = ACCESS_ALLOWED_ACE()
    body["Mask"] = ACCESS_MASK()
    body["Mask"]["Mask"] = mask
    body["Sid"] = trustee
    ace["Ace"] = body

    dacl = ACL()
    dacl["AclRevision"] = 4
    dacl["Sbz1"] = 0
    dacl["Sbz2"] = 0
    dacl.aces = [ace]
    owner = LDAP_SID()
    owner.fromCanonical("S-1-5-18")  # Ignored owner; isolate the tested ACE.
    descriptor = SR_SECURITY_DESCRIPTOR()
    descriptor["Revision"] = b"\x01"
    descriptor["Sbz1"] = b"\x00"
    descriptor["Control"] = 0x8004
    descriptor["OwnerSid"] = owner
    descriptor["GroupSid"] = b""
    descriptor["Sacl"] = b""
    descriptor["Dacl"] = dacl

    model = {
        "User": BloodHoundUser, "Computer": BloodHoundComputer,
        "Group": BloodHoundGroup, "OU": BloodHoundOU,
        "Domain": BloodHoundDomain, "GPO": BloodHoundGPO,
        "Container": BloodHoundContainer,
    }.get(entry_type, BloodHoundUser)
    entry = model({
        "distinguishedname": "CN=Example,OU=People,DC=example,DC=test",
        "samaccountname": "example",
        "objectsid": "S-1-5-21-111-222-333-5678",
    })
    entry._entry_type = entry_type
    entry.RawAces = base64.b64encode(descriptor.getData()).decode("ascii")
    return entry


@pytest.mark.parametrize("mask,right_guid,expected", [
    (0x00000100, RESET_PASSWORD_GUID, "ForceChangePassword"),
    (0x00050000, None, "WriteDacl"),
    (0x00000030, None, "GenericWrite"),
])
def test_user_class_restricted_ace_without_schema(mask, right_guid, expected):
    adds = ADDS()
    entry = make_acl_entry(mask=mask, right_guid=right_guid)

    adds.parse_acl(entry)

    assert entry.Aces == [{
        "RightName": expected, "PrincipalSID": TRUSTEE_SID,
        "IsInherited": True, "PrincipalType": "Unknown",
    }]


@pytest.mark.parametrize("entry_type,class_guid", [
    ("User", USER_GUID),
    ("Computer", COMPUTER_GUID),
    ("Group", "bf967a9c-0de6-11d0-a285-00aa003049e2"),
    ("OU", "bf967aa5-0de6-11d0-a285-00aa003049e2"),
    ("Domain", "19195a5b-6da0-11d0-afd3-00c04fd930c9"),
    ("GPO", "f30e3bc2-9ff0-11d1-b603-0000f80367c1"),
    ("Container", "bf967a8b-0de6-11d0-a285-00aa003049e2"),
])
def test_standard_class_restricted_write_dacl_without_schema(entry_type, class_guid):
    adds = ADDS()
    entry = make_acl_entry(entry_type=entry_type, inherited_guid=class_guid)

    adds.parse_acl(entry)

    assert [ace["RightName"] for ace in entry.Aces] == ["WriteDacl"]


def test_ace_restricted_to_computer_does_not_apply_to_user():
    adds = ADDS()
    entry = make_acl_entry(inherited_guid=COMPUTER_GUID)

    adds.parse_acl(entry)

    assert entry.Aces == []


def test_explicit_ace_child_class_restriction_does_not_restrict_current_object():
    adds = ADDS()
    entry = make_acl_entry(inherited_guid=COMPUTER_GUID, inherited=False)

    adds.parse_acl(entry)

    assert [ace["RightName"] for ace in entry.Aces] == ["WriteDacl"]


@pytest.mark.parametrize("inherited", [False, True])
@pytest.mark.parametrize("object_ace", [False, True])
def test_inherit_only_ace_never_applies_to_current_object(inherited, object_ace):
    adds = ADDS()
    adds.ObjectTypeGuidMap["user"] = USER_GUID
    entry = make_acl_entry(inherited=inherited, inherit_only=True, object_ace=object_ace)

    adds.parse_acl(entry)

    assert entry.Aces == []


@pytest.mark.parametrize("object_ace", [False, True])
def test_unrestricted_inherited_ace_still_applies(object_ace):
    adds = ADDS()
    entry = make_acl_entry(inherited_guid=None, object_ace=object_ace)

    adds.parse_acl(entry)

    assert [ace["RightName"] for ace in entry.Aces] == ["WriteDacl"]


def test_supplied_schema_takes_precedence_over_standard_fallback():
    adds = ADDS()
    custom_guid = "12345678-1234-1234-1234-123456789abc"
    adds.import_objects([{"name": "User", "schemaidguid": custom_guid}])
    entry = make_acl_entry(inherited_guid=USER_GUID)

    adds.parse_acl(entry)

    assert entry.Aces == []
    entry = make_acl_entry(inherited_guid=custom_guid)
    adds.parse_acl(entry)
    assert [ace["RightName"] for ace in entry.Aces] == ["WriteDacl"]


@pytest.mark.parametrize("entry_type,schema_name", [
    ("OU", "Organizational-Unit"),
    ("Domain", "Domain-DNS"),
    ("GPO", "Group-Policy-Container"),
])
def test_schema_names_resolve_bloodhound_type_aliases(entry_type, schema_name):
    adds = ADDS()
    # Use a distinct GUID to prove the supplied alias is consulted before fallback.
    custom_guid = "12345678-1234-1234-1234-123456789abc"
    adds.import_objects([{"name": schema_name, "schemaidguid": custom_guid}])
    entry = make_acl_entry(entry_type=entry_type, inherited_guid=custom_guid)

    adds.parse_acl(entry)

    assert [ace["RightName"] for ace in entry.Aces] == ["WriteDacl"]


def test_unknown_class_is_skipped_without_schema_and_supported_with_schema():
    adds = ADDS()
    custom_guid = "12345678-1234-1234-1234-123456789abc"
    entry = make_acl_entry(entry_type="CustomClass", inherited_guid=custom_guid)
    adds.parse_acl(entry)
    assert entry.Aces == []

    adds.import_objects([{"name": "CustomClass", "schemaidguid": custom_guid}])
    entry = make_acl_entry(entry_type="CustomClass", inherited_guid=custom_guid)
    adds.parse_acl(entry)
    assert [ace["RightName"] for ace in entry.Aces] == ["WriteDacl"]


@pytest.mark.parametrize('entry_type,schema_name', [
    ('User', 'User'), ('Computer', 'Computer'), ('Group', 'Group'),
    ('OU', 'Organizational-Unit'), ('Domain', 'Domain-DNS'),
    ('GPO', 'Group-Policy-Container'), ('Container', 'Container'),
])
@pytest.mark.parametrize('collected_schema', [False, True])
def test_inherited_class_restrictions_accept_only_matching_guid(entry_type, schema_name, collected_schema):
    adds = ADDS()
    # A partial schema collection must not disable fallback for unrelated classes.
    adds.import_objects([{'name': 'Unrelated-Class', 'schemaidguid': USER_GUID}])
    custom_guid = '12345678-1234-1234-1234-123456789abc'
    if collected_schema:
        adds.import_objects([{'name': schema_name, 'schemaidguid': custom_guid.upper()}])
        accepted = custom_guid
    else:
        from bofhound.ad.adds import STANDARD_CLASS_GUIDS
        accepted = STANDARD_CLASS_GUIDS[schema_name.lower()]
    rejected = custom_guid if not collected_schema else 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    entry = make_acl_entry(entry_type=entry_type, inherited_guid=rejected)
    adds.parse_acl(entry)
    assert entry.Aces == []
    entry = make_acl_entry(entry_type=entry_type, inherited_guid=accepted.upper())
    adds.parse_acl(entry)
    assert entry.Aces == [{
        'RightName': 'WriteDacl', 'PrincipalSID': TRUSTEE_SID,
        'IsInherited': True, 'PrincipalType': 'Unknown',
    }]


@pytest.mark.parametrize('entry_type', ['User', 'Computer', 'Group', 'OU', 'Domain', 'GPO', 'Container'])
@pytest.mark.parametrize('options', [
    {}, {'inherited_guid': COMPUTER_GUID}, {'inherit_only': True},
    {'inherit_only': True, 'object_ace': False}, {'inherited': False},
    {'right_guid': RESET_PASSWORD_GUID},
    {'right_guid': RESET_PASSWORD_GUID, 'mask': 0x100},
    {'mask': 0x10000000, 'inherited_guid': None},
    {'mask': 0x30, 'inherited_guid': None},
    {'mask': 0x40000, 'object_ace': False},
])
def test_parallel_adapter_matches_current_acl_parser(entry_type, options):
    from types import SimpleNamespace
    from bofhound.ad.acl_worker import (
        create_worker_context, prepare_entry_for_worker, parse_acl_standalone,
    )
    adds = ADDS()
    adds.SID_MAP[TRUSTEE_SID] = SimpleNamespace(_entry_type='Group')
    entry = make_acl_entry(entry_type=entry_type, **options)
    adds.parse_acl(entry)
    object_id, aces, protected = parse_acl_standalone(
        prepare_entry_for_worker(entry),
        create_worker_context(adds.SID_MAP, adds.DOMAIN_MAP, adds.ObjectTypeGuidMap),
    )
    assert object_id == entry.ObjectIdentifier
    assert aces == entry.Aces
    assert protected == entry.IsACLProtected


@pytest.mark.parametrize('attribute', ['ms-mcs-admpwd', 'ms-laps-password', 'ms-laps-encryptedpassword'])
def test_parallel_adapter_preserves_laps_rights(attribute):
    from bofhound.ad.acl_worker import create_worker_context, prepare_entry_for_worker, parse_acl_standalone
    adds = ADDS()
    guid = '12345678-1234-1234-1234-123456789abc'
    adds.ObjectTypeGuidMap[attribute] = guid
    entry = make_acl_entry(entry_type='Computer', inherited_guid=COMPUTER_GUID, right_guid=guid, mask=0x100)
    entry.Properties['haslaps'] = True
    adds.parse_acl(entry)
    assert [ace['RightName'] for ace in entry.Aces] == ['ReadLAPSPassword']
    result = parse_acl_standalone(prepare_entry_for_worker(entry), create_worker_context({}, {}, adds.ObjectTypeGuidMap))
    assert result[1] == entry.Aces


def test_spawned_acl_worker_matches_serial():
    import multiprocessing
    from concurrent.futures import ProcessPoolExecutor
    from bofhound.ad.acl_worker import create_worker_context, prepare_entry_for_worker, _worker_init, _worker_process
    entries = [make_acl_entry(), make_acl_entry(inherit_only=True)]
    adds = ADDS()
    for entry in entries:
        adds.parse_acl(entry)
    context = create_worker_context({}, {}, {})
    with ProcessPoolExecutor(max_workers=2, mp_context=multiprocessing.get_context('spawn'),
                             initializer=_worker_init, initargs=(context,)) as executor:
        results = list(executor.map(_worker_process, map(prepare_entry_for_worker, entries)))
    assert [result[1] for result in results] == [entry.Aces for entry in entries]


@pytest.mark.parametrize('workers', [1, 2])
def test_failed_acl_aborts_processing(workers):
    adds = ADDS()
    entries = [make_acl_entry(), make_acl_entry()]
    entries[1].RawAces = 'bm90IGEgZGVzY3JpcHRvcg=='
    adds.users = entries
    with pytest.raises(RuntimeError, match='Unable to parse ACL'):
        adds.process(num_workers=workers)
