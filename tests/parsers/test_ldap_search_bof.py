"""Tests for LDAP Search BOF parser."""
from bofhound.ad.models.bloodhound_computer import BloodHoundComputer
from bofhound.parsers import LdapSearchBofParser
from bofhound.ad.adds import ADDS
from tests.test_data import (
    ldapsearchbof_standard_file_257,
    ldapsearchpy_standard_file_516,
    ldapsearchbof_standard_file_2052,
    ldapsearchbof_standard_file_marvel
)

def test_parse_file_ldapsearchpy_normal_file(ldapsearchpy_standard_file_516):
    """Test parsing of a normal LDAP search file (pyldapsearch)."""
    parser = LdapSearchBofParser()
    with open(ldapsearchpy_standard_file_516, 'r', encoding='utf-8') as f:
        for line in f:
            parser.process_line(line)
    parsed_objects = parser.get_results()
    assert len(parsed_objects) == 451


def test_parse_file_ldapsearchbof_normal_file(ldapsearchbof_standard_file_257):
    """Test parsing of a normal LDAP search file (ldapsearchbof)."""
    parser = LdapSearchBofParser()
    with open(ldapsearchbof_standard_file_257, 'r', encoding='utf-8') as f:
        for line in f:
            parser.process_line(line)
    parsed_objects = parser.get_results()
    assert len(parsed_objects) == 224

def test_parse_file_ldapsearchbof_large_file(ldapsearchbof_standard_file_2052):
    """Test parsing of a normal LDAP search file (ldapsearchbof)."""
    parser = LdapSearchBofParser()
    with open(ldapsearchbof_standard_file_2052, 'r', encoding='utf-8') as f:
        for line in f:
            parser.process_line(line)
    parsed_objects = parser.get_results()
    assert len(parsed_objects) == 2052

def test_parse_file_marvel(ldapsearchbof_standard_file_marvel):
    """Test parsing of a normal LDAP search file (ldapsearchbof)."""
    parser = LdapSearchBofParser()
    with open(ldapsearchbof_standard_file_marvel, 'r', encoding='utf-8') as f:
        for line in f:
            parser.process_line(line)
    parsed_objects = parser.get_results()
    assert len(parsed_objects) == 327


def test_parse_broken_line():
    """Test parsing of broken lines in LDAP search output."""
    data = """--------------------
userAccountControl: 660

12/05 02:31:52 UTC [output]
received output:
48
badPwdCount: 0
----------

12/05 02:31:52 UTC [output]
received output:
----------
userAccountControl: 66048
bad

12/05 02:31:52 UTC [output]
received output:
PwdCount: 0
codePage: 0"""
    parser = LdapSearchBofParser()
    for line in data.splitlines(keepends=True):
        parser.process_line(line)
    parsed_objects = parser.get_results()
    assert len(parsed_objects) == 2
    for obj in parsed_objects:
        assert int(obj.get('useraccountcontrol', 0)) == 66048
        assert int(obj.get('badpwdcount', 0)) == 0


def test_parse_data_computer():
    """Test parsing of a computer object in LDAP search output."""
    data = """dSCorePropagationData: 16010101000000.0Z
--------------------
objectClass: top, person, organizationalPerson, user, computer
cn: WIN10
distinguishedName: CN=WIN10,OU=Workstations,DC=windomain,DC=local
instanceType: 4
whenCreated: 20220112013543.0Z
whenChanged: 20220401134507.0Z
uSNCreated: 14202
uSNChanged: 24046
nTSecurityDescriptor: AQAEjJgJAAC0CQAAAAAAABQAAAAEAIQJMQAAAAUASAAgAAAAAwAAABAgIF+ledARkCAAwE/C1M+Gepa/5g3QEaKFAKoAMEniAQUAAAAAAAUVAAAANowB26uPcGmReUlF6AMAAAUASAAgAAAAAwAAAFB5lr/mDdARooUAqgAwSeKGepa/5g3QEaKFAKoAMEniAQUAAAAAAAUVAAAANowB26uPcGmReUlF6AMAAAUASAAgAAAAAwAAAFN5lr/mDdARooUAqgAwSeKGepa/5g3QEaKFAKoAMEniAQUAAAAAAAUVAAAANowB26uPcGmReUlF6AMAAAUASAAgAAAAAwAAANC/Cj5qEtARoGAAqgBsM+2Gepa/5g3QEaKFAKoAMEniAQUAAAAAAAUVAAAANowB26uPcGmReUlF6AMAAAUAOAAIAAAAAQAAAEeV43IYe9ERre8AwE/Y1c0BBQAAAAAABRUAAAA2jAHbq49waZF5SUXoAwAABQA4AAgAAAABAAAAiEem8wZT0RGpxQAA+ANnwQEFAAAAAAAFFQAAADaMAdurj3BpkXlJRegDAAAFADgAIAAAAAEAAAAAQhZMwCDQEadoAKoAbgUpAQUAAAAAAAUVAAAANowB26uPcGmReUlF6AMAAAUAOAAwAAAAAQAAAH96lr/mDdARooUAqgAwSeIBBQAAAAAABRUAAAA2jAHbq49waZF5SUUFAgAABQAsAAMAAAABAAAAqHqWv+YN0BGihQCqADBJ4gECAAAAAAAFIAAAACYCAAAFACwAEAAAAAEAAAAdsalGrmBaQLfo/4pY1FbSAQIAAAAAAAUgAA

04/01 19:35:34 UTC [output]
received output:
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
name: WIN10
objectGUID: f981e173-4db8-48f9-9c2d-3d4987698505
userAccountControl: 4096
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 132933148216284771
localPolicyFlags: 0
pwdLastSet: 132888464114765330
primaryGroupID: 515
objectSid: S-1-5-21-3674311734-1768984491-1162443153-1104
accountExpires: 9223372036854775807
logonCount: 222
sAMAccountName: WIN10$
sAMAccountType: 805306369
operatingSystem: Windows 10 Enterprise Evaluation
operatingSystemVersion: 10.0 (18363)
dNSHostName: win10.windomain.local
servicePrincipalName: WSMAN/win10, WSMAN/win10.windomain.local, TERMSRV/WIN10, TERMSRV/win10.windomain.local, RestrictedKrbHost/WIN10, HOST/WIN10, RestrictedKrbHost/win10.windomain.local, HOST/win10.windomain.local
objectCategory: CN=Computer,CN=Schema,CN=Configuration,DC=windomain,DC=local
isCriticalSystemObject: FALSE
dSCorePropagationData: 20220325174020.0Z, 16010101000001.0Z
lastLogonTimestamp: 132932943074365707
msDS-SupportedEncryptionTypes: 28
ms-Mcs-AdmPwd: testpassword
ms-Mcs-AdmPwdExpirationTime: 13295315246991474
--------------------
    """
    parser = LdapSearchBofParser()
    for line in data.splitlines(keepends=True):
        parser.process_line(line)
    parsed_objects = parser.get_results()

    assert len(parsed_objects) == 1
    assert 'operatingsystem' in parsed_objects[0].keys()
    print(parsed_objects[0])
    assert int(parsed_objects[0].get('useraccountcontrol', 0)) == 4096
    assert 'operatingsystem' in BloodHoundComputer(parsed_objects[0]).Properties


def test_parse_lower_data_computer():
    """Test parsing of a computer object in LDAP search output with mixed case attributes."""
    data = """dSCorePropagationData: 16010101000000.0Z
--------------------
objectclass: top, person, organizationalPerson, user, computer
cn: WIN10
distinguishedname: CN=WIN10,OU=Workstations,DC=windomain,DC=local
instancetype: 4
whencreated: 20220112013543.0Z
whenchanged: 20220401134507.0Z
usncreated: 14202
usnchanged: 24046
ntsecuritydescriptor: AQAEjJgJAAC0CQAAAAAAABQAAAAEAIQJMQAAAAUASAAgAAAAAwAAABAgIF+ledARkCAAwE/C1M+Gepa/5g3QEaKFAKoAMEniAQUAAAAAAAUVAAAANowB26uPcGmReUlF6AMAAAUASAAgAAAAAwAAAFB5lr/mDdARooUAqgAwSeKGepa/5g3QEaKFAKoAMEniAQUAAAAAAAUVAAAANowB26uPcGmReUlF6AMAAAUASAAgAAAAAwAAAFN5lr/mDdARooUAqgAwSeKGepa/5g3QEaKFAKoAMEniAQUAAAAAAAUVAAAANowB26uPcGmReUlF6AMAAAUASAAgAAAAAwAAANC/Cj5qEtARoGAAqgBsM+2Gepa/5g3QEaKFAKoAMEniAQUAAAAAAAUVAAAANowB26uPcGmReUlF6AMAAAUAOAAIAAAAAQAAAEeV43IYe9ERre8AwE/Y1c0BBQAAAAAABRUAAAA2jAHbq49waZF5SUXoAwAABQA4AAgAAAABAAAAiEem8wZT0RGpxQAA+ANnwQEFAAAAAAAFFQAAADaMAdurj3BpkXlJRegDAAAFADgAIAAAAAEAAAAAQhZMwCDQEadoAKoAbgUpAQUAAAAAAAUVAAAANowB26uPcGmReUlF6AMAAAUAOAAwAAAAAQAAAH96lr/mDdARooUAqgAwSeIBBQAAAAAABRUAAAA2jAHbq49waZF5SUUFAgAABQAsAAMAAAABAAAAqHqWv+YN0BGihQCqADBJ4gECAAAAAAAFIAAAACYCAAAFACwAEAAAAAEAAAAdsalGrmBaQLfo/4pY1FbSAQIAAAAAAAUgAA

04/01 19:35:34 UTC [output]
received output:
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
name: WIN10
objectguid: f981e173-4db8-48f9-9c2d-3d4987698505
useraccountcontrol: 4096
badpwdcount: 0
codepage: 0
countrycode: 0
badpasswordtime: 0
lastlogoff: 0
lastlogon: 132933148216284771
localpolicyflags: 0
pwdlastset: 132888464114765330
primarygroupid: 515
objectsid: S-1-5-21-3674311734-1768984491-1162443153-1104
accountexpires: 9223372036854775807
logoncount: 222
samaccountname: WIN10$
samaccounttype: 805306369
operatingsystem: Windows 10 Enterprise Evaluation
operatingsystemversion: 10.0 (18363)
dnshostname: win10.windomain.local
serviceprincipalname: WSMAN/win10, WSMAN/win10.windomain.local, TERMSRV/WIN10, TERMSRV/win10.windomain.local, RestrictedKrbHost/WIN10, HOST/WIN10, RestrictedKrbHost/win10.windomain.local, HOST/win10.windomain.local
objectcategory: CN=Computer,CN=Schema,CN=Configuration,DC=windomain,DC=local
iscriticalsystemobject: FALSE
dscorepropagationdata: 20220325174020.0Z, 16010101000001.0Z
lastlogontimestamp: 132932943074365707
msds-supportedencryptiontypes: 28
ms-mcs-admpwd: testpassword
ms-mcs-admpwdexpirationtime: 13295315246991474
--------------------
    """
    parser = LdapSearchBofParser()
    for line in data.splitlines(keepends=True):
        parser.process_line(line)
    parsed_objects = parser.get_results()
    adds = ADDS()
    adds.import_objects(parsed_objects)

    assert len(parsed_objects) == 1
    assert 'operatingsystem' in parsed_objects[0].keys()
    assert 'operatingsystem' in BloodHoundComputer(parsed_objects[0]).Properties
    assert len(adds.computers) == 1


def test_parse_data_computer_data_missing_dn():
    """
    Test parsing of a computer object in LDAP search output with missing
    distinguishedName attribute.
    """
    data = """dSCorePropagationData: 16010101000000.0Z
--------------------
objectClass: top, person, organizationalPerson, user, computer
cn: WIN10
instanceType: 4
whenCreated: 20220112013543.0Z
whenChanged: 20220401134507.0Z
uSNCreated: 14202
uSNChanged: 24046
nTSecurityDescriptor: AQAEjJgJAAC0CQAAAAAAABQAAAAEAIQJMQAAAAUASAAgAAAAAwAAABAgIF+ledARkCAAwE/C1M+Gepa/5g3QEaKFAKoAMEniAQUAAAAAAAUVAAAANowB26uPcGmReUlF6AMAAAUASAAgAAAAAwAAAFB5lr/mDdARooUAqgAwSeKGepa/5g3QEaKFAKoAMEniAQUAAAAAAAUVAAAANowB26uPcGmReUlF6AMAAAUASAAgAAAAAwAAAFN5lr/mDdARooUAqgAwSeKGepa/5g3QEaKFAKoAMEniAQUAAAAAAAUVAAAANowB26uPcGmReUlF6AMAAAUASAAgAAAAAwAAANC/Cj5qEtARoGAAqgBsM+2Gepa/5g3QEaKFAKoAMEniAQUAAAAAAAUVAAAANowB26uPcGmReUlF6AMAAAUAOAAIAAAAAQAAAEeV43IYe9ERre8AwE/Y1c0BBQAAAAAABRUAAAA2jAHbq49waZF5SUXoAwAABQA4AAgAAAABAAAAiEem8wZT0RGpxQAA+ANnwQEFAAAAAAAFFQAAADaMAdurj3BpkXlJRegDAAAFADgAIAAAAAEAAAAAQhZMwCDQEadoAKoAbgUpAQUAAAAAAAUVAAAANowB26uPcGmReUlF6AMAAAUAOAAwAAAAAQAAAH96lr/mDdARooUAqgAwSeIBBQAAAAAABRUAAAA2jAHbq49waZF5SUUFAgAABQAsAAMAAAABAAAAqHqWv+YN0BGihQCqADBJ4gECAAAAAAAFIAAAACYCAAAFACwAEAAAAAEAAAAdsalGrmBaQLfo/4pY1FbSAQIAAAAAAAUgAA

04/01 19:35:34 UTC [output]
received output:
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
name: WIN10
objectGUID: f981e173-4db8-48f9-9c2d-3d4987698505
userAccountControl: 4096
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 132933148216284771
localPolicyFlags: 0
pwdLastSet: 132888464114765330
primaryGroupID: 515
objectSid: S-1-5-21-3674311734-1768984491-1162443153-1104
accountExpires: 9223372036854775807
logonCount: 222
sAMAccountName: WIN10$
sAMAccountType: 805306369
operatingSystem: Windows 10 Enterprise Evaluation
operatingSystemVersion: 10.0 (18363)
dNSHostName: win10.windomain.local
servicePrincipalName: WSMAN/win10, WSMAN/win10.windomain.local, TERMSRV/WIN10, TERMSRV/win10.windomain.local, RestrictedKrbHost/WIN10, HOST/WIN10, RestrictedKrbHost/win10.windomain.local, HOST/win10.windomain.local
objectCategory: CN=Computer,CN=Schema,CN=Configuration,DC=windomain,DC=local
isCriticalSystemObject: FALSE
dSCorePropagationData: 20220325174020.0Z, 16010101000001.0Z
lastLogonTimestamp: 132932943074365707
msDS-SupportedEncryptionTypes: 28
ms-Mcs-AdmPwd: testpassword
ms-Mcs-AdmPwdExpirationTime: 13295315246991474
--------------------
    """
    parser = LdapSearchBofParser()
    for line in data.splitlines(keepends=True):
        parser.process_line(line)
    parsed_objects = parser.get_results()
    adds = ADDS()
    adds.import_objects(parsed_objects)

    assert len(parsed_objects) == 1
    # this test is failing - should distinguishedname be required?
    assert len(adds.computers) == 0


def test_parse_mininal_data_computer():
    """Test parsing of a minimal computer object in LDAP search output."""
    data = """dSCorePropagationData: 16010101000000.0Z
--------------------
distinguishedName: CN=WIN10,OU=Workstations,DC=windomain,DC=local
objectSid: S-1-5-21-3674311734-1768984491-1162443153-1104
sAMAccountType: 805306369
--------------------
    """
    parser = LdapSearchBofParser()
    for line in data.splitlines(keepends=True):
        parser.process_line(line)
    parsed_objects = parser.get_results()
    adds = ADDS()
    adds.import_objects(parsed_objects)

    assert len(parsed_objects) == 1
    assert len(adds.computers) == 1


def test_streaming_ldap_parser_direct():
    """Test StreamingLdapParser directly with controlled input"""

    # pylint: disable=line-too-long
    # Test data - simulate what would come from file
    data = [
        "--------------------",
        "objectClass: top, container",
        "cn: System",
        "description: Builtin system settings",
        "distinguishedName: CN=System,DC=ez,DC=lab",
        "instanceType: 4",
        "whenCreated: 20210826173041.0Z",
        "whenChanged: 20210826173041.0Z",
        "uSNCreated: 5662",
        "uSNChanged: 5662",
        "showInAdvancedViewOnly: TRUE",
        "nTSecurityDescriptor: AQAEjKgFAADEBQAAAAAAABQAAAAEAJQFHQAAAAAAFACUAAIAAQEAAAAAAAULAAAAAAAkAL0BDgABBQAAAAAABRUAAAB/ivvSK592RVonQNMAAgAAAAAUAP8BDwABAQAAAAAABRIAAAAFGjwAEAAAAAMAAAAAQhZMwCDQEadoAKoAbgUpFMwoSDcUvEWbB61vAV5fKAECAAAAAAAFIAAAACoCAAAFGjwAEAAAAAMAAAAAQhZMwCDQEadoAKoAbgUpunqWv+YN0BGihQCqADBJ4gECAAAAAAAFIAAAACoCAAAFGjwAEAAAAAMAAAAQICBfpXnQEZAgAMBPwtTPFMwoSDcUvEWbB61vAV5fKAECAAAAAAAFIAAAACoCAAAFGjwAEAAAAAMAAAAQICBfpXnQEZAgAMBPwtTPunqWv+YN0BGihQCqADBJ4gECAAAAAAAFIAAAACoCAAAFGjwAEAAAAAMAAABAwgq8qXnQEZAgAMBPwtTPFMwoSDcUvEWbB61vAV5fKAECAAAAAAAFIAAAACoCAAAFGjwAEAAAAAMAAABAwgq8qXnQEZAgAMBPwtTPunqWv+YN0BGihQCqADBJ4gECAAAAAAAFIAAAACoCAAAFGjwAEAAAAAMAAABCL7pZonnQEZAgAMBPwtPPFMwoSDcUvEWbB61vAV5fKAECAAAAAAAFIAAAACoCAAAFGjwAEAAAAAMAAABCL7pZonnQEZAgAMBPwtPPunqWv+YN0BGihQCqADBJ4gECAAAAAAAFIAAAACoCAAAFGjwAEAAAAAMAAAD4iHAD4QrSEbQiAKDJaPk5FMwoSDcUvEWbB61vAV5fKAECAAAAAAAFIAAAACoCAAAFGjwAEAAAAAMAAAD4iHAD4QrSEbQiAKDJaPk5unqWv+YN0BGihQCqADBJ4gECAAAAAAAFIAAAACoCAAAFEjgAMAAAAAEAAAAP1kdbkGCyQJ83Kk3ojzBjAQUAAAAAAAUVAAAAf4r70iufdkVaJ0DTDgIAAAUSOAAwAAAAAQAAAA/WR1uQYLJAnzcqTeiPMGMBBQAAAAAAB",
        "",
        "04/12 00:43:20 UTC [output]",
        "received output:",
        "RUAAAB/ivvSK592RVonQNMPAgAABRo4AAgAAAADAAAApm0CmzwNXEaL7lGZ1xZcuoZ6lr/mDdARooUAqgAwSeIBAQAAAAAAAwAAAAAFGjgACAAAAAMAAACmbQKbPA1cRovuUZnXFly6hnqWv+YN0BGihQCqADBJ4gEBAAAAAAAFCgAAAAUaOAAQAAAAAwAAAG2exrfHLNIRhU4AoMmD9giGepa/5g3QEaKFAKoAMEniAQEAAAAAAAUJAAAABRo4ABAAAAADAAAAbZ7Gt8cs0hGFTgCgyYP2CJx6lr/mDdARooUAqgAwSeIBAQAAAAAABQkAAAAFGjgAEAAAAAMAAABtnsa3xyzSEYVOAKDJg/YIunqWv+YN0BGihQCqADBJ4gEBAAAAAAAFCQAAAAUaOAAgAAAAAwAAAJN7G+pIXtVGvGxN9P2nijWGepa/5g3QEaKFAKoAMEniAQEAAAAAAAUKAAAABRosAJQAAgACAAAAFMwoSDcUvEWbB61vAV5fKAECAAAAAAAFIAAAACoCAAAFGiwAlAACAAIAAACcepa/5g3QEaKFAKoAMEniAQIAAAAAAAUgAAAAKgIAAAUaLACUAAIAAgAAALp6lr/mDdARooUAqgAwSeIBAgAAAAAABSAAAAAqAgAABRMoADAAAAABAAAA5cN4P5r3vUaguJ0YEW3ceQEBAAAAAAAFCgAAAAUSKAAwAQAAAQAAAN5H5pFv2XBLlVfWP/TzzNgBAQAAAAAABQoAAAAAEiQA/wEPAAEFAAAAAAAFFQAAAH+K+9Irn3ZFWidA0wcCAAAAEhgABAAAAAECAAAAAAAFIAAAACoCAAAAEhgAvQEPAAECAAAAAAAFIAAAACACAAABBQAAAAAABRUAAAB/ivvSK592RVonQNMAAgAAAQUAAAAAAAUVAAAAf4r70iufdkVaJ0DTAAIAAA==",
        "name: System",
        "objectGUID: 4c03aff1-3558-4e5e-9b31-abe40eb99cae",
        "systemFlags: -1946157056",
        "objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=ez,DC=lab",
        "isCriticalSystemObject: TRUE",
        "dSCorePropagationData: 20210921193126.0Z, 20210826175542.0Z, 16010101000416.0Z",
        "-------------",
        "",
        "04/12 00:43:20 UTC [output]",
        "received output:",
        "-------",
        "objectClass: top, lostAndFound",
        "cn: LostAndFound",
        "description: Default container for orphaned objects",
        "distinguishedName: CN=LostAndFound,DC=ez,DC=lab",
        "instanceType: 4",
        "whenCreated: 20210826173041.0Z",
        "whenChanged: 20210826173041.0Z",
        "uSNCreated: 5658",
        "uSNChanged: 5658",
        "showInAdvancedViewOnly: TRUE",
        "nTSecurityDescriptor: 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",
        "name: LostAndFound",
        "objectGUID: a76d96ca-1775-491d-9950-b64aa943bb24",
        "systemFlags: -1946157056",
        "objectCategory: CN=Lost-And-Found,CN=Schema,CN=Configuration,DC=ez,DC=lab",
        "isCriticalSystemObject: TRUE",
        "dSCorePropagationData: 20210921193126.0Z, 20210826175542.0Z, 16010101000416.0Z",
        "--------------------",
    ]
    # pylint: enable=line-too-long

    parser = LdapSearchBofParser()
    for line in data:
        parser.process_line(line)
    parsed_objects = parser.get_results()

    assert len(parsed_objects) == 2

def test_parse_midsearch_taskings():
    data = """dSCorePropagationData: 16010101000000.0Z
--------------------
distinguishedName: CN=WIN10,OU=Workstations,DC=windomain,DC=local
objectSid: S-1-5-21-3674311734-1768984491-1162443153-
09/21 15:01:34 UTC [input] <user> ldapsearch "(&(objectClass=group)(name=Domain Users))" *,ntsecuritydescriptor 1 192.168.1.1 "DC=DOMAIN,DC=local"
09/21 15:01:34 UTC [output]
Running ldapsearch (T1018, T1069.002, T1087.002, T1087.003, T1087.004, T1482)
09/21 15:01:34 UTC [task] <T1018, T1069.002, T1087.002, T1087.003, T1087.004, T1482> Running ldapsearch (T1018, T1069.002, T1087.002, T1087.003, T1087.004, T1482)
09/21 15:01:41 UTC [output]
received output:
1104
sAMAccountType: 805306369
nTSecurityDescriptor: B64ENCODEDBINARYDATAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
09/21 15:01:34 UTC [input] <user> ldapsearch "(&(objectClass=group)(name=Domain Users))" *,ntsecuritydescriptor 1 192.168.1.1 "DC=DOMAIN,DC=local"
09/21 15:01:34 UTC [output]
Running ldapsearch (T1018, T1069.002, T1087.002, T1087.003, T1087.004, T1482)
09/21 15:01:34 UTC [task] <T1018, T1069.002, T1087.002, T1087.003, T1087.004, T1482> Running ldapsearch (T1018, T1069.002, T1087.002, T1087.003, T1087.004, T1482)
09/21 15:01:41 UTC [output]
received output:
BACKHALFOFNTSECURITYDESCRIPTOR==
name: Domain Admins
--------------------
    """
    parser = LdapSearchBofParser()
    for line in data.splitlines(keepends=True):
        parser.process_line(line)
    parsed_objects = parser.get_results()

    assert len(parsed_objects) == 1
    assert parsed_objects[0]['distinguishedname'] == 'CN=WIN10,OU=Workstations,DC=windomain,DC=local'
    assert parsed_objects[0]['objectsid'] == 'S-1-5-21-3674311734-1768984491-1162443153-1104'
    assert parsed_objects[0]['ntsecuritydescriptor'] == 'B64ENCODEDBINARYDATAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABACKHALFOFNTSECURITYDESCRIPTOR=='
