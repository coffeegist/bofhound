import pytest
from bofhound.ad.models.bloodhound_crossref import BloodHoundCrossRef

@pytest.fixture
def parsed_crossref():
    yield {
        "cn": "REDANIA",
        "dcsorepropagationdata": "16010101000000.0Z",
        "distinguishedname": "CN=REDANIA,CN=Partitions,CN=Configuration,DC=redania,DC=local",
        "dnsroot": "redania.local",
        "instancetype": "4",
        "msds-behavior-version": "7",
        "ncname": "DC=redania,DC=local",
        "netbiosname": "REDANIA",
        "ntmixeddomain": "0",
        "name": "REDANIA",
        "objectcategory": "CN=Cross-Ref,CN=Schema,CN=Configuration,DC=redania,DC=local",
        "objectclass": "top, crossRef",
        "objectguid": "f66cd454-5cf0-41c2-83c4-743ce81fb33e",
        "showinadvancedviewonly": "True",
        "systemflags": "3",
        "usnchanged": "12565",
        "usncreated": "4118",
        "whenchanged": "20230214042300.0Z",
        "whencreated": "20230214042103.0Z",
    }


def test_crossref_constructor(parsed_crossref):
    cross_ref = BloodHoundCrossRef(parsed_crossref)
    
    assert cross_ref.netBiosName == "REDANIA"
    assert cross_ref.nCName == "DC=REDANIA,DC=LOCAL"
    assert cross_ref.distinguishedName == "CN=REDANIA,CN=PARTITIONS,CN=CONFIGURATION,DC=REDANIA,DC=LOCAL"