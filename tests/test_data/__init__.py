import os 
import pytest 
from bofhound.parsers import LdapSearchBofParser
from bofhound.parsers.generic_parser import GenericParser
from bofhound.ad import ADDS
from bofhound.local import LocalBroker

TEST_DATA_DIR = os.path.abspath(
        os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 
            "..",
            "test_data"
        )
)

# LdapSearchPY Fixtures
@pytest.fixture
def ldapsearchpy_standard_file_516():
    yield os.path.join(TEST_DATA_DIR, "ldapsearchpy_logs/ldapsearch_516-objects.log")


# LdapSearchBOF Fixtures
@pytest.fixture
def ldapsearchbof_standard_file_257():
    yield os.path.join(TEST_DATA_DIR, "ldapsearchbof_logs/beacon_257-objects.log")


@pytest.fixture
def ldapsearchbof_standard_file_202():
    yield os.path.join(TEST_DATA_DIR, "ldapsearchbof_logs/beacon_202.log")


@pytest.fixture
def testdata_ldapsearchbof_beacon_257_objects():
    log_file = os.path.join(TEST_DATA_DIR, "ldapsearchbof_logs/beacon_257-objects.log")
    yield LdapSearchBofParser.parse_file(log_file)


@pytest.fixture
def testdata_ldapsearchbof_beacon_202_objects():
    log_file = os.path.join(TEST_DATA_DIR, "ldapsearchbof_logs/beacon_202.log")
    yield LdapSearchBofParser.parse_file(log_file)


@pytest.fixture
def testdata_pyldapsearch_redania_objects():
    log_file = os.path.join(TEST_DATA_DIR, "ldapsearchbof_logs/pyldapsearch_redania_objects.log")
    yield LdapSearchBofParser.parse_file(log_file)


@pytest.fixture
def testdata_marvel_ldap_objects():
    log_file = os.path.join(TEST_DATA_DIR, "ldapsearchbof_logs/beacon_marvel_ldap_sessions_localgroup.log")
    yield LdapSearchBofParser.parse_file(log_file)


@pytest.fixture
def testdata_marvel_local_objects():
    log_file = os.path.join(TEST_DATA_DIR, "ldapsearchbof_logs/beacon_marvel_ldap_sessions_localgroup.log")
    yield GenericParser.parse_file(log_file)


# BRc4 LDAP Sentinel Fixtures
@pytest.fixture
def brc4ldapsentinel_standard_file_1030():
    yield os.path.join(TEST_DATA_DIR, "brc4_ldap_sentinel_logs/badger_no_acl_1030_objects.log")


#### Generic Parser Fixtures

# NetLoggedOn BOF Fixtures
@pytest.fixture
def netloggedon_redania_file():
    yield os.path.join(TEST_DATA_DIR, "netloggedonbof_logs/netloggedonbof_redania.log")


@pytest.fixture
def netloggedon_redania_objects():
    log_file = os.path.join(TEST_DATA_DIR, "netloggedonbof_logs/netloggedonbof_redania.log")
    yield GenericParser.parse_file(log_file)

# NetSession BOF Fixtures
@pytest.fixture
def netsession_redania_netapi_file():
    yield os.path.join(TEST_DATA_DIR, "netsessionbof_logs/netsessionbof_redania_netapi.log")


@pytest.fixture
def netsession_redania_netapi_objects():
    log_file = os.path.join(TEST_DATA_DIR, "netsessionbof_logs/netsessionbof_redania_netapi.log")
    yield GenericParser.parse_file(log_file)


@pytest.fixture
def netsession_redania_dns_file():
    yield os.path.join(TEST_DATA_DIR, "netsessionbof_logs/netsessionbof_redania_dns.log")


@pytest.fixture
def netsession_redania_dns_objects():
    log_file = os.path.join(TEST_DATA_DIR, "netsessionbof_logs/netsessionbof_redania_dns.log")
    yield GenericParser.parse_file(log_file)

# NetLocalGroup BOF Fixtures
@pytest.fixture
def netlocalgroup_redania_file():
    yield os.path.join(TEST_DATA_DIR, "netlocalgroupbof_logs/netlocalgroupbof_redania.log")


@pytest.fixture
def netlocalgroup_redania_objects():
    log_file = os.path.join(TEST_DATA_DIR, "netlocalgroupbof_logs/netlocalgroupbof_redania.log")
    yield GenericParser.parse_file(log_file)


# RegSession BOF Fixtures
@pytest.fixture
def regsession_redania_file():
    yield os.path.join(TEST_DATA_DIR, "regsessionbof_logs/regsessionbof_redania.log")


@pytest.fixture
def regsession_redania_objects():
    log_file = os.path.join(TEST_DATA_DIR, "regsessionbof_logs/regsessionbof_redania.log")
    yield GenericParser.parse_file(log_file)


# fixture for processing marvel LDAP and local objects into a complete ADDS object
@pytest.fixture
def marvel_adds(testdata_marvel_ldap_objects, testdata_marvel_local_objects):
    ad = ADDS()
    broker = LocalBroker()

    ad.import_objects(testdata_marvel_ldap_objects)
    broker.import_objects(testdata_marvel_local_objects, ad.DOMAIN_MAP.values())

    ad.process()
    ad.process_local_objects(broker)

    yield ad