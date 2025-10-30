"""Fixtures for test data files and parsed objects"""
import os
import pytest
from bofhound.parsers import LdapSearchBofParser, ParsingPipelineFactory
from bofhound.ad import ADDS
from bofhound.local import LocalBroker
from bofhound.parsers.data_sources import FileDataSource

TEST_DATA_DIR = os.path.abspath(
        os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..",
            "test_data"
        )
)


@pytest.fixture
def ldapsearchpy_standard_file_516():
    """LdapSearchPY Fixtures"""
    yield os.path.join(TEST_DATA_DIR, "ldapsearchpy_logs/ldapsearch_516-objects.log")


# LdapSearchBOF Fixtures
@pytest.fixture
def ldapsearchbof_standard_file_257():
    """LdapSearchBOF Fixtures"""
    yield os.path.join(TEST_DATA_DIR, "ldapsearchbof_logs/beacon_257-objects.log")


@pytest.fixture
def ldapsearchbof_standard_file_2052():
    """LdapSearchBOF Fixtures"""
    yield os.path.join(TEST_DATA_DIR, "ldapsearchbof_logs/beacon_2052.log")


@pytest.fixture
def ldapsearchbof_standard_file_marvel():
    """LdapSearchBOF Fixtures"""
    yield os.path.join(
        TEST_DATA_DIR,
        "ldapsearchbof_logs/beacon_marvel_ldap_sessions_localgroup.log"
    )

@pytest.fixture
def ldapsearchbof_minimal_ou_gplink_results():
    """LdapSearchBOF minimal OU and GPO link log file fixture"""
    log_file = os.path.join(
        TEST_DATA_DIR,
        "ldapsearchbof_logs/minimal-ou-gplink.log"
    )
    parser = ParsingPipelineFactory.create_pipeline()
    results = parser.process_data_source(FileDataSource(log_file))
    yield results

@pytest.fixture
def testdata_ldapsearchbof_beacon_257_objects():
    """Parsed objects from LdapSearchBOF beacon_257-objects.log"""
    log_file = os.path.join(TEST_DATA_DIR, "ldapsearchbof_logs/beacon_257-objects.log")
    parser = LdapSearchBofParser()
    for line in open(log_file, 'r', encoding='utf-8'):
        parser.process_line(line.rstrip('\n\r'))
    return parser.get_results()


@pytest.fixture
def testdata_ldapsearchbof_beacon_2052_objects():
    """Parsed objects from LdapSearchBOF beacon_2052.log"""
    log_file = os.path.join(TEST_DATA_DIR, "ldapsearchbof_logs/beacon_2052.log")
    parser = LdapSearchBofParser()
    for line in open(log_file, 'r', encoding='utf-8'):
        parser.process_line(line.rstrip('\n\r'))
    yield parser.get_results()


@pytest.fixture
def testdata_pyldapsearch_redania_objects():
    """Parsed objects from LdapSearchBOF pyldapsearch_redania_objects.log"""
    log_file = os.path.join(TEST_DATA_DIR, "ldapsearchbof_logs/pyldapsearch_redania_objects.log")
    parser = LdapSearchBofParser()
    for line in open(log_file, 'r', encoding='utf-8'):
        parser.process_line(line.rstrip('\n\r'))
    yield parser.get_results()


@pytest.fixture
def testdata_marvel_ldap_objects():
    """Parsed objects from LdapSearchBOF beacon_marvel_ldap_sessions_localgroup.log"""
    log_file = os.path.join(
        TEST_DATA_DIR,
        "ldapsearchbof_logs/beacon_marvel_ldap_sessions_localgroup.log"
    )
    parser = LdapSearchBofParser()
    for line in open(log_file, 'r', encoding='utf-8'):
        parser.process_line(line.rstrip('\n\r'))
    yield parser.get_results()


@pytest.fixture
def testdata_marvel_local_objects():
    """Parsed local objects from LdapSearchBOF beacon_marvel_ldap_sessions_localgroup.log"""
    log_file = os.path.join(
        TEST_DATA_DIR,
        "ldapsearchbof_logs/beacon_marvel_ldap_sessions_localgroup.log"
    )
    pipeline = ParsingPipelineFactory.create_pipeline()
    yield pipeline.process_data_source(FileDataSource(log_file))


@pytest.fixture
def brc4ldapsentinel_standard_file_1030():
    """BRc4 LDAP Sentinel Fixtures"""
    yield os.path.join(TEST_DATA_DIR, "brc4_ldap_sentinel_logs/badger_no_acl_1030_objects.log")


# Generic Parser Fixtures


@pytest.fixture
def netloggedon_redania_file():
    """NetLoggedOn BOF Fixtures"""
    yield os.path.join(TEST_DATA_DIR, "netloggedonbof_logs/netloggedonbof_redania.log")


@pytest.fixture
def netloggedon_redania_objects():
    """Parsed objects from NetLoggedOn BOF netloggedonbof_redania.log"""
    log_file = os.path.join(TEST_DATA_DIR, "netloggedonbof_logs/netloggedonbof_redania.log")
    pipeline = ParsingPipelineFactory.create_pipeline()
    yield pipeline.process_data_source(FileDataSource(log_file))


@pytest.fixture
def netsession_redania_netapi_file():
    """NetSession BOF Fixtures"""
    yield os.path.join(TEST_DATA_DIR, "netsessionbof_logs/netsessionbof_redania_netapi.log")


@pytest.fixture
def netsession_redania_netapi_objects():
    """Parsed objects from NetSession BOF netsessionbof_redania_netapi.log"""
    log_file = os.path.join(TEST_DATA_DIR, "netsessionbof_logs/netsessionbof_redania_netapi.log")
    pipeline = ParsingPipelineFactory.create_pipeline()
    yield pipeline.process_data_source(FileDataSource(log_file))


@pytest.fixture
def netsession_redania_dns_file():
    """NetSession BOF Fixtures"""
    yield os.path.join(TEST_DATA_DIR, "netsessionbof_logs/netsessionbof_redania_dns.log")


@pytest.fixture
def netsession_redania_dns_objects():
    """Parsed objects from NetSession BOF netsessionbof_redania_dns.log"""
    log_file = os.path.join(TEST_DATA_DIR, "netsessionbof_logs/netsessionbof_redania_dns.log")
    pipeline = ParsingPipelineFactory.create_pipeline()
    yield pipeline.process_data_source(FileDataSource(log_file))


@pytest.fixture
def netlocalgroup_redania_file():
    """NetLocalGroup BOF Fixtures"""
    yield os.path.join(TEST_DATA_DIR, "netlocalgroupbof_logs/netlocalgroupbof_redania.log")


@pytest.fixture
def netlocalgroup_redania_objects():
    """Parsed objects from NetLocalGroup BOF netlocalgroupbof_redania.log"""
    log_file = os.path.join(TEST_DATA_DIR, "netlocalgroupbof_logs/netlocalgroupbof_redania.log")
    pipeline = ParsingPipelineFactory.create_pipeline()
    yield pipeline.process_data_source(FileDataSource(log_file))


@pytest.fixture
def regsession_redania_file():
    """RegSession BOF Fixtures"""
    yield os.path.join(TEST_DATA_DIR, "regsessionbof_logs/regsessionbof_redania.log")


@pytest.fixture
def regsession_redania_objects():
    """Parsed objects from RegSession BOF regsessionbof_redania.log"""
    log_file = os.path.join(TEST_DATA_DIR, "regsessionbof_logs/regsessionbof_redania.log")
    pipeline = ParsingPipelineFactory.create_pipeline()
    yield pipeline.process_data_source(FileDataSource(log_file))


@pytest.fixture
def marvel_adds(testdata_marvel_ldap_objects, testdata_marvel_local_objects): # pylint: disable=redefined-outer-name
    """
    Fixture for processing marvel LDAP and local objects into a complete ADDS
    object
    """
    ad = ADDS()
    broker = LocalBroker()

    ad.import_objects(testdata_marvel_ldap_objects)
    broker.import_objects(testdata_marvel_local_objects, ad.DOMAIN_MAP.values())

    ad.process()
    ad.process_local_objects(broker)

    yield ad

@pytest.fixture
def havoc_standard_file():
    """Havoc LDAP Fixtures"""
    yield os.path.join(TEST_DATA_DIR, "havoc_logs/Console_73169420.log")

@pytest.fixture
def outflankc2_standard_file():
    """Outflank LDAP Fixtures"""
    yield os.path.join(TEST_DATA_DIR, "outflankc2_logs/ldapsearchbof/beacon_2052.json")
