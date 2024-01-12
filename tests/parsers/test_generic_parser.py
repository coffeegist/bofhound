import pytest
from bofhound.parsers import GenericParser
from bofhound.parsers.shared_parsers import NetLoggedOnBofParser, NetSessionBofParser, NetLocalGroupBofParser, RegSessionBofParser
from tests.test_data import *


def test_parse_file_netloggedon_redania(netloggedon_redania_file):
    parsed_objects = GenericParser.parse_file(netloggedon_redania_file)
    assert len(parsed_objects) == 12


def test_parse_file_netsession_redania_netapi(netsession_redania_netapi_file):
    parsed_objects = GenericParser.parse_file(netsession_redania_netapi_file)
    assert len(parsed_objects) == 2


def test_parse_file_netsession_redania_dns(netsession_redania_dns_file):
    parsed_objects = GenericParser.parse_file(netsession_redania_dns_file)
    assert len(parsed_objects) == 2


def test_parse_file_netlocalgroup_redania(netlocalgroup_redania_file):
    parsed_objects = GenericParser.parse_file(netlocalgroup_redania_file)
    assert len(parsed_objects) == 5
    

def test_parse_file_regsession_redania(regsession_redania_file):
    parsed_objects = GenericParser.parse_file(regsession_redania_file)
    assert len(parsed_objects) == 4


def test_parsed_object_types(netloggedon_redania_file, netsession_redania_netapi_file, netsession_redania_dns_file, netlocalgroup_redania_file, regsession_redania_file):
    parsed_privsessions_objects = GenericParser.parse_file(netloggedon_redania_file)
    parsed_session_netapi_objects = GenericParser.parse_file(netsession_redania_netapi_file)
    parsed_session_dns_objects = GenericParser.parse_file(netsession_redania_dns_file)
    parsed_localgroup_objects = GenericParser.parse_file(netlocalgroup_redania_file)
    parsed_regsession_objects = GenericParser.parse_file(regsession_redania_file)

    assert parsed_privsessions_objects[0]["ObjectType"] == NetLoggedOnBofParser.OBJECT_TYPE
    assert parsed_session_netapi_objects[0]["ObjectType"] == NetSessionBofParser.OBJECT_TYPE
    assert parsed_session_dns_objects[1]["ObjectType"] == NetSessionBofParser.OBJECT_TYPE
    assert parsed_localgroup_objects[1]["ObjectType"] == NetLocalGroupBofParser.OBJECT_TYPE
    assert parsed_regsession_objects[0]["ObjectType"] == RegSessionBofParser.OBJECT_TYPE