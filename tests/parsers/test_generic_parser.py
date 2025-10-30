"""Tests for the specific BOF parsers."""
import os
from bofhound.parsers import (
    NetLocalGroupBofParser, NetLoggedOnBofParser, NetSessionBofParser, RegSessionBofParser
)
from bofhound.parsers.types import ObjectType
from tests.test_data import (
    netloggedon_redania_file,
    netsession_redania_netapi_file,
    netsession_redania_dns_file,
    netlocalgroup_redania_file,
    regsession_redania_file,
    ldapsearchbof_standard_file_marvel
)


def test_parse_file_netloggedon_redania(netloggedon_redania_file):
    """Test parsing of netloggedon BOF output from Redania."""
    parser = NetLoggedOnBofParser()
    with open(netloggedon_redania_file, 'r', encoding='utf-8') as f:
        for line in f:
            parser.process_line(line)
    parsed_objects = parser.get_results()
    assert len(parsed_objects) == 12
    assert parser.produces_object_type == ObjectType.PRIVILEGED_SESSION

def test_parse_file_netsession_redania_netapi(netsession_redania_netapi_file):
    """Test parsing of netsession BOF output from Redania (NetAPI)."""
    parser = NetSessionBofParser()
    with open(netsession_redania_netapi_file, 'r', encoding='utf-8') as f:
        for line in f:
            parser.process_line(line)
    parsed_objects = parser.get_results()
    assert len(parsed_objects) == 2
    assert parser.produces_object_type == ObjectType.SESSION

def test_parse_file_netsession_redania_dns(netsession_redania_dns_file):
    """Test parsing of netsession BOF output from Redania (DNS)."""
    parser = NetSessionBofParser()

    with open(netsession_redania_dns_file, 'r', encoding='utf-8') as f:
        for line in f:
            parser.process_line(line)
    parsed_objects = parser.get_results()
    assert len(parsed_objects) == 2
    assert parser.produces_object_type == ObjectType.SESSION

def test_parse_file_netsession_marvel(ldapsearchbof_standard_file_marvel):
    """Test parsing of netsession BOF output from Marvel."""
    parser = NetSessionBofParser()

    with open(ldapsearchbof_standard_file_marvel, 'r', encoding='utf-8') as f:
        for line in f:
            parser.process_line(line)
    parsed_objects = parser.get_results()

    assert len(parsed_objects) == 10

def test_parse_file_netlocalgroup_redania(netlocalgroup_redania_file):
    """Test parsing of netlocalgroup BOF output from Redania."""
    parser = NetLocalGroupBofParser()
    with open(netlocalgroup_redania_file, 'r', encoding='utf-8') as f:
        for line in f:
            parser.process_line(line)
    parsed_objects = parser.get_results()
    assert len(parsed_objects) == 5
    assert parser.produces_object_type == ObjectType.LOCAL_GROUP

def test_parse_file_regsession_redania(regsession_redania_file):
    """Test parsing of regsession BOF output from Redania."""
    parser = RegSessionBofParser()
    with open(regsession_redania_file, 'r', encoding='utf-8') as f:
        for line in f:
            parser.process_line(line)
    parsed_objects = parser.get_results()
    assert len(parsed_objects) == 4
    assert parser.produces_object_type == ObjectType.REGISTRY_SESSION
