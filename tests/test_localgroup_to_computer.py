from tests.test_data import *

EARTH_DC_SID = "S-1-5-21-3719975868-1113416855-2416171545-1000"
ASGARD_WKSTN_SID = "S-1-5-21-3719975868-1113416855-2416171545-1154"


def test_earth_dc_group_counts(marvel_adds):
    earth_dc_local_groups = marvel_adds.SID_MAP[EARTH_DC_SID].local_group_members

    assert len(earth_dc_local_groups) == 2
    assert "remote desktop users" not in earth_dc_local_groups.keys()
    assert "remote management users" not in earth_dc_local_groups.keys()
    assert len(earth_dc_local_groups["distributed com users"]) == 1
    assert len(earth_dc_local_groups["administrators"]) == 3


def test_asgard_wrkstn_group_counts(marvel_adds):
    asgard_wrkstn_local_groups = marvel_adds.SID_MAP[ASGARD_WKSTN_SID].local_group_members
    
    assert len(asgard_wrkstn_local_groups) == 2
    assert "distributed com users" not in asgard_wrkstn_local_groups.keys()
    assert "remote management users" not in asgard_wrkstn_local_groups.keys()
    assert len(asgard_wrkstn_local_groups["remote desktop users"]) == 4
    assert len(asgard_wrkstn_local_groups["administrators"]) == 5
