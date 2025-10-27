from tests.test_data import *

THOR_SID = "S-1-5-21-3719975868-1113416855-2416171545-1104"
EARTH_DC_SID = "S-1-5-21-3719975868-1113416855-2416171545-1000"
ASGARD_WKSTN_SID = "S-1-5-21-3719975868-1113416855-2416171545-1154"


def test_marvel_privileged_sessions(marvel_adds):
    earth_dc_priv_sessions = marvel_adds.SID_MAP[EARTH_DC_SID].privileged_sessions

    assert len(earth_dc_priv_sessions) == 1
    assert earth_dc_priv_sessions[0]["UserSID"] == THOR_SID


def test_marvel_sessions(marvel_adds):
    asgard_wrkstn_sessions = marvel_adds.SID_MAP[ASGARD_WKSTN_SID].sessions
    earth_dc_sessions = marvel_adds.SID_MAP[EARTH_DC_SID].sessions

    assert len(earth_dc_sessions) == 0
    assert len(asgard_wrkstn_sessions) == 1
    assert asgard_wrkstn_sessions[0]["UserSID"] == THOR_SID


def test_marvel_registry_sessions(marvel_adds):
    earth_dc_reg_sessions = marvel_adds.SID_MAP[EARTH_DC_SID].registry_sessions
    asgard_wrkstn_reg_sessions = marvel_adds.SID_MAP[ASGARD_WKSTN_SID].registry_sessions

    assert len(earth_dc_reg_sessions) == 1
    assert len(asgard_wrkstn_reg_sessions) == 1
    assert earth_dc_reg_sessions[0]["UserSID"] == THOR_SID
    assert asgard_wrkstn_reg_sessions[0]["UserSID"] == THOR_SID
