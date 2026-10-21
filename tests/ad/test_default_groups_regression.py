import pytest
from bofhound.ad import ADDS
from bofhound.ad.models import BloodHoundComputer, BloodHoundDomain

DOMAIN_SID = 'S-1-5-21-100-200-300'


@pytest.mark.parametrize('missing', [None, 'objectsid', 'primarygroupid'])
def test_default_groups_preserve_dc_membership_with_incomplete_computer(missing):
    adds = ADDS()
    adds.domains = [BloodHoundDomain({
        'distinguishedname': 'DC=example,DC=test', 'objectsid': DOMAIN_SID,
    })]
    dc = BloodHoundComputer({'objectsid': DOMAIN_SID + '-1000', 'primarygroupid': '516'})
    workstation = BloodHoundComputer({'objectsid': DOMAIN_SID + '-1001', 'primarygroupid': '515'})
    incomplete = {'objectsid': DOMAIN_SID + '-1002', 'primarygroupid': '515'}
    if missing is None:
        incomplete = {}
    else:
        incomplete.pop(missing)
    adds.computers = [dc, workstation, BloodHoundComputer(incomplete)]

    adds.write_default_groups()

    groups = {group.ObjectIdentifier: group for group in adds.groups}
    assert len(groups) == 4
    assert groups['EXAMPLE.TEST-S-1-5-9'].Members == [
        {'ObjectIdentifier': DOMAIN_SID + '-1000', 'ObjectType': 'Computer'}
    ]
