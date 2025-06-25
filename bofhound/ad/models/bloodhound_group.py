from bloodhound.ad.utils import ADUtils

from .bloodhound_object import BloodHoundObject
from bofhound.logger import logger, OBJ_EXTRA_FMT, ColorScheme


class BloodHoundGroup(BloodHoundObject):

    GUI_PROPERTIES = [
        'distinguishedname', 'samaccountname', 'objectsid',
        'admincount', 'description', 'whencreated',
        'name', 'domain', 'domainsid'
    ]

    COMMON_PROPERTIES = [
        'member', 'memberof'
    ]

    def __init__(self, object):
        super().__init__(object)

        self._entry_type = "Group"
        self.Members = []
        self.Aces = []
        self.ContainedBy = {}
        self.IsDeleted = False
        self.IsACLProtected = False
        self.MemberDNs = []
        self.MemberOfDNs = []
        self.IsACLProtected = False

        if 'distinguishedname' in object.keys() and 'samaccountname' in object.keys():
            domain = ADUtils.ldap2domain(object.get('distinguishedname')).upper()
            name = f'{object.get("samaccountname")}@{domain}'.upper()
            self.Properties["name"] = name
            self.Properties["domain"] = domain
            logger.debug(f"Reading Group object {ColorScheme.group}{name}[/]", extra=OBJ_EXTRA_FMT)

        if 'objectsid' in object.keys():
            #objectid = BloodHoundObject.get_sid(object.get('objectsid', None), object.get('distinguishedname', None))
            objectid = object.get('objectsid')
            self.ObjectIdentifier = objectid
            self.Properties["domainsid"] = objectid.rsplit('-',1)[0]


        if 'distinguishedname' in object.keys():
            self.Properties["distinguishedname"] = object.get('distinguishedname', None).upper()

        if 'admincount' in object.keys():
            self.Properties["admincount"] = int(object.get('admincount')) == 1 # do not move this lower, it may break imports for users
        else:
            self.Properties["admincount"] = False

        if 'description' in object.keys():
            self.Properties["description"] = object.get('description')

        if 'member' in object.keys():
            self.MemberDNs = [f'CN={dn.upper()}' for dn in object.get('member').split(', CN=')]
            if len(self.MemberDNs) > 0:
                self.MemberDNs[0] = self.MemberDNs[0][3:]

        if 'ntsecuritydescriptor' in object.keys():
            self.RawAces = object['ntsecuritydescriptor']

        if 'memberof' in object.keys():
                self.MemberOfDNs = [f'CN={dn.upper()}' for dn in object.get('memberof').split(', CN=')]
                if len(self.MemberOfDNs) > 0:
                    self.MemberOfDNs[0] = self.MemberOfDNs[0][3:]


    def add_group_member(self, object, object_type):
        member = {
            "ObjectIdentifier": object.ObjectIdentifier,
            "ObjectType": object_type
        }
        self.Members.append(member)


    def to_json(self, properties_level):
        group = super().to_json(properties_level)
        group["ObjectIdentifier"] = self.ObjectIdentifier
        group["ContainedBy"] = self.ContainedBy
        group["Aces"] = self.Aces
        group["Members"] = self.Members
        group["IsDeleted"] = self.IsDeleted
        group["IsACLProtected"] = self.IsACLProtected

        return group
