from bloodhound.ad.utils import ADUtils
from .bloodhound_object import BloodHoundObject

from bofhound.logger import logger, OBJ_EXTRA_FMT, ColorScheme


class BloodHoundDomain(BloodHoundObject):

    GUI_PROPERTIES = [
        'distinguishedname', 'domainsid', 'description', 'whencreated',
        'functionallevel', 'domain', 'isaclprotected', 'collected',
        'name'
    ]

    COMMON_PROPERTIES = [
    ]

    def __init__(self, object):
        super().__init__(object)

        self._entry_type = "Domain"
        self.GPLinks = []
        self.ContainedBy = {}
        level_id = object.get('msds-behavior-version', 0)
        try:
            functional_level = ADUtils.FUNCTIONAL_LEVELS[int(level_id)]
        except KeyError:
            functional_level = 'Unknown'

        dc = None

        self.Properties['collected'] = True

        if 'distinguishedname' in object.keys():
            self.Properties["name"] = ADUtils.ldap2domain(object.get('distinguishedname').upper())
            self.Properties["domain"] = self.Properties["name"]
            dc = BloodHoundObject.get_domain_component(object.get('distinguishedname').upper())
            logger.debug(f"Reading Domain object {ColorScheme.domain}{self.Properties['name']}[/]", extra=OBJ_EXTRA_FMT)

        if 'objectsid' in object.keys():
            self.Properties["domainsid"] = object.get('objectsid')

        if 'distinguishedname' in object.keys():
            self.Properties['distinguishedname'] = object.get('distinguishedname').upper()

        if 'description' in object.keys():
            self.Properties["description"] = object.get('description')
        else:
            self.Properties["description"] = None

        if 'ntsecuritydescriptor' in object.keys():
            self.RawAces = object['ntsecuritydescriptor']
        
        if 'gplink' in object.keys():
            # this is gross - not sure why gplink is coming in without a colon
            # (even from logs in test folder) but will hunt down later if it's a problem
            links = object.get('gplink').replace('LDAP//', 'LDAP://')
            
            # [['DN1', 'GPLinkOptions1'], ['DN2', 'GPLinkOptions2'], ...]
            self.GPLinks = [link.upper()[:-1].split(';') for link in links.split('[LDAP://')][1:]

        self.Properties["highvalue"] = True

        self.Properties["functionallevel"] = functional_level

        self.Trusts = []
        self.Aces = []
        self.Links = []
        self.ChildObjects = []
        self.GPOChanges = {
            "AffectedComputers": [],
            "DcomUsers": [],
            "LocalAdmins": [],
            "PSRemoteUsers": [],
            "RemoteDesktopUsers": []
        }
        self.IsDeleted = False
        self.IsACLProtected = False


    def to_json(self, properties_level):
        self.Properties['isaclprotected'] = self.IsACLProtected
        domain = super().to_json(properties_level)

        domain["ObjectIdentifier"] = self.ObjectIdentifier
        domain["Trusts"] = self.Trusts
        domain["ContainedBy"] = None
        # The below is all unsupported as of now.
        domain["Aces"] = self.Aces
        domain["Links"] = self.Links
        domain["ChildObjects"] = self.ChildObjects
        
        self.GPOChanges["AffectedComputers"] = self.AffectedComputers
        self.GPOChanges["AffectedUsers"] = self.AffectedUsers
        domain["GPOChanges"] = self.GPOChanges

        domain["IsDeleted"] = self.IsDeleted
        domain["IsACLProtected"] = self.IsACLProtected

        return domain
