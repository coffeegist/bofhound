from bloodhound.ad.utils import ADUtils

from .bloodhound_object import BloodHoundObject
from bofhound.logger import logger, OBJ_EXTRA_FMT, ColorScheme


class BloodHoundGPO(BloodHoundObject):

    GUI_PROPERTIES = [
        'distinguishedname', 'whencreated',
        'domain', 'domainsid', 'name', 'highvalue',
        'description', 'gpcpath', 'isaclprotected'
    ]

    COMMON_PROPERTIES = [
    ]

    def __init__(self, object):
        super().__init__(object)

        self._entry_type = "GPO"
        self.ContainedBy = {}
        
        if 'distinguishedname' in object.keys() and 'displayname' in object.keys():
            self.Properties["domain"] = ADUtils.ldap2domain(object.get('distinguishedname').upper())
            self.Properties["name"] = f"{object.get('displayname').upper()}@{self.Properties['domain']}"
            logger.debug(f"Reading GPO object {ColorScheme.gpo}{self.Properties['name']}[/]", extra=OBJ_EXTRA_FMT)

        if 'objectguid' in object.keys():
            self.ObjectIdentifier = object.get('objectguid').upper()

        if 'ntsecuritydescriptor' in object.keys():
            self.RawAces = object['ntsecuritydescriptor']

        if 'description' in object.keys():
            self.Properties["description"] = object.get('description')

        if 'gpcfilesyspath' in object.keys():
            self.Properties["gpcpath"] = object.get('gpcfilesyspath')

        self.Properties["highvalue"] = False

        self.Aces = []

        self.IsDeleted = False
        self.IsACLProtected = False

    def to_json(self, properties_level):
        self.Properties['isaclprotected'] = self.IsACLProtected
        gpo = super().to_json(properties_level)

        gpo["ObjectIdentifier"] = self.ObjectIdentifier
        gpo["ContainedBy"] = self.ContainedBy
        # The below is all unsupported as of now.
        gpo["Aces"] = self.Aces
        gpo["IsDeleted"] = self.IsDeleted
        gpo["IsACLProtected"] = self.IsACLProtected

        return gpo
