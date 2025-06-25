from bloodhound.ad.utils import ADUtils
from .bloodhound_object import BloodHoundObject
from bofhound.logger import logger, OBJ_EXTRA_FMT, ColorScheme


class BloodHoundContainer(BloodHoundObject):

    GUI_PROPERTIES = [
        'domain', 'name', 'distinguishedname', 'domainsid', 'highvalue', 'isaclprotected'
    ]

    COMMON_PROPERTIES = [
    ]

    def __init__(self, object):
        super().__init__(object)

        self._entry_type = "Container"
        self.ContainedBy = {}
        self.Properties["blocksinheritance"] = False

        if 'objectguid' in object.keys():
            self.ObjectIdentifier = object.get('objectguid').upper()
        
        if 'distinguishedname' in object.keys() and 'ou' in object.keys():
            self.Properties["domain"] = ADUtils.ldap2domain(object.get('distinguishedname').upper())
            self.Properties["name"] = f"{object.get('name').upper()}@{self.Properties['domain']}"
            logger.debug(f"Reading Container object {ColorScheme.ou}{self.Properties['name']}[/]", extra=OBJ_EXTRA_FMT)
        
        self.Properties['highvalue'] = False

        if 'ntsecuritydescriptor' in object.keys():
            self.RawAces = object['ntsecuritydescriptor']

        self.Properties["highvalue"] = False

        self.Aces = []
        self.ChildObjects = []
        self.IsDeleted = False
        self.IsACLProtected = False


    def to_json(self, properties_level):
        self.Properties['isaclprotected'] = self.IsACLProtected
        ou = super().to_json(properties_level)

        ou["ObjectIdentifier"] = self.ObjectIdentifier
        ou["ContainedBy"] = self.ContainedBy
        ou["Aces"] = self.Aces
        ou["ChildObjects"] = self.ChildObjects
        ou["IsDeleted"] = self.IsDeleted
        ou["IsACLProtected"] = self.IsACLProtected

        return ou
