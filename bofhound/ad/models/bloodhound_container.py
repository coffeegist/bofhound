from distutils.ccompiler import gen_preprocess_options
from bloodhound.ad.utils import ADUtils
from .bloodhound_object import BloodHoundObject
from bofhound.logger import OBJ_EXTRA_FMT, ColorScheme
import logging

class BloodHoundContainer(BloodHoundObject):

    COMMON_PROPERTIES = [
        'domain', 'name', 'distinguishedname', 'domainsid', 'highvalue', 'isaclprotected'
    ]

    def __init__(self, object):
        super().__init__(object)

        self._entry_type = "OU"
        self.GPLinks = []
        self.ContainedBy = []
        self.Properties["blocksinheritance"] = False

        if 'objectguid' in object.keys():
            self.ObjectIdentifier = object.get('objectguid').upper()
        
        if 'distinguishedname' in object.keys() and 'ou' in object.keys():
            self.Properties["domain"] = ADUtils.ldap2domain(object.get('distinguishedname').upper())
            self.Properties["name"] = f"{object.get('name').upper()}@{self.Properties['domain']}"
            logging.debug(f"Reading Container object {ColorScheme.ou}{self.Properties['name']}[/]", extra=OBJ_EXTRA_FMT)
        
        self.Properties['highvalue'] = False

        if 'ntsecuritydescriptor' in object.keys():
            self.RawAces = object['ntsecuritydescriptor']

        self.Properties["highvalue"] = False

        self.Aces = []
        self.ChildObjects = []
        self.IsDeleted = False
        self.IsACLProtected = False


    def to_json(self, only_common_properties=True):
        self.Properties['isaclprotected'] = self.IsACLProtected
        ou = super().to_json(only_common_properties)

        ou["ObjectIdentifier"] = self.ObjectIdentifier
        ou["ContainedBy"] = self.ContainedBy
        # The below is all unsupported as of now.
        ou["Aces"] = self.Aces
        ou["ChildObjects"] = self.ChildObjects
        ou["IsDeleted"] = self.IsDeleted
        ou["IsACLProtected"] = self.IsACLProtected

        return ou
