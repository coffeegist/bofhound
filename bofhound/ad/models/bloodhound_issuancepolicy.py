import hashlib
import base64
from asn1crypto import x509
from bloodhound.ad.utils import ADUtils

from .bloodhound_object import BloodHoundObject
from bofhound.logger import logger, OBJ_EXTRA_FMT, ColorScheme


class BloodHoundIssuancePolicy(BloodHoundObject):

    GUI_PROPERTIES = [
        'domain', 'name', 'distinguishedname', 'domainsid', 'isaclprotected',
        'description', 'whencreated', 'displayname', 'certtemplateoid'
    ]

    COMMON_PROPERTIES = [
    ]

    def __init__(self, object):
        super().__init__(object)

        self._entry_type = "IssuancePolicy"
        self.IsDeleted = False
        self.ContainedBy = {}
        self.IsACLProtected = False
        self.GroupLink = None # {}

        if 'objectguid' in object.keys():
            self.ObjectIdentifier = object.get("objectguid")

        if 'distinguishedname' in object.keys():
            domain = ADUtils.ldap2domain(object.get('distinguishedname')).upper()
            self.Properties['domain'] = domain
            self.Properties['distinguishedname'] = object.get('distinguishedname').upper()

            # name relies on domain existing, so it can be appended to the end
            if 'displayname' in object.keys():
                self.Properties['name'] = f"{object.get('displayname').upper()}@{domain}"
        
        if 'displayname' in object.keys():
            self.Properties['displayname'] = object.get('displayname')

        if 'description' in object.keys():
            self.Properties['description'] = object.get('description')
        else:
            self.Properties['description'] = None

        if 'mspki-cert-template-oid' in object.keys():
            self.Properties['mspki-cert-template-oid'] = object.get('mspki-cert-template-oid')

        if 'ntsecuritydescriptor' in object.keys():
            self.RawAces = object['ntsecuritydescriptor']
        

    def to_json(self, properties_level):
        self.Properties['isaclprotected'] = self.IsACLProtected
        data = super().to_json(properties_level)

        data["Aces"] = self.Aces
        data["ObjectIdentifier"] = self.ObjectIdentifier
        data["IsDeleted"] = self.IsDeleted
        data["IsACLProtected"] = self.IsACLProtected
        data["ContainedBy"] = self.ContainedBy
        
        return data