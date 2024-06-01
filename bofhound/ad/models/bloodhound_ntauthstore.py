from bloodhound.ad.utils import ADUtils
from .bloodhound_object import BloodHoundObject
from bofhound.logger import OBJ_EXTRA_FMT, ColorScheme
import logging
from asn1crypto import x509
import hashlib
import base64


class BloodHoundNTAuthStore(BloodHoundObject):

    COMMON_PROPERTIES = [
        'domain', 'name', 'distinguishedname', 'domainsid', 'isaclprotected',
        'description', 'whencreated', 'certthumbprints'
    ]

    def __init__(self, object):
        super().__init__(object)

        self._entry_type = "NTAuthStore"
        self.IsDeleted = False
        self.ContainedBy = []
        self.IsACLProtected = False

        if 'objectguid' in object.keys():
            self.ObjectIdentifier = object.get("objectguid")

        if 'distinguishedname' in object.keys():
            domain = ADUtils.ldap2domain(object.get('distinguishedname')).upper()
            self.Properties['domain'] = domain
            self.Properties['distinguishedname'] = object.get('distinguishedname').upper()

            # name relies on domain existing, so it can be appended to the end
            if 'name' in object.keys():
                self.Properties['name'] = f"{object.get('name').upper()}@{domain}"

        if 'description' in object.keys():
            self.Properties['description'] = object.get('description')
        else:
            self.Properties['description'] = None

        # how are multiple certs stored in the property/can we handle?
        if 'cacertificate' in object.keys():
            certificate_b64 = object.get("cacertificate")
            certificate_byte_array = base64.b64decode(certificate_b64)
            
            self.Properties['certthumbprints'] = [hashlib.sha1(certificate_byte_array).hexdigest().upper()]

        if 'ntsecuritydescriptor' in object.keys():
            self.RawAces = object['ntsecuritydescriptor']
        

    def to_json(self, only_common_properties=True):
        self.Properties['isaclprotected'] = self.IsACLProtected
        data = super().to_json(only_common_properties)

        data["Aces"] = self.Aces
        data["DomainSID"] = self.Properties["domainsid"]
        data["ObjectIdentifier"] = self.ObjectIdentifier
        data["IsDeleted"] = self.IsDeleted
        data["IsACLProtected"] = self.IsACLProtected
        data["ContainedBy"] = self.ContainedBy
        
        return data