import hashlib
import base64
from asn1crypto import x509
from bloodhound.ad.utils import ADUtils

from .bloodhound_object import BloodHoundObject
from bofhound.logger import logger, OBJ_EXTRA_FMT, ColorScheme


class BloodHoundNTAuthStore(BloodHoundObject):

    GUI_PROPERTIES = [
        'domain', 'name', 'distinguishedname', 'domainsid', 'isaclprotected',
        'description', 'whencreated', 'certthumbprints'
    ]

    COMMON_PROPERTIES = [
    ]

    def __init__(self, object):
        super().__init__(object)

        self._entry_type = "NTAuthStore"
        self.IsDeleted = False
        self.ContainedBy = {}
        self.IsACLProtected = False

        self.Properties['certthumbprints'] = []

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

        if 'cacertificate' in object.keys():
            certificate_b64 = object.get("cacertificate")
            
            certificate_b64_list = certificate_b64.split(", ")
            for cert in certificate_b64_list:
                certificate_byte_array = base64.b64decode(cert)
                thumbprint = hashlib.sha1(certificate_byte_array).hexdigest().upper()
                self.Properties['certthumbprints'].append(thumbprint)
            
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
        
        if "domainsid" in self.Properties:
            data["DomainSID"] = self.Properties["domainsid"]

        return data