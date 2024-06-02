from bloodhound.ad.utils import ADUtils
from .bloodhound_object import BloodHoundObject
from bofhound.logger import OBJ_EXTRA_FMT, ColorScheme
import logging
from asn1crypto import x509
import base64


class BloodHoundAIACA(BloodHoundObject):

    COMMON_PROPERTIES = [
        'domain', 'name', 'distinguishedname', 'domainsid', 'isaclprotected',
        'description', 'whencreated', 'crosscertificatepair', 'hascrosscertificatepair',
        'certthumbprint', 'certname', 'certchain', 'hasbasicconstraints',
        'basicconstraintpathlength'
    ]

    def __init__(self, object):
        super().__init__(object)

        self._entry_type = "AIACA"
        self.GPLinks = []
        self.ContainedBy = []
        self.IsACLProtected = False
        self.IsDeleted = False
        self.Properties["blocksinheritance"] = False
        self.cas_ids = []

        if 'objectguid' in object.keys():
            self.ObjectIdentifier = object.get("objectguid")

        if 'distinguishedname' in object.keys():
            domain = ADUtils.ldap2domain(object.get('distinguishedname')).upper()
            self.Properties['domain'] = domain
            self.Properties['distinguishedname'] = object.get('distinguishedname').upper()

        if 'description' in object.keys():
            self.Properties['description'] = object.get('description')
        else:
            self.Properties['description'] = None

        ### Not parsed atm
        self.Properties['crosscertificatepair'] = []
        self.Properties['hascrosscertificatepair'] = False

        if 'cacertificate' in object.keys():
            certificate_b64 = object.get("cacertificate")
            certificate_byte_array = base64.b64decode(certificate_b64)
            ca_cert = x509.Certificate.load(certificate_byte_array)[
                    "tbs_certificate"
                ]

            # May need a rework
            self.Properties['certthumbprint'] = None
            self.Properties['certname'] = self.Properties['certthumbprint']
            self.Properties['certchain'] = [self.Properties['certthumbprint']]
            self.Properties['hasbasicconstraints'] = False
            self.Properties['basicconstraintpathlength'] = 0


        
    def to_json(self, only_common_properties=True):
        self.Properties['isaclprotected'] = self.IsACLProtected
        data = super().to_json(only_common_properties)

        data["Aces"] = self.Aces
        data["IsACLProtected"] = self.IsACLProtected
        data["ObjectIdentifier"] = self.ObjectIdentifier
        data["ContainedBy"] = self.ContainedBy

        return data
