from bloodhound.ad.utils import ADUtils
from .bloodhound_object import BloodHoundObject
from bofhound.logger import OBJ_EXTRA_FMT, ColorScheme
import logging
from asn1crypto import x509
import base64
from bofhound.ad.helpers.cert_utils import PkiCertificateAuthorityFlags


class BloodHoundEnterpriseCA(BloodHoundObject):

    COMMON_PROPERTIES = [
        'domain', 'name', 'distinguishedname', 'domainsid', 'isaclprotected',
        'description', 'whencreated', 'flags', 'caname', 'dnshostname', 'certthumbprint',
        'certname', 'certchain', 'hasbasicconstraints', 'basicconstraintpathlength',
        'casecuritycollected', 'enrollmentagentrestrictionscollected', 'isuserspecifiessanenabledcollected'
    ]

    def __init__(self, object):
        super().__init__(object)

        self._entry_type = "EnterpriseCA"
        self.IsDeleted = False
        self.GPLinks = []
        self.ContainedBy = []
        self.IsACLProtected = False
        self.Properties['casecuritycollected'] = False
        self.Properties['enrollmentagentrestrictionscollected'] = False
        self.Properties['isuserspecifiessanenabledcollected'] = False
        self.CARegistryData = {}
        self.Properties["blocksinheritance"] = False

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

        if 'flags' in object.keys():
            int_flag = int(object.get("flags"))
            self.Properties['flags'] = ', '.join([member.name for member in PkiCertificateAuthorityFlags if member.value & int_flag == member.value])

        if 'name' in object.keys():
            self.Properties['caname'] = object.get('name')

        if 'dnshostname' in object.keys():
            self.Properties['dnshostname'] = object.get('dnshostname')

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

        if 'ntsecuritydescriptor' in object.keys():
            self.RawAces = object['ntsecuritydescriptor']

        self.HostingComputer = (self.Properties['dnshostname'].split('.')[0]).upper()
        self.EnabledCertTemplates = []

        if 'certificatetemplates' in object.keys():
            self.CertTemplates = object.get('certificatetemplates').split(', ')
        
        

    def to_json(self, only_common_properties=True):
        self.Properties['isaclprotected'] = self.IsACLProtected
        data = super().to_json(only_common_properties)

        data["HostingComputer"] = self.HostingComputer
        data["CARegistryData"] = self.CARegistryData
        data["EnabledCertTemplates"] = self.EnabledCertTemplates
        data["Aces"] = self.Aces
        data["ObjectIdentifier"] = self.ObjectIdentifier
        data["IsDeleted"] = self.IsDeleted
        data["IsACLProtected"] = self.IsACLProtected
        data["ContainedBy"] = self.ContainedBy
        
        return data