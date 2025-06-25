from bloodhound.ad.utils import ADUtils

from .bloodhound_object import BloodHoundObject
from bofhound.logger import logger, OBJ_EXTRA_FMT, ColorScheme
from bofhound.ad.helpers.cert_utils import PkiCertificateAuthorityFlags


class BloodHoundEnterpriseCA(BloodHoundObject):

    GUI_PROPERTIES = [
        'domain', 'name', 'distinguishedname', 'domainsid', 'isaclprotected',
        'description', 'whencreated', 'flags', 'caname', 'dnshostname', 'certthumbprint',
        'certname', 'certchain', 'hasbasicconstraints', 'basicconstraintpathlength',
        'casecuritycollected', 'enrollmentagentrestrictionscollected', 'isuserspecifiessanenabledcollected',
        'unresolvedpublishedtemplates'
    ]

    COMMON_PROPERTIES = [
    ]

    def __init__(self, object):
        super().__init__(object)

        self._entry_type = "EnterpriseCA"
        self.IsDeleted = False
        self.ContainedBy = {}
        self.IsACLProtected = False
        self.Properties['casecuritycollected'] = False
        self.Properties['enrollmentagentrestrictionscollected'] = False
        self.Properties['isuserspecifiessanenabledcollected'] = False
        self.Properties['unresolvedpublishedtemplates'] = []
        self.CARegistryData = None
        self.x509Certificate = None

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
            if 'domain' in self.Properties.keys():
                self.Properties['name'] = object.get('name').upper() + "@" + self.Properties['domain'].upper()

        if 'dnshostname' in object.keys():
            self.Properties['dnshostname'] = object.get('dnshostname')

        if 'cacertificate' in object.keys():
            self.parse_cacertificate(object)

        if 'ntsecuritydescriptor' in object.keys():
            self.RawAces = object['ntsecuritydescriptor']

        self.HostingComputer = None
        self.EnabledCertTemplates = []

        if 'certificatetemplates' in object.keys():
            self.CertTemplates = object.get('certificatetemplates').split(', ')
    

    def to_json(self, properties_level):
        self.Properties['isaclprotected'] = self.IsACLProtected
        data = super().to_json(properties_level)

        data["HostingComputer"] = self.HostingComputer
        data["CARegistryData"] = self.CARegistryData
        data["EnabledCertTemplates"] = self.EnabledCertTemplates
        data["Aces"] = self.Aces
        data["ObjectIdentifier"] = self.ObjectIdentifier
        data["IsDeleted"] = self.IsDeleted
        data["IsACLProtected"] = self.IsACLProtected
        data["ContainedBy"] = self.ContainedBy
        
        return data