from distutils.ccompiler import gen_preprocess_options
from bloodhound.ad.utils import ADUtils
from .bloodhound_object import BloodHoundObject
from bofhound.logger import OBJ_EXTRA_FMT, ColorScheme
import logging
from asn1crypto import x509
import ast
import base64
from bofhound.ad.utils import PkiCertificateAuthorityFlags

class BloodHoundPKI(BloodHoundObject):

    COMMON_PROPERTIES = [
        'name', 'highvalue', 'CA Name', 'DNS Name', 'Certificate Subject', 'Certificate Serial Number',
        'Certificate Validity Start', 'Certificate Validity End', 'domain', 'flags'
    ]

    def __init__(self, object):
        super().__init__(object)

        self._entry_type = "PKI"
        self.GPLinks = []
        self.Properties["blocksinheritance"] = False

        if 'objectguid' in object.keys():
            self.ObjectIdentifier = object.get("objectguid")

        if 'distinguishedname' in object.keys():
            DN = object.get("distinguishedname")
            domain = ""
            split = DN.split("DC=")
            for i in range (1, len(split)):
                domain = domain + split[i].replace(',', '')
                if i < (len(split)-1):
                    domain = domain + "."
            self.Properties["domain"] = domain.upper()
            if 'name' in object.keys():
                self.Properties["name"] = ("%s@%s" % (object.get("name"), domain)).upper()
        
        self.Properties["highvalue"] = False

        if 'certificatetemplates' in object.keys():
            self.Properties["Certificate Templates"] = object.get("certificatetemplates").split(', ')

        if 'cn' in object.keys():
            self.Properties["CA Name"] = object.get("cn")

        if 'dNSHostnName' in object.keys():
            self.Properties["DNS Name"] = object.get("dNSHostnName")

        if 'ntsecuritydescriptor' in object.keys():
            self.RawAces = object['ntsecuritydescriptor']

        if 'cacertificatedn' in object.keys():
                self.Properties["Certificate Subject"] = object.get("cacertificatedn")

        if 'cacertificate' in object.keys():
            certificate_b64 = object.get("cacertificate")
            certificate_byte_array = base64.b64decode(certificate_b64)
            ca_cert = x509.Certificate.load(certificate_byte_array)[
                    "tbs_certificate"
                ]
            self.Properties["Certificate Serial Number"] = hex(int(ca_cert["serial_number"]))[2:].upper()
            validity = ca_cert["validity"].native
            self.Properties["Certificate Validity Start"] = str(validity["not_before"])
            self.Properties["Certificate Validity End"] = str(validity["not_after"])

        if 'ntsecuritydescriptor' in object.keys():
            self.RawAces = object['ntsecuritydescriptor']
        
        if 'flags' in object.keys():
            int_flag = int(object.get("flags"))
            self.Properties['flags'] = [member.name for member in PkiCertificateAuthorityFlags if member.value & int_flag == member.value]

    def to_json(self, only_common_properties=True):
        data = super().to_json(only_common_properties)
        data["ObjectIdentifier"] = self.ObjectIdentifier
        data["Aces"] = self.Aces
        return data