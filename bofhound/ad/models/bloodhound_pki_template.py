from distutils.ccompiler import gen_preprocess_options
from bloodhound.ad.utils import ADUtils
from .bloodhound_object import BloodHoundObject
from bofhound.logger import OBJ_EXTRA_FMT, ColorScheme
import logging
import ast
import base64
from bofhound.ad.utils import OID_TO_STR_MAP, MS_PKI_CERTIFICATE_NAME_FLAG, MS_PKI_PRIVATE_KEY_FLAG, MS_PKI_ENROLLMENT_FLAG, filetime_to_span, span_to_str

class BloodHoundPKITemplate(BloodHoundObject):
    COMMON_PROPERTIES = [
        'domain', 'name', 'highvalue', 'Template Name', 'Display Name', 'Certificate Authorities',
        'Enabled', 'DNS Name', 'type', 'Validity Period', 'Renewal Period', 'Minimum RSA Key Length',
        'Extended Key Usage', 'Any Purpose', 'Client Authentication', 'Enrollment Agent', 'Certificate Name Flag',
        'Enrollee Supplies Subject', 'Private Key Flag', 'Requires Key Archival',
        'Authorize Signatures Required', 'Enrollment Flags', 'Requires Manager Approval',
        'No Security Extension'
    ]

    def __init__(self, object):

        super().__init__(object)

        self._entry_type = "PKI Template"
        self.GPLinks = []
        self.Properties["blocksinheritance"] = False
        self.cas_ids = []

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
                self.Properties["name"] = ("%s@%s" % (object.get("cn"), domain)).upper()
        
        self.Properties["highvalue"] = False

        if 'cn' in object.keys():
            self.Properties["Template Name"] = object.get("cn")
        
        if 'displayname' in object.keys():
            self.Properties["Display Name"] = object.get("displayname")

        self.Properties["Certificate Authorities"] = []
        self.Properties["Enabled"] = True

        if 'pkiextendedkeyusage' in object.keys():
            ekus = object.get('pkiextendedkeyusage').split(', ')
            ekus = list(
                map(lambda x: OID_TO_STR_MAP[x] if x in OID_TO_STR_MAP else x, ekus)
            )
            any_purpose = (
                "Any Purpose" in ekus or len(ekus) == 0
            )
            client_authentication = any_purpose or any(
                eku in ekus
                for eku in [
                    "Client Authentication",
                    "Smart Card Logon",
                    "PKINIT Client Authentication",
                ]
            )
            enrollment_agent = any_purpose or any(
                eku in ekus
                for eku in [
                    "Certificate Request Agent",
                ]
            )

            self.Properties["Client Authentication"] = client_authentication
            self.Properties["Enrollment Agent"] = enrollment_agent            
            self.Properties["Any Purpose"] = any_purpose
            self.Properties["Extended Key Usage"] = ekus


        if 'mspki-certificate-name-flag' in object.keys():
            certificate_name_flag = object.get('mspki-certificate-name-flag')
            if certificate_name_flag is not None:
                certificate_name_flag = MS_PKI_CERTIFICATE_NAME_FLAG(
                    int(certificate_name_flag)
                )
            else:
                certificate_name_flag = MS_PKI_CERTIFICATE_NAME_FLAG(0)
            self.Properties["Certificate Name Flag"] = certificate_name_flag.to_str_list()

            enrollee_supplies_subject = any(
                flag in certificate_name_flag
                for flag in [
                    MS_PKI_CERTIFICATE_NAME_FLAG.ENROLLEE_SUPPLIES_SUBJECT,
                ]
            )
            self.Properties["Enrollee Supplies Subject"] = enrollee_supplies_subject

        if 'mspki-private-key-flag' in object.keys():
            private_key_flag = object.get("mspki-private-key-flag")
            if private_key_flag is not None:
                private_key_flag = MS_PKI_PRIVATE_KEY_FLAG(int(private_key_flag))
            else:
                private_key_flag = MS_PKI_PRIVATE_KEY_FLAG(0)
            self.Properties["Private Key Flag"] = private_key_flag.to_str_list()

            requires_key_archival = (
                MS_PKI_PRIVATE_KEY_FLAG.REQUIRE_PRIVATE_KEY_ARCHIVAL in private_key_flag
            )
            self.Properties["Requires Key Archival"] = requires_key_archival
        
        if 'mspki-ra-signature' in object.keys():
            authorized_signatures_required = object.get("mspki-ra-signature")
            if authorized_signatures_required is not None:
                authorized_signatures_required = int(authorized_signatures_required)
            else:
                authorized_signatures_required = 0
            self.Properties["Authorize Signatures Required"] = authorized_signatures_required

        if 'mspki-enrollment-flag' in object.keys():
            enrollment_flag = object.get("mspki-enrollment-flag")
            if enrollment_flag is not None:
                enrollment_flag = MS_PKI_ENROLLMENT_FLAG(int(enrollment_flag))
            else:
                enrollment_flag = MS_PKI_ENROLLMENT_FLAG(0)
            self.Properties["Enrollment Flags"] = enrollment_flag.to_str_list()

            requires_manager_approval = (
                MS_PKI_ENROLLMENT_FLAG.PEND_ALL_REQUESTS in enrollment_flag
            )
            self.Properties["Requires Manager Approval"] = requires_manager_approval

            no_security_extension = (
                MS_PKI_ENROLLMENT_FLAG.NO_SECURITY_EXTENSION in enrollment_flag
            )
            self.Properties["No Security Extension"] = no_security_extension

        if 'pkiexpirationperiod' in object.keys():
            pKIExpirationPeriod_b64 = object.get("pkiexpirationperiod")
            pKIExpirationPeriod_byte_array = base64.b64decode(pKIExpirationPeriod_b64)
            self.Properties["Validity Period"] = span_to_str(filetime_to_span(pKIExpirationPeriod_byte_array))

        if 'pkioverlapperiod' in object.keys():
            pKIRenewalPeriod_b64 = object.get("pkioverlapperiod")
            pKIRenewalPeriod_byte_array = base64.b64decode(pKIRenewalPeriod_b64)
            self.Properties["Renewal Period"] = span_to_str(filetime_to_span(pKIRenewalPeriod_byte_array))

        if 'mspki-minimal-key-size' in object.keys():
            self.Properties["Minimum RSA Key Length"] = int(object.get('mspki-minimal-key-size'))            

        self.Properties["type"] = "Certificate Template"

        if 'ntsecuritydescriptor' in object.keys():
            self.RawAces = object['ntsecuritydescriptor']

    def to_json(self, only_common_properties=True):
        data = super().to_json(only_common_properties)
        data["ObjectIdentifier"] = self.ObjectIdentifier
        data["Aces"] = self.Aces
        data["cas_ids"] = self.cas_ids
        return data