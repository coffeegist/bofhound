## From Certipy https://github.com/ly4k/Certipy/blob/main/certipy/lib/constants.py
##              https://github.com/ly4k/Certipy/blob/main/certipy/lib/structs.py
##              https://github.com/ly4k/Certipy/blob/main/certipy/lib/formatting.py

import enum
import struct

def filetime_to_span(filetime: str) -> int:
    (span,) = struct.unpack("<q", filetime)

    span *= -0.0000001

    return int(span)

def span_to_str(span: int) -> str:
    if (span % 31536000 == 0) and (span // 31536000) >= 1:
        if (span / 31536000) == 1:
            return "1 year"
        return "%i years" % (span // 31536000)
    elif (span % 2592000 == 0) and (span // 2592000) >= 1:
        if (span // 2592000) == 1:
            return "1 month"
        else:
            return "%i months" % (span // 2592000)
    elif (span % 604800 == 0) and (span // 604800) >= 1:
        if (span / 604800) == 1:
            return "1 week"
        else:
            return "%i weeks" % (span // 604800)

    elif (span % 86400 == 0) and (span // 86400) >= 1:
        if (span // 86400) == 1:
            return "1 day"
        else:
            return "%i days" % (span // 86400)
    elif (span % 3600 == 0) and (span / 3600) >= 1:
        if (span // 3600) == 1:
            return "1 hour"
        else:
            return "%i hours" % (span // 3600)
    else:
        return ""

def to_pascal_case(snake_str: str) -> str:
    components = snake_str.split("_")
    return "".join(x.title() for x in components)

def _high_bit(value):
    """returns index of highest bit, or -1 if value is zero or negative"""
    return value.bit_length() - 1

def _decompose(flag, value):
    """Extract all members from the value."""
    # _decompose is only called if the value is not named
    not_covered = value
    negative = value < 0
    members = []
    for member in flag:
        member_value = member.value
        if member_value and member_value & value == member_value:
            members.append(member)
            not_covered &= ~member_value
    if not negative:
        tmp = not_covered
        while tmp:
            flag_value = 2 ** _high_bit(tmp)
            if flag_value in flag._value2member_map_:
                members.append(flag._value2member_map_[flag_value])
                not_covered &= ~flag_value
            tmp &= ~flag_value
    if not members and value in flag._value2member_map_:
        members.append(flag._value2member_map_[value])
    members.sort(key=lambda m: m._value_, reverse=True)
    if len(members) > 1 and members[0].value == value:
        # we have the breakdown, don't need the value member itself
        members.pop(0)
    return members, not_covered

class PkiCertificateAuthorityFlags(enum.Enum):
    NO_TEMPLATE_SUPPORT = 1
    SUPPORTS_NT_AUTHENTICATION = 2
    CA_SUPPORTS_MANUAL_AUTHENTICATION = 4
    CA_SERVERTYPE_ADVANCED = 8

OID_TO_STR_MAP = {
    "1.3.6.1.4.1.311.76.6.1": "Windows Update",
    "1.3.6.1.4.1.311.10.3.11": "Key Recovery",
    "1.3.6.1.4.1.311.10.3.25": "Windows Third Party Application Component",
    "1.3.6.1.4.1.311.21.6": "Key Recovery Agent",
    "1.3.6.1.4.1.311.10.3.6": "Windows System Component Verification",
    "1.3.6.1.4.1.311.61.4.1": "Early Launch Antimalware Drive",
    "1.3.6.1.4.1.311.10.3.23": "Windows TCB Component",
    "1.3.6.1.4.1.311.61.1.1": "Kernel Mode Code Signing",
    "1.3.6.1.4.1.311.10.3.26": "Windows Software Extension Verification",
    "2.23.133.8.3": "Attestation Identity Key Certificate",
    "1.3.6.1.4.1.311.76.3.1": "Windows Store",
    "1.3.6.1.4.1.311.10.6.1": "Key Pack Licenses",
    "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
    "1.3.6.1.5.2.3.5": "KDC Authentication",
    "1.3.6.1.5.5.7.3.7": "IP security use",
    "1.3.6.1.4.1.311.10.3.8": "Embedded Windows System Component Verification",
    "1.3.6.1.4.1.311.10.3.20": "Windows Kits Component",
    "1.3.6.1.5.5.7.3.6": "IP security tunnel termination",
    "1.3.6.1.4.1.311.10.3.5": "Windows Hardware Driver Verification",
    "1.3.6.1.5.5.8.2.2": "IP security IKE intermediate",
    "1.3.6.1.4.1.311.10.3.39": "Windows Hardware Driver Extended Verification",
    "1.3.6.1.4.1.311.10.6.2": "License Server Verification",
    "1.3.6.1.4.1.311.10.3.5.1": "Windows Hardware Driver Attested Verification",
    "1.3.6.1.4.1.311.76.5.1": "Dynamic Code Generato",
    "1.3.6.1.5.5.7.3.8": "Time Stamping",
    "1.3.6.1.4.1.311.10.3.4.1": "File Recovery",
    "1.3.6.1.4.1.311.2.6.1": "SpcRelaxedPEMarkerCheck",
    "2.23.133.8.1": "Endorsement Key Certificate",
    "1.3.6.1.4.1.311.2.6.2": "SpcEncryptedDigestRetryCount",
    "1.3.6.1.4.1.311.10.3.4": "Encrypting File System",
    "1.3.6.1.5.5.7.3.1": "Server Authentication",
    "1.3.6.1.4.1.311.61.5.1": "HAL Extension",
    "1.3.6.1.5.5.7.3.4": "Secure Email",
    "1.3.6.1.5.5.7.3.5": "IP security end system",
    "1.3.6.1.4.1.311.10.3.9": "Root List Signe",
    "1.3.6.1.4.1.311.10.3.30": "Disallowed List",
    "1.3.6.1.4.1.311.10.3.19": "Revoked List Signe",
    "1.3.6.1.4.1.311.10.3.21": "Windows RT Verification",
    "1.3.6.1.4.1.311.10.3.10": "Qualified Subordination",
    "1.3.6.1.4.1.311.10.3.12": "Document Signing",
    "1.3.6.1.4.1.311.10.3.24": "Protected Process Verification",
    "1.3.6.1.4.1.311.80.1": "Document Encryption",
    "1.3.6.1.4.1.311.10.3.22": "Protected Process Light Verification",
    "1.3.6.1.4.1.311.21.19": "Directory Service Email Replication",
    "1.3.6.1.4.1.311.21.5": "Private Key Archival",
    "1.3.6.1.4.1.311.10.5.1": "Digital Rights",
    "1.3.6.1.4.1.311.10.3.27": "Preview Build Signing",
    "1.3.6.1.4.1.311.20.2.1": "Certificate Request Agent",
    "2.23.133.8.2": "Platform Certificate",
    "1.3.6.1.4.1.311.20.1": "CTL Usage",
    "1.3.6.1.5.5.7.3.9": "OCSP Signing",
    "1.3.6.1.5.5.7.3.3": "Code Signing",
    "1.3.6.1.4.1.311.10.3.1": "Microsoft Trust List Signing",
    "1.3.6.1.4.1.311.10.3.2": "Microsoft Time Stamping",
    "1.3.6.1.4.1.311.76.8.1": "Microsoft Publishe",
    "1.3.6.1.5.5.7.3.2": "Client Authentication",
    "1.3.6.1.5.2.3.4": "PKINIT Client Authentication",
    "1.3.6.1.4.1.311.10.3.13": "Lifetime Signing",
    "2.5.29.37.0": "Any Purpose",
    "1.3.6.1.4.1.311.64.1.1": "Server Trust",
    "1.3.6.1.4.1.311.10.3.7": "OEM Windows System Component Verification",
}

class IntFlag(enum.IntFlag):
    def to_list(self):
        cls = self.__class__
        members, _ = _decompose(cls, self._value_)
        return members

    def to_str_list(self):
        return list(map(lambda x: str(x), self.to_list()))
        

    def __str__(self):
        cls = self.__class__
        if self._name_ is not None:
            return "%s" % (to_pascal_case(self._name_))
        members, _ = _decompose(cls, self._value_)
        if len(members) == 1 and members[0]._name_ is None:
            return "%r" % (members[0]._value_)
        else:
            return "%s" % (
                ", ".join(
                    [to_pascal_case(str(m._name_ or m._value_)) for m in members]
                ),
            )

    def __repr__(self):
        return str(self)

class MS_PKI_CERTIFICATE_NAME_FLAG(IntFlag):
    NONE = 0
    ENROLLEE_SUPPLIES_SUBJECT = 1
    ADD_EMAIL = 0x00000002
    ADD_OBJ_GUID = 0x00000004
    OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME = 0x00000008
    ADD_DIRECTORY_PATH = 0x00000100
    ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000
    SUBJECT_ALT_REQUIRE_DOMAIN_DNS = 0x00400000
    SUBJECT_ALT_REQUIRE_SPN = 0x00800000
    SUBJECT_ALT_REQUIRE_DIRECTORY_GUID = 0x01000000
    SUBJECT_ALT_REQUIRE_UPN = 0x02000000
    SUBJECT_ALT_REQUIRE_EMAIL = 0x04000000
    SUBJECT_ALT_REQUIRE_DNS = 0x08000000
    SUBJECT_REQUIRE_DNS_AS_CN = 0x10000000
    SUBJECT_REQUIRE_EMAIL = 0x20000000
    SUBJECT_REQUIRE_COMMON_NAME = 0x40000000
    SUBJECT_REQUIRE_DIRECTORY_PATH = 0x80000000

    def __str__(self):
        return self.name

class MS_PKI_PRIVATE_KEY_FLAG(IntFlag):
    REQUIRE_PRIVATE_KEY_ARCHIVAL = 0x00000001
    EXPORTABLE_KEY = 0x00000010
    STRONG_KEY_PROTECTION_REQUIRED = 0x00000020
    REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM = 0x00000040
    REQUIRE_SAME_KEY_RENEWAL = 0x00000080
    USE_LEGACY_PROVIDER = 0x00000100
    ATTEST_NONE = 0x00000000
    ATTEST_REQUIRED = 0x00002000
    ATTEST_PREFERRED = 0x00001000
    ATTESTATION_WITHOUT_POLICY = 0x00004000
    EK_TRUST_ON_USE = 0x00000200
    EK_VALIDATE_CERT = 0x00000400
    EK_VALIDATE_KEY = 0x00000800
    HELLO_LOGON_KEY = 0x00200000

    def __str__(self):
        cls = self.__class__
        if self._name_ is not None:
            return "%s" % (self._name_)
        members, _ = _decompose(cls, self._value_)
        if len(members) == 1 and members[0]._name_ is None:
            return "%r" % (members[0]._value_)
        else:
            return "%s" % (
                ", ".join(
                    [str(m._name_ or m._value_) for m in members]
                ),
            )

class MS_PKI_ENROLLMENT_FLAG(IntFlag):
    NONE = 0x00000000
    INCLUDE_SYMMETRIC_ALGORITHMS = 0x00000001
    PEND_ALL_REQUESTS = 0x00000002
    PUBLISH_TO_KRA_CONTAINER = 0x00000004
    PUBLISH_TO_DS = 0x00000008
    AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE = 0x00000010
    AUTO_ENROLLMENT = 0x00000020
    CT_FLAG_DOMAIN_AUTHENTICATION_NOT_REQUIRED = 0x80
    PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT = 0x00000040
    USER_INTERACTION_REQUIRED = 0x00000100
    ADD_TEMPLATE_NAME = 0x200
    REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE = 0x00000400
    ALLOW_ENROLL_ON_BEHALF_OF = 0x00000800
    ADD_OCSP_NOCHECK = 0x00001000
    ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL = 0x00002000
    NOREVOCATIONINFOINISSUEDCERTS = 0x00004000
    INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS = 0x00008000
    ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT = 0x00010000
    ISSUANCE_POLICIES_FROM_REQUEST = 0x00020000
    SKIP_AUTO_RENEWAL = 0x00040000
    NO_SECURITY_EXTENSION = 0x00080000

    def __str__(self):
        cls = self.__class__
        if self._name_ is not None:
            return "%s" % (self._name_)
        members, _ = _decompose(cls, self._value_)
        if len(members) == 1 and members[0]._name_ is None:
            return "%r" % (members[0]._value_)
        else:
            return "%s" % (
                ", ".join(
                    [str(m._name_ or m._value_) for m in members]
                ),
            )
