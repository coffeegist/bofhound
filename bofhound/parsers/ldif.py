"""Implementation of parser for LDIF written by the OpenLDAP ldapsearch client."""
import re
import base64
from uuid import UUID
from typing import Any, Dict, List
from typing_extensions import override
from impacket.ldap.ldaptypes import LDAP_SID

from bofhound.logger import logger
from .types import ObjectType, ToolParser


class LdifParser(ToolParser):
    # binary attributes the BH models decode themselves - leave them base64
    BINARY_ATTRS = frozenset([
        'ntsecuritydescriptor', 'msds-allowedtoactonbehalfofotheridentity',
        'msds-groupmsamembership', 'schemaidguid', 'pkiexpirationperiod',
        'pkioverlapperiod', 'usercertificate', 'cacertificate',
        'crosscertificatepair', 'dnsrecord', 'logonhours', 'thumbnailphoto',
        'msexchmailboxsecuritydescriptor', 'auditingpolicy', 'dsasignature',
        'repsfrom', 'repsto', 'repluptodatevector', 'msds-trustforesttrustinfo',
        'msds-generationid', 'msds-managedpasswordid',
        'msds-managedpasswordpreviousid', 'userparameters', 'msds-keycredentiallink',
        'protocolsettings', 'terminalserver', 'replicationsignature',
    ])
    # binary SIDs the BH models want in canonical S-1-5-... form
    SID_ATTRS = frozenset(['objectsid', 'securityidentifier'])
    # binary GUIDs the BH models use as an ObjectIdentifier
    GUID_ATTRS = frozenset(['objectguid', 'ms-ds-consistencyguid', 'msexcharchiveguid','msexchmailboxguid', 'msrtcsip-userroutinggroupid'])
    # the BH models iterate these and hand each element to LDAP_SID()
    BYTE_LIST_ATTRS = frozenset(['sidhistory'])

    # 'attributeName[;option]: value', '...:: <base64>' or '...:< <url>'
    ATTRIBUTE_LINE = re.compile(r'^(?P<key>[A-Za-z][A-Za-z0-9.-]*)(?:;[^:]*)?(?P<marker>::|:<|:)[ ]?(?P<value>.*)$')

    def __init__(self):
        self._current_record_lines: List[str] = []
        self._records: List[Dict[str, Any]] = []
        # LDIF folding applies to comments too, so they have to be tracked
        self._in_comment = False

    @property
    def tool_name(self) -> str:
        return "ldif"

    @property
    def produces_object_type(self) -> ObjectType:
        return ObjectType.LDAP_OBJECT

    @override
    def process_line(self, line: str) -> None:
        """Process a single line, unfolding it into the current entry."""
        line = line.rstrip('\r\n')

        # a blank line ends the entry
        if not line.strip():
            self._save_current_record()
            self._in_comment = False
            return

        # a leading space continues the previous line
        if line.startswith(' '):
            if not self._in_comment and self._current_record_lines:
                self._current_record_lines[-1] += line[1:]
            return

        # '# pagedresults: cookie=...', '# search result', version markers, ...
        self._in_comment = line.startswith('#')
        if self._in_comment:
            return

        # entries are not always separated by a blank line (ldapsearch -LLL
        # against a referral-chasing server, concatenated dumps, ...)
        if line[:3].lower() == 'dn:':
            self._save_current_record()

        self._current_record_lines.append(line)

    @override
    def get_results(self) -> List[Dict[str, Any]]:
        if self._current_record_lines:  # complete any pending record
            self._save_current_record()
        return self._records

    def _save_current_record(self) -> None:
        """Build the current record from its lines and save it"""
        attributes = self._parse_lines_to_attributes()
        if attributes:
            self._records.append(attributes)
        self._current_record_lines = []

    def _parse_lines_to_attributes(self) -> Dict[str, Any]:
        attributes: Dict[str, Any] = {}

        for line in self._current_record_lines:
            attribute = LdifParser.ATTRIBUTE_LINE.match(line)
            if not attribute:
                continue

            key = attribute.group('key').lower()
            marker = attribute.group('marker')
            value = attribute.group('value')

            # ':<' holds a URL the value lives at, there is nothing to parse
            if marker == ':<':
                continue

            if marker == '::':
                value = self._decode_attribute(key, value)
                if value is None:
                    continue

            if key in LdifParser.BYTE_LIST_ATTRS:
                attributes.setdefault(key, []).append(value)
            elif key in attributes:
                # the BH models split multi-values on ', ', as the BOF joins them
                attributes[key] += f', {value}'
            else:
                attributes[key] = value

        if not attributes:
            return {}

        # a dump that did not ask for distinguishedName still carries the DN
        if 'dn' in attributes:
            attributes.setdefault('distinguishedname', attributes['dn'])

        return attributes

    def _decode_attribute(self, key: str, value: str) -> Any:
        """Render a base64 LDIF value the way the BloodHound models expect it"""
        try:
            raw = base64.b64decode(value, validate=True)
        except Exception:
            logger.debug("Failed to base64 decode %s, keeping raw value", key)
            return value

        if key in LdifParser.BYTE_LIST_ATTRS:
            return raw

        if key in LdifParser.SID_ATTRS:
            try:
                return LDAP_SID(data=raw).formatCanonical()
            except Exception:
                logger.warning("Failed to parse binary %s: %s", key, value)
                return value

        if key in LdifParser.GUID_ATTRS:
            try:
                return str(UUID(bytes_le=raw)).upper()
            except Exception:
                logger.warning("Failed to parse binary %s: %s", key, value)
                return value

        if key in LdifParser.BINARY_ATTRS:
            return value

        # anything else was base64'd only because it holds non-ASCII text
        # (names with accents, DNs with embedded newlines, ...) - binary blobs
        # that happen to decode cleanly keep their base64 form
        try:
            text = raw.decode('utf-8')
        except UnicodeDecodeError:
            return value
        if any(ord(char) < 32 or ord(char) == 127 for char in text):
            return value
        return text
