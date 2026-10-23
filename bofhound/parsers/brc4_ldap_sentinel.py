"""BRC4 LDAP Sentinel Parser Module."""
import re
import base64
from datetime import datetime as dt
from typing import Dict, Any
from typing_extensions import override
from impacket.ldap.ldaptypes import LDAP_SID

from bofhound.logger import logger
from .types import ObjectType, BoundaryBasedParser


class Brc4LdapSentinelParser(BoundaryBasedParser):
    """
    BRC4 LDAP Sentinel currently only queries attributes=["*"] and objectClass
    is always the top result. May need to be updated in the future.
    """
    FORMATTED_TS_ATTRS = [
        'lastlogontimestamp', 'lastlogon', 'lastlogoff', 'pwdlastset', 'accountexpires'
    ]
    ISO_8601_TS_ATTRS = ['dscorepropagationdata', 'whenchanged', 'whencreated']
    BRACKETED_ATTRS = ['objectguid']
    SEMICOLON_DELIMITED_ATTRS = [
        'serviceprincipalname', 'memberof', 'member', 'objectclass', 'msds-allowedtodelegateto','certificatetemplates', 'pkiextendedkeyusage', 'mspki-certificate-application-policy','mspki-ra-policies', 'dnsrecord'
    ]
    # BRc4 renders binary attributes as hex strings, the BH models expect base64
    HEX_ENCODED_ATTRS = [
        'cacertificate', 'usercertificate', 'crosscertificatepair', 'ntsecuritydescriptor',
        'schemaidguid', 'pkiexpirationperiod', 'pkioverlapperiod', 'dnsrecord',
        'msds-allowedtoactonbehalfofotheridentity'
    ]
    # values BRc4 prints for a timestamp attribute that holds no time
    EMPTY_TS_VALUES = ['', '0', 'never expires', 'value not set']

    # '[+] attributeName : value'. BRc4 pads the name into a fixed-width column and
    # drops the space before the colon when the name fills it
    ATTRIBUTE_LINE = re.compile(r'^\[\+\]\s+(?P<key>[^:]+?)\s*:\s?(?P<value>.*)$')
    # BRc4 frames console output with '+---+'; LDAP Sentinel separates objects with a run of dashes
    BOUNDARY_LINE = re.compile(r'^\+?-{10,}\+?$')
    # C2 console other output of other commands, not part of an object
    NOISE_LINE = re.compile(
        r'^(?:$'                                                # blank
        r'|\[[^+]\]'                                            # [*], [!], [-] status lines
        r'|\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} [A-Z]{2,5}\b'    # timestamped console lines
        r'|[-|]\s|\s+[-|]\s)'                                   # bulleted output of other BOFs
    )
    # BRc4 renders timestamps with the locale of the host it ran on, so both '10/17/2026 7:32:50 PM' and '17/10/2026 19:32:50' turn up in the same run
    TIMESTAMP = re.compile(
        r'^(\d{1,2})[/-](\d{1,2})[/-](\d{4})'
        r'(?:\s+(\d{1,2}):(\d{2}):(\d{2})\s*([AP])?\.?M?\.?)?$', re.IGNORECASE
    )
    # LDAP Sentinel prints objectClass first for every object
    OBJECT_START_ATTR = 'objectclass'

    def __init__(self):
        super().__init__(start_boundary_pattern=f'+{"-" * 67}+')
        # 'MDY' or 'DMY', inferred from the data as it is parsed
        self._date_order = 'MDY'

    @property
    def tool_name(self) -> str:
        return "brc4_ldap_sentinel"

    @property
    def produces_object_type(self) -> ObjectType:
        return ObjectType.LDAP_OBJECT

    @override
    def process_line(self, line: str) -> None:
        """
        An LDAP object is a list of consecutive '[+] attribute : value' lines,
        started by objectClass and ended by a separator, a console line or the
        output of any other command.
        """
        line = line.strip()

        attribute = Brc4LdapSentinelParser.ATTRIBUTE_LINE.match(line)
        if attribute:
            if (attribute.group('key').strip().lower() == Brc4LdapSentinelParser.OBJECT_START_ATTR):
                self._save_current_record()
            self._current_record_lines.append(line)
            return

        if (Brc4LdapSentinelParser.BOUNDARY_LINE.match(line) or Brc4LdapSentinelParser.NOISE_LINE.match(line)):
            self._save_current_record()
            return

        # anything else is the continuation of a value split across output chunks
        if self._current_record_lines:
            self._current_record_lines[-1] += line

    @override
    def _parse_lines_to_attributes(self) -> Dict[str, str]:
        attributes: Dict[str, Any] = {}

        for line in self._current_record_lines:
            attribute = Brc4LdapSentinelParser.ATTRIBUTE_LINE.match(line)
            if not attribute:
                continue
            key = attribute.group('key').strip().lower()
            value = attribute.group('value').strip()
            if attributes.get(key) and value:
                # repeated attribute, join as BRc4 joins its own multi-values
                attributes[key] += f'; {value}'
            else:
                attributes[key] = value

        if Brc4LdapSentinelParser.OBJECT_START_ATTR not in attributes:
            # output of some other command that happens to share BRc4's '[+] key : value' formatting (whoami, ipconfig, ...)
            return {}

        return self._post_process_attributes(attributes)

    def _post_process_attributes(self, attributes: Dict[str, Any]) -> Dict[str, Any]:
        processed_attributes = {}
        self._infer_date_order(attributes)
        for key, value in attributes.items():
            try:
                # BRc4 formats some timestamps for us that we need to revert to raw values
                if key in Brc4LdapSentinelParser.FORMATTED_TS_ATTRS:
                    if value.lower() in Brc4LdapSentinelParser.EMPTY_TS_VALUES:
                        continue
                    timestamp_obj = self._parse_timestamp(value)
                    value = int((timestamp_obj - dt(1601, 1, 1)).total_seconds() * 10000000)

                elif key in Brc4LdapSentinelParser.ISO_8601_TS_ATTRS:
                    formatted_ts = []
                    for ts in value.split(';'):
                        if not ts.strip():
                            continue
                        formatted_ts.append(self._parse_timestamp(ts).strftime("%Y%m%d%H%M%S.0Z"))
                    value = ', '.join(formatted_ts)

                # BRc4 formats some attributes with surroudning {} we need to remove
                if key in Brc4LdapSentinelParser.BRACKETED_ATTRS:
                    value = value.strip('{}')

                # BRc4 delimits some list-esque attributes with semicolons but BH models expect commas
                if key in Brc4LdapSentinelParser.SEMICOLON_DELIMITED_ATTRS:
                    value = value.replace('; ', ', ')

                # BRc4 prints binary attributes as hex, the BH models expect base64
                if key in Brc4LdapSentinelParser.HEX_ENCODED_ATTRS:
                    value = Brc4LdapSentinelParser._hex_to_b64(value)

                # Older BRc4 puts the trustDirection attribute within securityidentifier
                if key == 'securityidentifier' and 'trustdirection' in value.lower():
                    trust_direction = value.lower().split('trustdirection ')[1]
                    processed_attributes['trustdirection'] = trust_direction.strip()
                    value = value.split('trustdirection')[0].strip(' :')

                # trusts carry a binary SID, the BH model wants it canonicalized
                if key == 'securityidentifier':
                    value = Brc4LdapSentinelParser._canonicalize_sid(value)

                processed_attributes[key] = value

            except ValueError as e:
                # Handle timestamp parsing errors specifically
                if (key in
                    Brc4LdapSentinelParser.FORMATTED_TS_ATTRS
                    + Brc4LdapSentinelParser.ISO_8601_TS_ATTRS
                ):
                    # dropped rather than kept raw - the BH models feed these to int()
                    logger.warning('Failed to parse timestamp for %s: %s. Error: %s', key, value, e)
                else:
                    logger.warning('Value error processing %s: %s', key, e)
                    processed_attributes[key] = value
            except IndexError as e:
                # Handle list access errors (bracket removal, string splitting)
                logger.warning('Index error processing %s: %s. Error: %s', key, value, e)
                processed_attributes[key] = value
            except AttributeError as e:
                # Handle cases where value might be None
                logger.warning('Attribute error processing %s: %s. Error: %s', key, value, e)
                # Skip this attribute or set default
                continue
            except Exception as e:
                # Catch-all for unexpected errors, but log more context
                logger.error('Unexpected error processing attribute %s with value %s: %s: %s',key, value, type(e).__name__, e)
                # Decide whether to skip or keep original value
                processed_attributes[key] = value

        return processed_attributes

    def _infer_date_order(self, attributes: Dict[str, Any]) -> None:
        """
        Work out whether this object's timestamps are day-first or month-first.

        A component above 12 settles it outright; failing that, a 12-hour clock
        means a month-first rendering. An object that offers no evidence at all
        keeps the order of the last one, which holds a single log together.
        """
        votes = {'DMY': 0, 'MDY': 0}
        meridiem_seen = False

        timestamp_attrs = (Brc4LdapSentinelParser.FORMATTED_TS_ATTRS + Brc4LdapSentinelParser.ISO_8601_TS_ATTRS)
        for key in timestamp_attrs:
            for part in str(attributes.get(key, '')).split(';'):
                timestamp = Brc4LdapSentinelParser.TIMESTAMP.match(part.strip())
                if not timestamp:
                    continue
                first, second = int(timestamp.group(1)), int(timestamp.group(2))
                if first > 12:
                    votes['DMY'] += 1
                elif second > 12:
                    votes['MDY'] += 1
                meridiem_seen = meridiem_seen or bool(timestamp.group(7))

        if votes['DMY'] or votes['MDY']:
            self._date_order = 'DMY' if votes['DMY'] >= votes['MDY'] else 'MDY'
        elif meridiem_seen:
            self._date_order = 'MDY'

    def _parse_timestamp(self, value: str) -> dt:
        """
        Parse a timestamp as BRc4's host rendered it, using the day/month order inferred for the object it belongs to.
        """
        timestamp = Brc4LdapSentinelParser.TIMESTAMP.match(value.strip())
        if not timestamp:
            raise ValueError(f"unrecognized timestamp format: '{value}'")

        first, second, year = (int(timestamp.group(i)) for i in (1, 2, 3))
        hour, minute, second_of_min = (int(timestamp.group(i) or 0) for i in (4, 5, 6))
        meridiem = timestamp.group(7)

        date_order = self._date_order
        if first > 12:
            date_order = 'DMY'
        elif second > 12:
            date_order = 'MDY'

        day, month = (first, second) if date_order == 'DMY' else (second, first)

        if meridiem:
            if meridiem.upper() == 'P' and hour != 12:
                hour += 12
            elif meridiem.upper() == 'A' and hour == 12:
                hour = 0

        return dt(year, month, day, hour, minute, second_of_min)

    @staticmethod
    def _hex_to_b64(value: str) -> str:
        """Re-encode BRc4's hex-rendered binary attributes as base64"""
        converted = []
        for item in re.split(r'[;,]\s*', value):
            item = item.strip()
            if not item:
                continue
            try:
                converted.append(base64.b64encode(bytes.fromhex(item)).decode())
            except ValueError:
                # not hex (already base64) - leave untouched
                converted.append(item)
        return ', '.join(converted)

    @staticmethod
    def _canonicalize_sid(value: str) -> str:
        """Convert a hex-rendered binary SID to its canonical S-1-5-... form"""
        if not value or value.upper().startswith('S-'):
            return value
        try:
            return LDAP_SID(data=bytes.fromhex(value)).formatCanonical()
        except Exception:
            logger.warning('Failed to parse binary securityIdentifier: %s', value)
            return value

    def get_key_value(self, line: str) -> tuple[str, str]:
        """Split line into key and value at the first colon"""
        parts = line.split(":", 1)
        key_part = parts[0]
        if ']' in key_part:
            # strip the BRc4 '[+] ' output marker, if present
            key_part = key_part.split(']', 1)[1]
        key = key_part.strip().lower()
        value = None
        if len(parts) > 1:
            value = parts[1].strip()
        return key, value
