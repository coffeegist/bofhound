"""BRC4 LDAP Sentinel Parser Module."""
from datetime import datetime as dt
from typing import Dict, Any

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
        'serviceprincipalname', 'memberof', 'member', 'objectclass', 'msds-allowedtodelegateto'
    ]

    def __init__(self):
        super().__init__(start_boundary_pattern=f'+{"-" * 67}+')

        self._skippable_patterns = [
            r'^\[\*\] Task-\d+ \[Thread: \d+\]$',
            r'^\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2} [A-Z]{3} \[input\] .+$',
            r'^\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2} [A-Z]{3} \[sent \d+ bytes\]$'
        ]

    @property
    def tool_name(self) -> str:
        return "brc4_ldap_sentinel"

    @property
    def produces_object_type(self) -> ObjectType:
        return ObjectType.LDAP_OBJECT

    def _post_process_attributes(self, attributes: Dict[str, Any]) -> Dict[str, Any]:
        processed_attributes = {}
        for key, value in attributes.items():
            try:
                # BRc4 formats some timestamps for us that we need to revert to raw values
                if key in Brc4LdapSentinelParser.FORMATTED_TS_ATTRS:
                    if value.lower() in ['never expires', 'value not set', '0']:
                        continue
                    timestamp_obj = dt.strptime(value, '%m/%d/%Y %I:%M:%S %p')
                    value = int((timestamp_obj - dt(1601, 1, 1)).total_seconds() * 10000000)

                if key in Brc4LdapSentinelParser.ISO_8601_TS_ATTRS:
                    formatted_ts = []
                    for ts in value.split(';'):
                        timestamp_obj = dt.strptime(ts.strip(), "%m/%d/%Y %I:%M:%S %p")
                        timestamp_str = timestamp_obj.strftime("%Y%m%d%H%M%S.0Z")
                        formatted_ts.append(timestamp_str)
                    value = ', '.join(formatted_ts)

                # BRc4 formats some attributes with surroudning {} we need to remove
                if key in Brc4LdapSentinelParser.BRACKETED_ATTRS:
                    value = value[1:-1]

                # BRc4 delimits some list-esque attributes with semicolons
                # when our BH models expect commas
                if key in Brc4LdapSentinelParser.SEMICOLON_DELIMITED_ATTRS:
                    value = value.replace('; ', ', ')

                # BRc4 puts the trustDirection attribute within securityidentifier
                if key == 'securityidentifier' and 'trustdirection' in value.lower():
                    trust_direction = value.lower().split('trustdirection ')[1]
                    processed_attributes['trustdirection'] = trust_direction
                    value = value.split('trustdirection: ')[0]
                    continue

                processed_attributes[key] = value

            except ValueError as e:
                # Handle timestamp parsing errors specifically
                if (key in
                    Brc4LdapSentinelParser.FORMATTED_TS_ATTRS
                    + Brc4LdapSentinelParser.ISO_8601_TS_ATTRS
                ):
                    logger.warning('Failed to parse timestamp for %s: %s. Error: %s', key, value, e)
                    # Keep original value or set to None based on requirements
                    processed_attributes[key] = value
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
                logger.error(
                    'Unexpected error processing attribute %s with value %s: %s: %s',
                    key, value, type(e).__name__, e
                )
                # Decide whether to skip or keep original value
                processed_attributes[key] = value

        return processed_attributes

    def get_key_value(self, line:str) -> tuple[str, str]:
        """Split line into key and value at the first colon"""
        parts = line.split(":", 1)
        key = parts[0].split(']')[1].strip().lower()
        value = None
        if len(parts) > 1:
            value = parts[1].strip()
        return key, value
