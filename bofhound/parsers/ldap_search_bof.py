"""Implementation of ToolParser for ldapsearch BOF logs."""
from .types import ObjectType, LdapRecordParser


class LdapSearchBofParser(LdapRecordParser):
    """
    Implementation of ToolParser for ldapsearch BOF logs.
    """

    def __init__(self):
        super().__init__(boundary_pattern="-" * 20)

        self._skippable_patterns = [
            r'^\d{2}\/\d{2} \d{2}:\d{2}:\d{2} UTC \[output\]$',
            r'^received output:$'
        ]
        self._end_of_tool_output_pattern = r'^(R|r)etr(e|i)(e|i)ved \d+ results?'

    @property
    def tool_name(self) -> str:
        return "ldapsearch_bof"

    @property
    def produces_object_type(self) -> ObjectType:
        return ObjectType.LDAP_OBJECT
