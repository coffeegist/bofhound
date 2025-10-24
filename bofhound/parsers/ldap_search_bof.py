"""Implementation of ToolParser for ldapsearch BOF logs."""
import re
from typing_extensions import override
from .types import ObjectType, BoundaryBasedParser


class LdapSearchBofParser(BoundaryBasedParser):
    """
    Implementation of ToolParser for ldapsearch BOF logs.
    """

    def __init__(self):
        super().__init__(start_boundary_pattern="-" * 20)

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

    def _is_end_of_tool_output(self, line: str) -> bool:
        """Check if the line indicates the end of tool output."""
        return re.match(self._end_of_tool_output_pattern, line) is not None

    @override
    def process_line(self, line: str) -> None:
        """Process a single line."""
        line = line.strip()
        if self._is_end_of_tool_output(line):
            self._handle_end_boundary_line()
            return
        super().process_line(line)
