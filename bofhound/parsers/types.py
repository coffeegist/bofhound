"""Parser types and base classes"""

import re
from enum import Enum
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from typing_extensions import override


class ObjectType(Enum):
    """Types of objects that parsers can produce"""
    LDAP_OBJECT = "ldap_object"
    SESSION = "session"
    LOCAL_GROUP = "local_group"
    REGISTRY_SESSION = "registry_session"


class ParsingState(Enum):
    """States for the LDAP parsing state machine"""
    WAITING_FOR_LDAP_OBJECT = "waiting_for_ldap_object"
    IN_LDAP_OBJECT = "in_ldap_object"


class ToolParser(ABC):
    """Abstract base class for all tool parsers"""

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Return the name of the tool this parser handles"""

    @property
    @abstractmethod
    def produces_object_type(self) -> ObjectType:
        """Return the type of object this parser produces"""

    @abstractmethod
    def process_line(self, line: str) -> None:
        """Process a single line of input"""

    @abstractmethod
    def get_results(self) -> List[Dict[str, Any]]:
        """Return all parsed objects and reset internal state"""


class LdapRecordParser(ToolParser):
    """Abstract base class for LDAP record parsers"""

    def __init__(self, boundary_pattern: str):
        self._current_record_lines: List[str] = []
        self._ldap_records: List[Dict[str, Any]] = []
        self._parsing_state = ParsingState.WAITING_FOR_LDAP_OBJECT
        self._boundary_detector = BoundaryDetector(boundary_pattern)
        self._skippable_patterns = []
        self._end_of_tool_output_pattern = None

    @override
    def process_line(self, line) -> None:
        """
        Process a single line.
        """
        line = line.strip()
        boundary = self._boundary_detector.process_line(line)

        match boundary:
            case BoundaryResult.COMPLETE_BOUNDARY:
                self._handle_boundary_line()
            case BoundaryResult.PARTIAL_BOUNDARY:
                return
            case BoundaryResult.NOT_BOUNDARY | BoundaryResult.INVALID_BOUNDARY:
                if self._is_end_of_tool_output(line):
                    self._handle_end_of_tool_output()
                elif not self.should_skip_line(line):
                    self._handle_content_line(line)

    @override
    def get_results(self) -> list[dict[str, str]]:
        if self._current_record_lines:  # Complete any pending record
            self._save_current_record()
        return self._ldap_records

    def should_skip_line(self, line: str) -> bool:
        """Determine if a line should be skipped."""
        return any(re.match(pattern, line) for pattern in self._skippable_patterns)

    def _is_end_of_tool_output(self, line: str) -> bool:
        """Check if line indicates end of tool's output"""
        if self._end_of_tool_output_pattern is None:
            return False
        else:
            return re.match(self._end_of_tool_output_pattern, line) is not None

    def _handle_end_of_tool_output(self) -> None:
        """Handle end of tool's output line"""
        if self._parsing_state == ParsingState.IN_LDAP_OBJECT:
            self._save_current_record()
        self._parsing_state = ParsingState.WAITING_FOR_LDAP_OBJECT

    def _handle_boundary_line(self) -> None:
        """Handle boundary line between LDAP objects"""
        if self._parsing_state != ParsingState.IN_LDAP_OBJECT:
            self._parsing_state = ParsingState.IN_LDAP_OBJECT
        else:
            # Even if record is empty, add it to stay consistent with
            # number of entries ldapsearchbof reports to have retrieved
            self._save_current_record()

    def _save_current_record(self) -> None:
        """Build the current record from lines and save it"""
        attributes = self._parse_lines_to_attributes()
        if attributes: # If not empty object
            self._ldap_records.append(attributes)
        self._current_record_lines = []

    def _handle_content_line(self, line: str) -> None:
        if self._parsing_state == ParsingState.IN_LDAP_OBJECT:
            self._current_record_lines.append(line)

    def _parse_lines_to_attributes(self) -> Dict[str, str]:
        break_in_previous_message: bool = False
        in_attribute_key: bool = True
        current_attribute: str = ""
        attributes: Dict[str, Any] = {}

        for line in self._current_record_lines:
            if line.strip() == "":
                break_in_previous_message = True
            else:
                key, value = self.get_key_value(line)
                if break_in_previous_message:
                    break_in_previous_message = False
                    if in_attribute_key:
                        current_attribute += key
                        if value:
                            attributes[current_attribute] = value
                            in_attribute_key = False
                    else:
                        attributes[current_attribute] += line
                else:
                    current_attribute = key
                    if value:
                        attributes[key] = value
                        in_attribute_key = False
                    else:
                        in_attribute_key = True

        processed_attributes = self._post_process_attributes(attributes)
        return processed_attributes

    def _post_process_attributes(self, attributes: Dict[str, Any]) -> Dict[str, Any]:
        """Post-process parsed attributes if needed"""
        return attributes

    def get_key_value(self, line:str) -> tuple[str, str]:
        """Split line into key and value at the first colon"""
        parts = line.split(":", 1)
        key = parts[0].strip().lower()
        value = None
        if len(parts) > 1:
            value = parts[1].strip()
        return key, value


class BoundaryResult(Enum):
    """Results of boundary detection."""
    NOT_BOUNDARY = "not_boundary"
    PARTIAL_BOUNDARY = "partial_boundary"
    COMPLETE_BOUNDARY = "complete_boundary"
    INVALID_BOUNDARY = "invalid_boundary"


class BoundaryDetector:
    """Detects boundaries of specific character repeated exactly N times."""

    def __init__(self, boundary_pattern: str):
        self._boundary_pattern = boundary_pattern
        self._accumulated_chars = 0
        self._target_length = len(boundary_pattern)

    def process_line(self, line: str) -> BoundaryResult:
        """Process a line and return boundary detection result."""
        # clean_line = line.strip()

        if not line:
            return BoundaryResult.NOT_BOUNDARY

        # Check if this line could be part of the boundary pattern
        remaining_pattern = self._boundary_pattern[self._accumulated_chars:]

        if remaining_pattern.startswith(line):
            # This line matches the next part of the pattern
            self._accumulated_chars += len(line)

            if self._accumulated_chars == self._target_length:
                self._reset()
                return BoundaryResult.COMPLETE_BOUNDARY
            else:
                return BoundaryResult.PARTIAL_BOUNDARY
        else:
            return BoundaryResult.NOT_BOUNDARY

    def _reset(self) -> None:
        """Reset accumulated character count."""
        self._accumulated_chars = 0
