"""Parser types and base classes"""

import re
from enum import Enum
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from typing_extensions import override


class ObjectType(Enum):
    """Types of objects that parsers can produce"""
    LDAP_OBJECT = "ldap_object"
    SESSION = "Session"
    LOCAL_GROUP = "LocalGroup"
    REGISTRY_SESSION = "RegistrySession"
    PRIVILEGED_SESSION = "PrivilegedSession"


class ParsingState(Enum):
    """States for the parsing state machine"""
    WAITING_FOR_OBJECT = "waiting_for_object"
    IN_OBJECT = "in_object"


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


class BoundaryBasedParser(ToolParser):
    """Abstract base class for parsing records from tools with start/end boundaries."""

    __skipped_marker = "<__NOISE_SKIPPED_LINE__>"

    def __init__(self, start_boundary_pattern: str, end_boundary_pattern: str = None):
        self._current_record_lines: List[str] = []
        self._records: List[Dict[str, Any]] = []
        self._parsing_state = ParsingState.WAITING_FOR_OBJECT
        self._start_boundary_detector = BoundaryDetector(start_boundary_pattern)
        self._end_boundary_detector = (
            BoundaryDetector(end_boundary_pattern) if end_boundary_pattern else None
        )
        self._skippable_patterns = []

    @override
    def process_line(self, line) -> None:
        """
        Process a single line.
        """
        line = line.strip()

        if self.should_skip_line(line):
            self._handle_skipped_line()
            return

        start_boundary = self._start_boundary_detector.process_line(line)

        # Handle start boundary results
        match start_boundary:
            case BoundaryResult.COMPLETE_BOUNDARY:
                self._handle_start_boundary_line()
                return
            case BoundaryResult.PARTIAL_BOUNDARY:
                return

        if self._end_boundary_detector is not None:
            end_boundary = self._end_boundary_detector.process_line(line)

            # Handle end boundary results
            match end_boundary:
                case BoundaryResult.COMPLETE_BOUNDARY:
                    self._handle_end_boundary_line()
                    return
                case BoundaryResult.PARTIAL_BOUNDARY:
                    return

        self._handle_content_line(line)

    @override
    def get_results(self) -> list[dict[str, str]]:
        if self._current_record_lines:  # Complete any pending record
            self._save_current_record()
        return self._records

    def should_skip_line(self, line: str) -> bool:
        """Determine if a line should be skipped."""
        return any(re.match(pattern, line) for pattern in self._skippable_patterns)

    def _handle_end_boundary_line(self) -> None:
        """Handle end of tool's output line"""
        if self._parsing_state == ParsingState.IN_OBJECT:
            self._save_current_record()
        self._parsing_state = ParsingState.WAITING_FOR_OBJECT

    def _handle_start_boundary_line(self) -> None:
        """Handle boundary line between LDAP objects"""
        if self._parsing_state == ParsingState.WAITING_FOR_OBJECT:
            self._parsing_state = ParsingState.IN_OBJECT
        else:
            # Even if record is empty, add it to stay consistent with
            # number of entries ldapsearchbof reports to have retrieved
            self._save_current_record()

    def _save_current_record(self) -> None:
        """Build the current record from lines and save it"""
        attributes = self._parse_lines_to_attributes()
        if attributes: # If not empty object
            self._records.append(attributes)
        self._current_record_lines = []

    def _handle_skipped_line(self) -> None:
        """Handle a line that should be skipped."""
        if self._parsing_state == ParsingState.IN_OBJECT:
            # Keep a marker of a skipped line in the record's lines
            self._current_record_lines.append(self.__skipped_marker)

    def _handle_content_line(self, line: str) -> None:
        if self._parsing_state == ParsingState.IN_OBJECT:
            self._current_record_lines.append(line)

    def _parse_lines_to_attributes(self) -> Dict[str, str]:
        break_in_previous_message: bool = False
        in_attribute_key: bool = True
        current_attribute: str = ""
        attributes: Dict[str, Any] = {}

        for line in self._current_record_lines:
            line = line.strip()
            if (line == ""
                or line == self.__skipped_marker):
                # This line is blank or was skipped as noise;
                #  treat as break in previous message
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
            self._reset()
            return BoundaryResult.NOT_BOUNDARY

    def _reset(self) -> None:
        """Reset accumulated character count."""
        self._accumulated_chars = 0
