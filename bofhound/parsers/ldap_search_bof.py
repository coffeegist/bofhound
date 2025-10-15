"""
Parser for LDAP search results from ldapsearch BOF and pyldapsearch
using a state machine approach.
"""
import re
import codecs
from enum import Enum
from typing import List, Optional, Dict, Any, Iterable
from bofhound.parsers.generic_parser import GenericParser


class ParsingState(Enum):
    """States for the LDAP parsing state machine"""
    WAITING_FOR_LDAP_OBJECT = "waiting_for_ldap_object"
    IN_LDAP_OBJECT = "in_ldap_object"


class LdapRecordState(Enum):
    """States for the LDAP Record Object state machine"""
    IN_ATTRIBUTE_KEY = "in_attribute"
    IN_ATTRIBUTE_VALUE = "in_attribute_value"


class LdapRecord:
    """Represents a single LDAP object being parsed"""

    def __init__(self):
        self.attributes: Dict[str, str] = {}
        self.current_attribute: Optional[str] = None
        self.state = LdapRecordState.IN_ATTRIBUTE_KEY
        self._break_in_previous_message = False

    def add_attribute_line(self, line: str) -> None:
        """Add data to the current record from the given line"""
        if line.strip() == "":
            self._break_in_previous_message = True
        else:
            key, value = self._get_key_value(line)
            if self._break_in_previous_message:
                self._break_in_previous_message = False
                if self.state == LdapRecordState.IN_ATTRIBUTE_KEY:
                    self.current_attribute += key
                    if value:
                        self.attributes[self.current_attribute] = value
                        self.state = LdapRecordState.IN_ATTRIBUTE_VALUE
                elif self.state == LdapRecordState.IN_ATTRIBUTE_VALUE:
                    self.attributes[self.current_attribute] += line
            else:
                self.current_attribute = key
                if value:
                    self.attributes[key] = value
                    self.state = LdapRecordState.IN_ATTRIBUTE_VALUE
                else:
                    self.state = LdapRecordState.IN_ATTRIBUTE_KEY

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format expected by existing code"""
        return dict(self.attributes)

    def is_empty(self) -> bool:
        """Check if record has no attributes"""
        return len(self.attributes) == 0

    def _get_key_value(self, line:str) -> tuple[str, str]:
        """Split line into key and value at the first colon"""
        parts = line.split(":", 1)
        key = parts[0].strip().lower()
        value = None
        if len(parts) > 1:
            value = parts[1].strip()
        return key, value

    @staticmethod
    def from_lines(lines: List[str]) -> 'LdapRecord':
        """Create an LdapRecord from a list of lines"""
        record = LdapRecord()
        for line in lines:
            record.add_attribute_line(line)

        return record


class StreamingLdapParser:
    """State machine-based streaming parser for LDAP data from C2 logs"""
    RESULT_DELIMITER = "-"
    RESULT_BOUNDARY_LENGTH = 20
    _COMPLETE_BOUNDARY_LINE = -1

    def __init__(self):
        self.state = ParsingState.WAITING_FOR_LDAP_OBJECT
        self.current_record: List[str] = []
        self.ldap_records: List[LdapRecord] = []

        # Regex patterns
        self.new_message_pattern = re.compile(r'^\d{2}\/\d{2} \d{2}:\d{2}:\d{2} UTC \[output\]$')
        self.retrieved_pattern = re.compile(r'^(R|r)etr(e|i)(e|i)ved \d+ results?')

    def process_line(self, line: str) -> None:
        """
        Process a single line and return any completed LDAP records.

        Returns:
            List of completed LDAP records as dictionaries
        """
        line = line.strip()
        # completed_objects = []

        if (self._is_timestamp_line(line) or
            self._is_received_output_line(line)):
            return

        elif self._is_boundary_line(line):
            self._handle_boundary_line()

        elif self._is_retrieved_line(line):
            self._handle_retrieved_results_line()

        else:
            # Empty or non-empty content line
            # We need to process empty lines to determine if a message break occurred
            self._handle_content_line(line)

    def finalize(self) -> None:
        """Finalize parsing and return any remaining records"""
        if self.current_record:  # Complete any pending record
            self.ldap_records.append(LdapRecord.from_lines(self.current_record))
            self.current_record = []

        return

    def get_records(self) -> List[Dict[str, Any]]:
        """Get all parsed LDAP records as dictionaries"""
        return [record.to_dict() for record in self.ldap_records if not record.is_empty()]

    def _is_timestamp_line(self, line: str) -> bool:
        """Check if line is a timestamp marking new message"""
        return self.new_message_pattern.match(line) is not None

    def _is_boundary_line(self, line: str) -> bool:
        """Check if line is a boundary (dashes) between LDAP objects"""
        chars = set(line.strip())

        if (len(chars) == 1
            and chars.pop() == LdapSearchBofParser.RESULT_DELIMITER):
            return True
        else:
            return False

    def _is_retrieved_line(self, line: str) -> bool:
        """Check if line indicates end of LDAP results"""
        return self.retrieved_pattern.match(line) is not None

    def _handle_boundary_line(self) -> None:
        """Handle boundary line between LDAP objects"""
        if not self.state == ParsingState.IN_LDAP_OBJECT:
            self.state = ParsingState.IN_LDAP_OBJECT
            return

        # Even if record is empty, add it to stay consistent with
        # number of entries ldapsearchbof reports to have retrieved
        self.ldap_records.append(LdapRecord.from_lines(self.current_record))

        self.current_record = []

    def _handle_retrieved_results_line(self) -> List[Dict[str, Any]]:
        """Handle 'Retrieved X results' line"""
        self.finalize()
        self.state = ParsingState.WAITING_FOR_LDAP_OBJECT

    def _handle_content_line(self, line: str) -> None:
        """Handle a line with actual content"""
        if self.state == ParsingState.IN_LDAP_OBJECT:
            self.current_record.append(line)

    def _is_received_output_line(self, line: str) -> bool:
        """Check if line is 'received output:' control message"""
        return line.strip() == "received output:"


class LdapSearchBofParser():
    """
    This class will be inherited by other parsers since most if not all are
    based off the same BOF, wrapped by various C2s. These methods can be
    overridden by child classes to handle specific parsing requirements
    """
    RESULT_DELIMITER = "-"
    RESULT_BOUNDARY_LENGTH = 20
    _COMPLETE_BOUNDARY_LINE = -1

    def __init__(self):
        pass

    @staticmethod
    def parse_data(data: Iterable) -> List[Dict[str, Any]]:
        """
        Parse LDAP data using true streaming approach with state machine.
        """
        if isinstance(data, str):
            raise ValueError("Input data should be an iterable of lines, not a single string.")

        parser = StreamingLdapParser()

        for raw_line in data:
            line = raw_line.rstrip('\n\r')
            # Process line with state machine and get any completed objects
            parser.process_line(line)

        # Get any final objects from the parser
        parser.finalize()

        return parser.get_records()

    @staticmethod
    def parse_file(file) -> List[Dict[str, Any]]:
        """Parse LDAP data from a file"""
        with codecs.open(file, 'r', 'utf-8') as f:
            return LdapSearchBofParser.parse_data(f)

    @staticmethod
    def parse_local_objects(data):
        """
        Get local groups, sessions, etc by feeding data to GenericParser class
        """
        return GenericParser.parse_data(data)

    @staticmethod
    def parse_local_objects_stream(file_path: str) -> List[Dict[str, Any]]:
        """
        Parse local objects using streaming approach.

        For now, we filter the file content and pass to GenericParser,
        but this could be enhanced with its own state machine in the future.
        """
        filtered_lines = []
        new_message_pattern = re.compile(r'^\d{2}\/\d{2} \d{2}:\d{2}:\d{2} UTC \[output\]$')

        with codecs.open(file_path, 'r', 'utf-8') as f:
            for line in f:
                line = line.rstrip('\n\r')

                # Skip timestamp and "received output:" lines
                if (new_message_pattern.match(line) or
                    line.strip() == "received output:" or
                    line.strip() == ""):
                    continue

                filtered_lines.append(line)

        # Join and pass to GenericParser
        if filtered_lines:
            clean_content = '\n'.join(filtered_lines)
            return GenericParser.parse_data(clean_content)

        return []
