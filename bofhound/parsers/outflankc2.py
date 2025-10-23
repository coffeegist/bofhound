"""Parser for Outflank C2 JSON logfiles containing ldapsearch BOF data."""
import codecs
import json

from typing_extensions import override
from bofhound.logger import logger
from bofhound.parsers.generic_parser import GenericParser
from bofhound.parsers import LdapSearchBofParser


class OutflankC2JsonParser(LdapSearchBofParser):
    """
    Parses ldapsearch BOF objects from Outflank C2 JSON logfile
    Assumes that the BOF was registered as a command in OC2 named 'ldapsearch'
    """

    @override
    def process_line(self, line: str) -> None:
        """Process a single line from an Outflank C2 JSON logfile"""
        bofname = 'ldapsearch'
        event_json = json.loads(line.split('UTC ', 1)[1])

        # we only care about task_resonse events
        if (event_json['event_type'] == 'task_response'
            and event_json['task']['name'].lower() == bofname):
            # now we have a block of ldapsearch data we can parse through for objects
            response_lines = event_json['task']['response']
            for response_line in response_lines.splitlines():
                super().process_line(response_line)

    @staticmethod
    def parse_local_objects(file):
        return GenericParser.parse_file(file, is_outflankc2=True)
