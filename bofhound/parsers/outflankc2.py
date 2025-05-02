import re
import codecs
import json

from bofhound.logger import logger
from bofhound.parsers.generic_parser import GenericParser
from bofhound.parsers import LdapSearchBofParser


#
# Parses ldapsearch BOF objects from Outflank C2 JSON logfiles
#   Assumes that the BOF was registered as a command in OC2 named 'ldapserach'
#

class OutflankC2JsonParser(LdapSearchBofParser):
    BOFNAME =  'ldapsearch'
    

    @staticmethod
    def prep_file(file):
        with codecs.open(file, 'r', 'utf-8') as f:
            return f.read()


    #
    # Slightly modified from LdapSearchBofParser to account for
    #  needing only part of each JSON object, instead of the whole file
    #
    @staticmethod
    def parse_data(contents):
        parsed_objects = []
        current_object = None
        in_result_region = False
        previous_attr = None

        in_result_region = False

        lines = contents.splitlines()
        for line in lines:
            event_json = json.loads(line.split('UTC ', 1)[1])

            # we only care about task_resonse events
            if event_json['event_type'] != 'task_response':
                continue
            
            # within task_response events, we only care about tasks with the name 'ldapsearch'
            if event_json['task']['name'].lower() !=  OutflankC2JsonParser.BOFNAME:
                continue
            
            # now we have a block of ldapsearch data we can parse through for objects
            response_lines = event_json['task']['response'].splitlines()
            for response_line in response_lines:

                is_boundary_line = OutflankC2JsonParser._is_boundary_line(response_line)

                if (not in_result_region and
                    not is_boundary_line):
                    continue

                if (is_boundary_line
                    and is_boundary_line != OutflankC2JsonParser._COMPLETE_BOUNDARY_LINE):
                    while True:
                        try:
                            next_line = next(response_lines)[1]
                            remaining_length = OutflankC2JsonParser._is_boundary_line(next_line, is_boundary_line)

                            if remaining_length:
                                is_boundary_line = remaining_length
                                if is_boundary_line == OutflankC2JsonParser._COMPLETE_BOUNDARY_LINE:
                                    break
                        except:
                            # probably ran past the end of the iterable
                            break

                if (is_boundary_line):
                    if not in_result_region:
                        in_result_region = True
                    elif current_object is not None:
                        # self.store_object(current_object)
                        parsed_objects.append(current_object)
                    current_object = {}
                    continue
                elif re.match("^(R|r)etr(e|i)(e|i)ved \\d+ results?", response_line):
                    #self.store_object(current_object)
                    parsed_objects.append(current_object)
                    in_result_region = False
                    current_object = None
                    continue

                data = response_line.split(': ')

                try:
                    # If we previously encountered a control message, we're probably still in the old property
                    if len(data) == 1:
                        if previous_attr is not None:
                            value = current_object[previous_attr] + response_line
                    else:
                        data = response_line.split(':')
                        attr = data[0].strip().lower()
                        value = ''.join(data[1:]).strip()
                        previous_attr = attr

                    current_object[attr] = value

                except Exception as e:
                    logger.debug(f'Error - {str(e)}')

        return parsed_objects


    #
    # Get local groups, sessions, etc by feeding data to GenericParser class
    #
    @staticmethod
    def parse_local_objects(file):
        return GenericParser.parse_file(file, is_outflankc2=True)