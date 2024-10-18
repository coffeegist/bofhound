import re
import base64
import codecs
import json

from io import BytesIO
from bloodhound.ad.utils import ADUtils
from bloodhound.enumeration.acls import parse_binary_acl, SecurityDescriptor
from bloodhound.enumeration.acls import ACL, ACCESS_ALLOWED_ACE, ACCESS_MASK, ACE, ACCESS_ALLOWED_OBJECT_ACE, build_relation, has_extended_right, EXTRIGHTS_GUID_MAPPING
import logging

from bofhound.ad.models import BloodHoundDomain, BloodHoundComputer, BloodHoundUser, BloodHoundGroup, BloodHoundSchema

#
# Parses ldapsearch BOF objects from Outflank C2 JSON logfiles
#   Assumes that the BOF was registered as a command in OC2 named 'ldapserach'
#

class OutflankC2JsonParser():
    RESULT_DELIMITER = "-"
    RESULT_BOUNDARY_LENGTH = 20
    _COMPLETE_BOUNDARY_LINE = -1

    def __init__(self):
        pass #self.objects = []

    @staticmethod
    def parse_file(file):

        with codecs.open(file, 'r', 'utf-8') as f:
            return OutflankC2JsonParser.parse_data(f.read())

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
            if event_json['task']['name'].lower() != 'ldapsearch':
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
                    logging.debug(f'Error - {str(e)}')

        return parsed_objects


    # Returns one of the following integers:
    #    0 - This is not a boundary line
    #   -1 - This is a complete boundary line
    #    n - The remaining characters needed to form a complete boundary line
    @staticmethod
    def _is_boundary_line(line, length=RESULT_BOUNDARY_LENGTH):
        line = line.strip()
        chars = set(line)

        if len(chars) == 1 and chars.pop() == OutflankC2JsonParser.RESULT_DELIMITER:
            if len(line) == length:
                return -1
            elif len(line) < length:
                return OutflankC2JsonParser.RESULT_BOUNDARY_LENGTH - len(line)

        return 0 # Falsey
