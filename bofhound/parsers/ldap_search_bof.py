import re
import codecs

from bofhound.logger import logger
from bofhound.parsers.generic_parser import GenericParser


#
# This class will be inherited by other parsers since most if not all are based
#   off the same BOF, wrapped by various C2s. These methods can be overridden
#   by child classes to handle specific parsing requirements
#
class LdapSearchBofParser():
    RESULT_DELIMITER = "-"
    RESULT_BOUNDARY_LENGTH = 20
    _COMPLETE_BOUNDARY_LINE = -1


    def __init__(self):
        pass

    #
    # Legacy, used by test cases for 1 liner
    #   Removed from __main__.py to avoid duplicating file reads and formatting
    #
    @staticmethod
    def parse_file(file):
        return LdapSearchBofParser.parse_data(
            LdapSearchBofParser.prep_file(file)
        )

    
    #
    # Replaces parse_file() usage in __main__.py to avoid duplicate file reads
    #
    @staticmethod
    def prep_file(file):
        with codecs.open(file, 'r', 'utf-8') as f:
            contents = f.read()

        return re.sub(r'\n\n\d{2}\/\d{2} (\d{2}:){2}\d{2} UTC \[output\]\nreceived output:\n', '', contents)

    
    #
    # Meat of the parsing logic 
    #
    @staticmethod
    def parse_data(data):
        parsed_objects = []
        current_object = None
        in_result_region = False
        previous_attr = None

        in_result_region = False

        lines = data.splitlines()
        for line in lines:
            is_boundary_line = LdapSearchBofParser._is_boundary_line(line)

            if (not in_result_region and
                  not is_boundary_line):
                continue

            if (is_boundary_line
                  and is_boundary_line != LdapSearchBofParser._COMPLETE_BOUNDARY_LINE):
                while True:
                    try:
                        next_line = next(lines)[1]
                        remaining_length = LdapSearchBofParser._is_boundary_line(next_line, is_boundary_line)

                        if remaining_length:
                            is_boundary_line = remaining_length
                            if is_boundary_line == LdapSearchBofParser._COMPLETE_BOUNDARY_LINE:
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
            elif re.match("^(R|r)etr(e|i)(e|i)ved \\d+ results?", line):
                #self.store_object(current_object)
                parsed_objects.append(current_object)
                in_result_region = False
                current_object = None
                continue

            data = line.split(': ')

            try:
                # If we previously encountered a control message, we're probably still in the old property
                if len(data) == 1:
                    if previous_attr is not None:
                        value = current_object[previous_attr] + line
                else:
                    data = line.split(':')
                    attr = data[0].strip().lower()
                    value = ''.join(data[1:]).strip()
                    previous_attr = attr

                current_object[attr] = value

            except Exception as e:
                logger.debug(f'Error - {str(e)}')

        return parsed_objects


    # Returns one of the following integers:
    #    0 - This is not a boundary line
    #   -1 - This is a complete boundary line
    #    n - The remaining characters needed to form a complete boundary line
    @staticmethod
    def _is_boundary_line(line, length=RESULT_BOUNDARY_LENGTH):
        line = line.strip()
        chars = set(line)

        if len(chars) == 1 and chars.pop() == LdapSearchBofParser.RESULT_DELIMITER:
            if len(line) == length:
                return -1
            elif len(line) < length:
                return LdapSearchBofParser.RESULT_BOUNDARY_LENGTH - len(line)

        return 0 # Falsey


    #
    # Get local groups, sessions, etc by feeding data to GenericParser class
    #
    @staticmethod
    def parse_local_objects(data):
        return GenericParser.parse_data(data)