import json
import codecs

from .shared_parsers import __all_generic_parsers__


class GenericParser:

    def __init__(self):
        pass


    @staticmethod
    def parse_file(file, is_outflankc2=False):
         with codecs.open(file, 'r', 'utf-8') as f:
            if is_outflankc2:
                return GenericParser.parse_outflank_file(f.read())
            else:    
                return GenericParser.parse_data(f.read())

    
    @staticmethod
    def parse_outflank_file(contents):
        parsed_objects = []

        for line in contents.splitlines():
            event_json = json.loads(line.split('UTC ', 1)[1])

            # we only care about task_resonse events
            if event_json['event_type'] != 'task_response':
                continue
             
            # within task_response events, we only care about tasks with specific BOF names
            if event_json['task']['name'].lower() not in ['netsession2', 'netloggedon2', 'regsession', 'netlocalgrouplistmembers2']:
                continue
            
            parsed_objects.extend(GenericParser.parse_data(event_json['task']['response']))

        return parsed_objects


    @staticmethod
    def parse_data(contents):
        parsed_objects = []
        current_parser = None
        current_object = {}
        
        lines = contents.splitlines()

        for line in lines:
            # if we have no current parser, check and see if the current line is a start boundary
            if current_parser is None:
                for parser in __all_generic_parsers__:
                    if parser.is_start_boundary_line(line):
                        current_parser = parser
                        break

            # if we do have a current parser, check and see if the current line is an end boundary
            else:
                if current_parser is not None:
                    if current_parser.is_end_boundary_line(line):
                        # we've reached the end of the current object, so store it and reset the parser
                        current_object["ObjectType"] = current_parser.OBJECT_TYPE
                        parsed_objects.append(current_object)
                        current_parser = None
                        current_object = {}
                        continue
               
                # if we have a current parser and the current line is not an end boundary, parse the line
                if current_parser is not None:
                    current_object = current_parser.parse_line(line, current_object)

        return parsed_objects
                
                
                    
        