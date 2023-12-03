from .shared_parsers import __all_generic_parsers__
import codecs

class GenericParser:

    def __init__(self):
        pass


    @staticmethod
    def parse_file(file):
         with codecs.open(file, 'r', 'utf-8') as f:
            return GenericParser.parse_data(f.read())


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
                
                
                    
        