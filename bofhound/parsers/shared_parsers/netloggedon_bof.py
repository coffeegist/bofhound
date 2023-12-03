from .sharedparser import SharedParser


class NetLoggedOnBofParser(SharedParser):
    START_BOUNDARY  = "-----------Logged on User-----------"
    END_BOUNDARY    = "---------End Logged on User---------"
    OBJECT_TYPE     = "PrivilegedSession"

    def __init__(self):
        pass


    @staticmethod
    def is_start_boundary_line(line):
        return line.strip() == NetLoggedOnBofParser.START_BOUNDARY
    

    @staticmethod
    def is_end_boundary_line(line):
        return line.strip() == NetLoggedOnBofParser.END_BOUNDARY