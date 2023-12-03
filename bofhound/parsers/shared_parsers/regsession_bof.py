from .sharedparser import SharedParser


class RegSessionBofParser(SharedParser):
    START_BOUNDARY  = "-----------Registry Session---------"
    END_BOUNDARY    = "---------End Registry Session-------"
    OBJECT_TYPE     = "RegistrySession"

    def __init__(self):
        pass


    @staticmethod
    def is_start_boundary_line(line):
        return line.strip() == RegSessionBofParser.START_BOUNDARY
    

    @staticmethod
    def is_end_boundary_line(line):
        return line.strip() == RegSessionBofParser.END_BOUNDARY