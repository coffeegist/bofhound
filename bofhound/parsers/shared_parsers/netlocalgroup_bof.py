from .sharedparser import SharedParser


class NetLocalGroupBofParser(SharedParser):
    START_BOUNDARY  = "----------Local Group Member----------"
    END_BOUNDARY    = "--------End Local Group Member--------"
    OBJECT_TYPE     = "LocalGroup"

    def __init__(self):
        pass


    @staticmethod
    def is_start_boundary_line(line):
        return line.strip() == NetLocalGroupBofParser.START_BOUNDARY
    

    @staticmethod
    def is_end_boundary_line(line):
        return line.strip() == NetLocalGroupBofParser.END_BOUNDARY