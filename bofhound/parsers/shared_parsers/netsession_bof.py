from .sharedparser import SharedParser


class NetSessionBofParser(SharedParser):
    START_BOUNDARY  = "---------------Session--------------"
    END_BOUNDARY    = "-------------End Session------------"
    OBJECT_TYPE     = "Session"

    def __init__(self):
        pass


    @staticmethod
    def is_start_boundary_line(line):
        return line.strip() == NetSessionBofParser.START_BOUNDARY
    

    @staticmethod
    def is_end_boundary_line(line):
        return line.strip() == NetSessionBofParser.END_BOUNDARY