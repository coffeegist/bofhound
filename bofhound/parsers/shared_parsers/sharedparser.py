
class SharedParser():

    def __init__(self):
        pass


    # will be same for all child classes
    @staticmethod
    def parse_line(line, current_object):
        data = line.split(': ')
        try:
            attr = data[0].strip()
            value = data[1].strip()

            # if attr is not on the current object, add it
            if attr not in current_object:
                current_object[attr] = value

            return current_object
        except IndexError:
            return current_object


    # will be implemented in child classes
    @staticmethod
    def is_start_boundary_line(line):
        pass
    

    # will be implemented in child classes
    @staticmethod
    def is_end_boundary_line(line):
        pass