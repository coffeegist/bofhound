from bofhound.logger import logger, OBJ_EXTRA_FMT, ColorScheme


class BloodHoundCrossRef(object):

    def __init__(self, object):
        self.netBiosName = None
        self.nCName = None
        self.distinguishedName = None

        if 'netbiosname' in object.keys() and 'ncname' in object.keys() and 'distinguishedname' in object.keys():
            self.netBiosName = object.get('netbiosname')
            self.nCName = object.get('ncname').upper()
            self.distinguishedName = object.get('distinguishedname').upper()
            logger.debug(f"Reading CrossRef object {ColorScheme.schema}{self.distinguishedName}[/]", extra=OBJ_EXTRA_FMT)
