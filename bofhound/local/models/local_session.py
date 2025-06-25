from bofhound.logger import logger, ColorScheme, OBJ_EXTRA_FMT


class LocalSession:
    SESSION_PTR             = "PTR"
    SESSION_USER            = "User"
    SESSION_COMPUTER_NAME   = "ComputerName"
    SESSION_COMPUTER_DOMAIN = "ComputerDomain"

    def __init__(self, object):
        self.username                   = None
        self.ptr_record                 = None
        self.computer_name              = None
        self.computer_netbios_domain    = None
        self.computer_domain            = None

        # will be set to True if correlated to a computer object
        self.matched = False

        if LocalSession.SESSION_PTR in object.keys():
            if "reverse lookup failed" not in object[LocalSession.SESSION_PTR]:
                self.ptr_record = object[LocalSession.SESSION_PTR]
                self.computer_name = self.ptr_record.split('.')[0]
                self.computer_domain = '.'.join(self.ptr_record.split('.')[1:])
        
        if LocalSession.SESSION_USER in object.keys():
            self.username = object[LocalSession.SESSION_USER]

        if LocalSession.SESSION_COMPUTER_NAME in object.keys():
            self.computer_name = object[LocalSession.SESSION_COMPUTER_NAME]

        if LocalSession.SESSION_COMPUTER_DOMAIN in object.keys():
            self.computer_netbios_domain = object[LocalSession.SESSION_COMPUTER_DOMAIN]
    

    def should_import(self):
        # missing required attributes
        if self.username is None or self.ptr_record is None \
            and self.computer_name is None or (self.computer_domain is None and self.computer_netbios_domain is None):
            return False
        
        # do not import sessions if NetWkstaGetInfo failed
        fail = "NetWkstaGetInfo Failed;"
        if self.computer_name is not None and self.computer_netbios_domain is not None:
            if self.computer_name.startswith(fail) or self.computer_netbios_domain.startswith(fail):
                return False
        
        # do not import computer accounts
        if self.username.endswith('$'):
            return False
        
        # do not import anonymous sessions
        if self.username.upper() == 'ANONYMOUS LOGON':
            return False
        
        computer = self.ptr_record if self.ptr_record else self.computer_name
        logger.debug(f"NetSessionEnum session found for {ColorScheme.user}{self.username}[/] on {ColorScheme.computer}{computer}[/]", extra=OBJ_EXTRA_FMT)
        return True


    # so that a set can be used to keep a unique list of objects
    def __eq__(self, other):
        return (self.username, self.ptr_record, self.computer_name, self.computer_domain) == \
               (other.username, other.ptr_record, other.computer_name, other.computer_domain)
    

    # so that a set can be used to keep a unique list of objects
    def __hash__(self):
        return hash((self.username, self.ptr_record, self.computer_name, self.computer_domain))

    # for debugging
    def __repr__(self):
        return f"LocalSession(username={self.username}, ptr_record={self.ptr_record}, computer_name={self.computer_name}, computer_domain={self.computer_domain}, computer_netbios_domain={self.computer_netbios_domain})"