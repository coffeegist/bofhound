import ipaddress

from bofhound.logger import logger, ColorScheme, OBJ_EXTRA_FMT


class LocalRegistrySession:
    REGSESSION_HOST     = "Host"
    REGSESSION_USER_SID = "UserSid"


    def __init__(self, object):
        self.user_sid       = None
        self.host_name      = None
        self.host_domain    = None
        self.host_fqdn      = None

        try:
            ipaddress.ip_address(object[LocalRegistrySession.REGSESSION_HOST])
            logger.debug(f"Skipping session on {object[LocalRegistrySession.REGSESSION_HOST]} due to IP instead of hostname")
            return
        except:
            pass
        
        # will be set to True if correlated to a computer object
        self.matched = False

        if LocalRegistrySession.REGSESSION_USER_SID in object.keys():
            self.user_sid = object[LocalRegistrySession.REGSESSION_USER_SID]

        if LocalRegistrySession.REGSESSION_HOST in object.keys():
            if '.' in object[LocalRegistrySession.REGSESSION_HOST]:
                self.host_fqdn = object[LocalRegistrySession.REGSESSION_HOST]
                self.host_name = self.host_fqdn.split('.')[0]
                self.host_domain = '.'.join(self.host_fqdn.split('.')[1:])
            else:
                self.host_name = object[LocalRegistrySession.REGSESSION_HOST]
                logger.debug(f"FQDN missing from hostname for {ColorScheme.user}{self.user_sid}[/] session on {ColorScheme.computer}{self.host_name}[/]", extra=OBJ_EXTRA_FMT)

    def should_import(self, known_domain_sids):
        # missing required attributes
        if self.user_sid is None or self.host_name is None:
            return False

        # do not import local account sessions or 
        # user sessions from unknown domains
        if self.user_sid.rsplit('-', 1)[0] not in known_domain_sids:
            logger.debug(f"Skipping session for {ColorScheme.user}{self.user_sid}[/] since domain SID is unfamiliar", extra=OBJ_EXTRA_FMT)
            return False

        computer = self.host_fqdn if self.host_fqdn else self.host_name
        logger.debug(f"Registry session found for {ColorScheme.user}{self.user_sid}[/] on {ColorScheme.computer}{computer}[/]", extra=OBJ_EXTRA_FMT)
        return True


    # so that a set can be used to keep a unique list of objects
    def __eq__(self, other):
        return (self.user_sid, self.host_name, self.host_domain) == \
               (other.user_sid, other.host_name, other.host_domain)
    

    # so that a set can be used to keep a unique list of objects
    def __hash__(self):
        return hash((self.user_sid, self.host_name, self.host_domain))


    # for debugging
    def __repr__(self):
        return f"RegistrySession<user_sid={self.user_sid}, host_name={self.host_name}, host_domain={self.host_domain}>"