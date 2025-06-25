import ipaddress

from bofhound.logger import logger, ColorScheme, OBJ_EXTRA_FMT


class LocalPrivilegedSession:
    PS_HOST     = "Host"
    PS_USERNAME = "Username"
    PS_DOMAIN   = "Domain"

    def __init__(self, object):
        self.host_name      = None
        self.host_domain    = None
        self.host_fqdn      = None
        self.user           = None
        self.user_domain    = None

        # will be set to True if correlated to a computer object
        self.matched = False

        try:
            ipaddress.ip_address(object[LocalPrivilegedSession.PS_HOST])
            logger.debug(f"Skipping session on {object[LocalPrivilegedSession.PS_HOST]} due to IP instead of hostname")
            return
        except:
            pass
        
        if LocalPrivilegedSession.PS_USERNAME in object.keys():
            self.user = object[LocalPrivilegedSession.PS_USERNAME]

        if LocalPrivilegedSession.PS_DOMAIN in object.keys():
            self.user_domain = object[LocalPrivilegedSession.PS_DOMAIN]

        if LocalPrivilegedSession.PS_HOST in object.keys():
            self.host_fqdn = object[LocalPrivilegedSession.PS_HOST]
            if '.' in self.host_fqdn:
                self.host_name = self.host_fqdn.split('.')[0]
                self.host_domain = '.'.join(self.host_fqdn.split('.')[1:])
            else:
                logger.debug(f"FQDN missing from hostname for {ColorScheme.user}{self.user}[/] session on {ColorScheme.computer}{self.host_fqdn}[/]", extra=OBJ_EXTRA_FMT)

    def should_import(self):
        # missing required attributes
        if self.host_name is None or self.host_domain is None \
            or self.user is None or self.user_domain is None:
            return False
        
        # do not import computer accounts
        if self.user.endswith('$'):
            return False
        
        # do not import local accounts
        if self.host_name.lower() == self.user_domain.lower():
            return False
        
        logger.debug(f"NetWkstaUserEnum session found for {ColorScheme.user}{self.user}@{self.user_domain}[/] on {ColorScheme.computer}{self.host_fqdn}[/]", extra=OBJ_EXTRA_FMT)
        return True


    # so that a set can be used to keep a unique list of objects
    def __eq__(self, other):
        return (self.host_name, self.host_domain, self.host_fqdn, self.user, self.user_domain) == \
               (other.host_name, other.host_domain, other.host_fqdn, other.user, other.user_domain)


    # so that a set can be used to keep a unique list of objects
    def __hash__(self):
        return hash((self.host_name, self.host_domain, self.host_fqdn, self.user, self.user_domain))


    # for debugging
    def __repr__(self):
        return f"LocalPrivilegedSession(host_name={self.host_name}, host_domain={self.host_domain}, host_fqdn={self.host_fqdn}, user={self.user}, user_domain={self.user_domain})"