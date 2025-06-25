import ipaddress

from bofhound.logger import logger, ColorScheme, OBJ_EXTRA_FMT


class LocalGroupMembership:
    LOCALGROUP_HOST              = "Host"
    LOCALGROUP_GROUP             = "Group"
    LOCALGROUP_MEMBER            = "Member"
    LOCALGROUP_MEMBER_SID        = "MemberSid"
    LOCALGROUP_MEMBER_SID_TYPE   = "MemberSidType"
    LOCALGROUP_NAMES             = [
        "administrators",
        "remote desktop users",
        "remote management users",
        "distributed com users"
    ]

    def __init__(self, object):
        self.host_name              = None
        self.host_domain            = None
        self.host_fqdn              = None
        self.group                  = None
        self.member                 = None
        self.member_netbios_domain  = None
        self.member_sid             = None
        self.member_sid_type        = None

        # will be set to True if correlated to a computer object
        self.matched = False

        try:
            ipaddress.ip_address(object[LocalGroupMembership.LOCALGROUP_HOST])
            logger.debug(f"Skipping local group member on {object[LocalGroupMembership.LOCALGROUP_HOST]} due to IP instead of hostname")
            return
        except:
            pass

        if LocalGroupMembership.LOCALGROUP_GROUP in object.keys():
            self.group = object[LocalGroupMembership.LOCALGROUP_GROUP]

        if LocalGroupMembership.LOCALGROUP_MEMBER in object.keys():
            parts = object[LocalGroupMembership.LOCALGROUP_MEMBER].split('\\')
            if len(parts) == 2:
                self.member = parts[1]
                self.member_netbios_domain = parts[0]
            else:
                self.member = parts[0]

        if LocalGroupMembership.LOCALGROUP_HOST in object.keys():
            if '.' in object[LocalGroupMembership.LOCALGROUP_HOST]:
                self.host_name = object[LocalGroupMembership.LOCALGROUP_HOST].split('.')[0]
                self.host_domain = '.'.join(object[LocalGroupMembership.LOCALGROUP_HOST].split('.')[1:])
                self.host_fqdn = object[LocalGroupMembership.LOCALGROUP_HOST]
            else:
                self.host_name = object[LocalGroupMembership.LOCALGROUP_HOST]
                logger.debug(f"FQDN missing from hostname for {ColorScheme.user}{self.user}[/] session on {ColorScheme.computer}{self.host_name}[/]", extra=OBJ_EXTRA_FMT)

        if LocalGroupMembership.LOCALGROUP_MEMBER_SID in object.keys():
            self.member_sid = object[LocalGroupMembership.LOCALGROUP_MEMBER_SID]

        if LocalGroupMembership.LOCALGROUP_MEMBER_SID_TYPE in object.keys():
            self.member_sid_type = object[LocalGroupMembership.LOCALGROUP_MEMBER_SID_TYPE]
    

    def should_import(self, known_domain_sids):
        # missing required attributes
        if self.host_name is None or self.group is None \
            or self.member_sid is None or self.member_sid_type is None:
            return False
        
        # filter out local groups we don't care about
        if self.group.lower() not in LocalGroupMembership.LOCALGROUP_NAMES:
            return False
        
        # do not import local account sessions or 
        # user sessions from unknown domains
        if self.member_sid.rsplit('-', 1)[0] not in known_domain_sids:
            color = ColorScheme.user if self.member_sid_type == "User" else ColorScheme.group
            logger.debug(f"Skipping local group membership for {color}{self.member}[/] since domain SID is unfamiliar", extra=OBJ_EXTRA_FMT)
            return False
        
        computer = f"{self.host_name}.{self.host_domain}" if self.host_domain else self.host_name
        user = f"{self.member}@{self.member_netbios_domain}" if self.member_netbios_domain else self.member
        logger.debug(f"Local group member found for {ColorScheme.user}{user}[/] on {ColorScheme.computer}{computer}[/]", extra=OBJ_EXTRA_FMT)
        return True
    

    # so that a set can be used to keep a unique list of objects
    def __eq__(self, other):
        return (self.host_name, self.host_domain, self.group, self.member_sid) == \
               (other.host_name, other.host_domain, other.group, other.member_sid)
    

    # so that a set can be used to keep a unique list of objects
    def __hash__(self):
        return hash((self.host_name, self.host_domain, self.group, self.member_sid))
    

    # for debugging
    def __repr__(self):
        return f"LocalGroupMembership(host_name={self.host_name}, group={self.group}, member={self.member}, member_netbios_domain={self.member_netbios_domain}, member_sid={self.member_sid}, member_sid_type={self.member_sid_type})"
    
