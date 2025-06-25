import calendar
from datetime import datetime
from bloodhound.ad.utils import ADUtils, LDAP_SID

from .bloodhound_object import BloodHoundObject
from bofhound.logger import logger, OBJ_EXTRA_FMT, ColorScheme


class BloodHoundComputer(BloodHoundObject):

    GUI_PROPERTIES = [
        'domain', 'name', 'distinguishedname', 'domainsid', 'samaccountname',
        'haslaps', 'isaclprotected', 'description', 'whencreated', 'enabled',
        'unconstraineddelegation', 'trustedtoauth', 'isdc', 'lastlogon', 'lastlogontimestamp',
        'pwdlastset', 'serviceprincipalnames', 'email', 'operatingsystem', 'sidhistory'
    ]

    COMMON_PROPERTIES = [
        'useraccountcontrol', 'dnshostname', 'samaccounttype', 'primarygroupid',
        'msds-allowedtodelegateto', 'operatingsystemservicepack',
        'msds-allowedtoactonbehalfofotheridentity', 'ms-mcs-admpwdexpirationtime',
        'memberof'
    ]

    LOCAL_GROUP_SIDS = {
        "administrators": 544,
        "remote desktop users": 555,
        "remote management users": 580,
        "distributed com users": 562
    }

    def __init__(self, object):
        super().__init__(object)

        self._entry_type = "Computer"
        self.not_collected = {
            "Collected": False,
            "FailureReason": None,
            "Results": []
        }
        self.uac = None
        self.IsACLProtected = False
        self.IsDeleted = False
        self.hostname = object.get('dnshostname', None)
        self.PrimaryGroupSid = self.get_primary_membership(object) # Returns none if non-existent
        self.sessions = None #['not currently supported by bofhound']
        self.AllowedToDelegate = []
        self.MemberOfDNs = []
        self.sessions = []
        self.ContainedBy = {}
        self.privileged_sessions = []
        self.registry_sessions = []
        self.local_group_members = {} # {group_name: [{member_sid, member_type}]}

        if 'dnshostname' in object.keys():
            self.hostname = object.get('dnshostname', None)
            self.Properties['name'] = self.hostname.upper()
            logger.debug(f"Reading Computer object {ColorScheme.computer}{self.Properties['name']}[/]", extra=OBJ_EXTRA_FMT)

        if 'msds-allowedtodelegateto' in object.keys():
            self.AllowedToDelegate = object.get('msds-allowedtodelegateto').split(', ')

        if 'useraccountcontrol' in object.keys():
            self.uac = int(object.get('useraccountcontrol'))
            self.Properties['unconstraineddelegation'] = self.uac & 0x00080000 == 0x00080000
            self.Properties['enabled'] = self.uac & 2 == 0
            self.Properties['trustedtoauth'] = self.uac & 0x01000000 == 0x01000000
            self.Properties['isdc'] = self.uac & 0x2000 == 0x2000

        if 'operatingsystem' in object.keys():
            self.Properties['operatingsystem'] = object.get('operatingsystem', 'Unknown')

        if 'operatingsystemservicepack' in object.keys() and 'operatingsystem' in self.Properties:
            self.Properties['operatingsystem'] += f' {object.get("operatingsystemservicepack")}'

        if 'sidhistory' in object.keys():
            self.Properties['sidhistory'] = [LDAP_SID(bsid).formatCanonical() for bsid in object.get('sidhistory', [])]
        else:
            self.Properties['sidhistory'] = []

        if 'distinguishedname' in object.keys():
            domain = ADUtils.ldap2domain(object.get('distinguishedname')).upper()
            self.Properties['domain'] = domain
            if 'samaccountname' in object.keys() and 'dnshostname' not in object.keys():
                samacctname = object.get("samaccountname")
                if samacctname.endswith("$"):
                    name = f'{samacctname[:-1]}.{domain}'.upper()
                else:
                    name = f'{samacctname}.{domain}'.upper()
                self.Properties["name"] = name
                logger.debug(f"Reading Computer object {ColorScheme.computer}{self.Properties['name']}[/]", extra=OBJ_EXTRA_FMT)

        # TODO: HighValue / AdminCount
        self.Properties['highvalue'] = False

        if 'ms-mcs-admpwdexpirationtime' in object.keys():
            self.Properties['haslaps'] = True
        else:
            self.Properties['haslaps'] = False

        if 'lastlogontimestamp' in object.keys():
            self.Properties['lastlogontimestamp'] = ADUtils.win_timestamp_to_unix(
                int(object.get('lastlogontimestamp'))
            )

        if 'lastlogon' in object.keys():
            self.Properties['lastlogon'] = ADUtils.win_timestamp_to_unix(
                int(object.get('lastlogon'))
            )

        if 'pwdlastset' in object.keys():
            self.Properties['pwdlastset'] = ADUtils.win_timestamp_to_unix(
                int(object.get('pwdlastset'))
            )

        if 'serviceprincipalname' in object.keys():
            self.Properties['serviceprincipalnames'] = object.get('serviceprincipalname').split(', ')

        if 'description' in object.keys():
            self.Properties['description'] = object.get('description')
        
        if 'email' in object.keys():
            self.Properties['email'] = object.get('email')

        if 'samaccounttype' in object.keys():
            self.Properties['samaccounttype'] = object.get('samaccounttype')    

        if 'ntsecuritydescriptor' in object.keys():
            self.RawAces = object['ntsecuritydescriptor']

        if 'memberof' in object.keys():
                self.MemberOfDNs = [f'CN={dn.upper()}' for dn in object.get('memberof').split(', CN=')]
                if len(self.MemberOfDNs) > 0:
                    self.MemberOfDNs[0] = self.MemberOfDNs[0][3:]

        if 'email' in object.keys():
            self.Properties['email'] = object.get('email')
        else:
            self.Properties['email'] = None

        if 'description' in object.keys():
            self.Properties['description'] = object.get('description')
        else:
            self.Properties['description'] = None

    def to_json(self, properties_level):
        self.Properties['msds-allowedtodelegateto'] = self.AllowedToDelegate
        self.Properties['isaclprotected'] = self.IsACLProtected
        data = super().to_json(properties_level)
        data["Sessions"] = self.format_session_json(self.sessions)
        data["PrivilegedSessions"] = self.format_session_json(self.privileged_sessions)
        data["RegistrySessions"] = self.format_session_json(self.registry_sessions)
        data["ObjectIdentifier"] = self.ObjectIdentifier
        data["PrimaryGroupSID"] = self.PrimaryGroupSid
        data["AllowedToDelegate"] = self.AllowedToDelegate
        data["AllowedToAct"] = []
        data["HasSidHistory"] = self.Properties.get("sidhistory", [])
        data["DumpSMSAPassword"] = []
        data["LocalGroups"] = self.format_local_group_json()
        data["UserRights"] = []
        data["Status"] = None
        data["IsDeleted"] = self.IsDeleted
        data["ContainedBy"] = self.ContainedBy
        data["Aces"] = self.Aces
        data["IsACLProtected"] = self.IsACLProtected
        data["IsDC"] = self.Properties["isdc"]

        return data

    
    def format_session_json(self, results):
        if len(results) == 0:
            return self.not_collected

        return {
            "Collected": True,
            "FailureReason": None,
            "Results": results
        }

    
    def format_local_group_json(self):
        if len(self.local_group_members) == 0:
            return []

        data = []

        hostname = self.hostname if self.hostname is not None else self.Properties['name']

        for group_name, members in self.local_group_members.items():
            data.append({
                "ObjectIdentifier": f"{self.ObjectIdentifier}-{BloodHoundComputer.LOCAL_GROUP_SIDS[group_name]}",
                "Name": f"{group_name}@{hostname}".upper(),
                "Results": members,
                "Collected": True,
                "FailureReason": None
            })

        return data

    
    # check if a session host's fully qualified hostname matches 
    # the computer's dnshostname attribute
    def matches_dnshostname(self, session_host_fqdn):
        if self.Properties.get('dnshostname', '').upper() == session_host_fqdn.upper():
            return True
        return False

    
    # check if a session host's hostname matches the computer's samaccountname
    def matches_samaccountname(self, session_hostname):
        if self.Properties['samaccountname'].upper() == session_hostname.upper() + '$':
            return True
        return False


    # add a session to the computer object
    def add_session(self, user_sid, session_type):
        session = {
            "UserSID": user_sid,
            "ComputerSID": self.ObjectIdentifier,
        }

        if session_type == 'privileged':
            self.privileged_sessions.append(session)
        elif session_type == 'registry':
            self.registry_sessions.append(session)
        elif session_type == 'session':
            self.sessions.append(session)


    # add a local group member
    def add_local_group_member(self, member_sid, member_type, group_name):
        member = {
                "ObjectIdentifier": member_sid,
                "ObjectType": member_type
        }

        if group_name.lower() not in self.local_group_members.keys():
            self.local_group_members[group_name.lower()] = [ member ]
        else:
            self.local_group_members[group_name.lower()].append(member)    
