import re
import base64
from io import BytesIO
from typing import Dict, List
from impacket.uuid import string_to_bin
from bloodhound.ad.utils import ADUtils
from bloodhound.enumeration.acls import (
    SecurityDescriptor, ACCESS_MASK, ACE, ACCESS_ALLOWED_OBJECT_ACE,
    has_extended_right, EXTRIGHTS_GUID_MAPPING, can_write_property, ace_applies
)
from bofhound.logger import logger
from bofhound.ad.models import (
    BloodHoundComputer, BloodHoundDomain, BloodHoundGroup, BloodHoundObject, BloodHoundSchema,
    BloodHoundUser, BloodHoundOU, BloodHoundGPO, BloodHoundEnterpriseCA, BloodHoundAIACA,
    BloodHoundRootCA, BloodHoundNTAuthStore, BloodHoundIssuancePolicy, BloodHoundCertTemplate,
    BloodHoundContainer, BloodHoundDomainTrust, BloodHoundCrossRef, BloodHoundDnsNode
)
from bofhound.logger import OBJ_EXTRA_FMT, ColorScheme
from bofhound import console

#
# Add a GUID for enroll to the bloodhound-python mapping we imported
#
EXTRIGHTS_GUID_MAPPING["Enroll"] = string_to_bin("0e10c968-78fb-11d2-90d4-00c04f79dc55")


class ADDS():

    AT_SCHEMAIDGUID = "schemaidguid"
    AT_SAMACCOUNTTYPE = "samaccounttype"
    AT_DISTINGUISHEDNAME = "distinguishedname"
    AT_MSDS_GROUPMSAMEMBERSHIP = "msds-groupmsamembership"
    AT_OBJECTCLASS = "objectclass"
    AT_OBJECTID = "objectsid"
    AT_NAME = "name"
    AT_COMMONNAME = "cn"
    AT_SAMACCOUNTNAME = "samaccountname"
    AT_ORGUNIT = "ou"
    AT_OBJECTGUID = "objectguid"


    def __init__(self):
        self.sid = None
        self.SID_MAP = {} # {sid: BofHoundModel}
        self.DN_MAP = {} # {dn: BofHoundModel}
        self.DOMAIN_MAP = {} # {dc: ObjectIdentifier}
        self.CROSSREF_MAP = {} # { netBiosName: BofHoundModel }
        self.DNSNODE_MAP = {} # { dnsHostname: set(ipaddress) }
        self.ObjectTypeGuidMap = {} # { Name : schemaIdGuid }
        self.domains: list[BloodHoundDomain] = []
        self.users: list[BloodHoundUser] = []
        self.computers: list[BloodHoundComputer] = []
        self.groups: list[BloodHoundGroup] = []
        self.ous: list[BloodHoundOU] = []
        self.gpos: list[BloodHoundGPO] = []
        self.enterprisecas: list[BloodHoundEnterpriseCA] = []
        self.aiacas: list[BloodHoundAIACA] = []
        self.rootcas: list[BloodHoundRootCA] = []
        self.ntauthstores: list[BloodHoundNTAuthStore] = []
        self.issuancepolicies: list[BloodHoundIssuancePolicy] = []
        self.certtemplates: list[BloodHoundCertTemplate] = []
        self.containers: list[BloodHoundContainer] = []
        self.schemas: list[BloodHoundSchema] = []
        self.trusts: list[BloodHoundDomainTrust] = []
        self.trustaccounts: list[BloodHoundUser] = []
        self.unknown_objects: list[dict] = []

    def import_objects(self, objects):
        """Parse a list of dictionaries representing attributes of an AD object
            and add or merge them into appropriate lists of objects in the ADDS instance

        objects: [] of {} containing attributes for AD objects
        """

        for object in objects:
            # check if object is a schema - exception for normally required attributes
            schemaIdGuid = object.get(ADDS.AT_SCHEMAIDGUID, None)
            if schemaIdGuid:
                new_schema = BloodHoundSchema(object)
                if new_schema.SchemaIdGuid is not None:
                    self.schemas.append(new_schema)
                    if new_schema.Name not in self.ObjectTypeGuidMap:
                        self.ObjectTypeGuidMap[new_schema.Name] = new_schema.SchemaIdGuid
                continue

            # check if object is a crossRef - exception for normally required attributes
            if 'top, crossRef' in object.get(ADDS.AT_OBJECTCLASS, ''):
                new_crossref = BloodHoundCrossRef(object)
                if new_crossref.netBiosName is not None:
                    if new_crossref.netBiosName not in self.CROSSREF_MAP:
                        self.CROSSREF_MAP[new_crossref.netBiosName] = new_crossref
                continue

            # check if object is a dnsNode - exception for normally required attributes
            if 'top, dnsNode' in object.get(ADDS.AT_OBJECTCLASS, ''):
                new_dnsnode = BloodHoundDnsNode(object)
                if new_dnsnode.name is not None and new_dnsnode.ipaddresses:
                    if new_dnsnode.name not in self.DNSNODE_MAP:
                        self.DNSNODE_MAP[new_dnsnode.name] = set()
                    self.DNSNODE_MAP[new_dnsnode.name].update(new_dnsnode.ipaddresses)
                continue

            #
            # if samaccounttype comes back as something other
            #  than int, skip the object
            #
            try:
                accountType = int(object.get(ADDS.AT_SAMACCOUNTTYPE, 0))
            except:
                continue

            target_list = None

            # objectClass: top, container
            # objectClass: top, container, groupPolicyContainer
            # objectClass: top, organizationalUnit

            dn = object.get(ADDS.AT_DISTINGUISHEDNAME, None)
            sid = object.get(ADDS.AT_OBJECTID, None)
            guid = object.get(ADDS.AT_OBJECTGUID, None)

            # SID and DN are required attributes for bofhound objects
            if dn is None or (sid is None and guid is None):
                self.unknown_objects.append(object)
                continue

            originalObject = self.retrieve_object(dn.upper(), sid)
            bhObject = None

            # Groups
            if accountType in [268435456, 268435457, 536870912, 536870913]:
                bhObject = BloodHoundGroup(object)
                target_list = self.groups

            # Users
            elif object.get(ADDS.AT_MSDS_GROUPMSAMEMBERSHIP, b'') != b'' \
                or accountType in [805306368]:
                bhObject = BloodHoundUser(object)
                target_list = self.users

            # Computers
            elif accountType in [805306369]:
                bhObject = BloodHoundComputer(object)
                target_list = self.computers

            # Trust Accounts
            elif accountType in [805306370]:
                self.trustaccounts.append(object)

            # Other Things :)
            else:
                object_class = object.get(ADDS.AT_OBJECTCLASS, '')
                # if 'top, domain' in object_class or 'top, builtinDomain' in object_class:
                if 'top, domain' in object_class:
                    if 'objectsid' in object:
                        bhObject = BloodHoundDomain(object)
                        self.add_domain(bhObject)
                        target_list = self.domains
                # grab domain trusts
                elif 'trustedDomain' in object_class:
                    bhObject = BloodHoundDomainTrust(object)
                    target_list = self.trusts
                # grab OUs
                elif 'top, organizationalUnit' in object_class:
                    bhObject = BloodHoundOU(object)
                    target_list = self.ous
                elif 'container, groupPolicyContainer' in object_class:
                    bhObject = BloodHoundGPO(object)
                    target_list = self.gpos
                # grab PKIs
                elif 'top, certificationAuthority' in object_class:
                    if 'CN=AIA,' in object.get('distinguishedname'):
                        bhObject = BloodHoundAIACA(object)
                        target_list = self.aiacas
                    elif 'CN=Certification Authorities,' in object.get('distinguishedname') :
                        bhObject = BloodHoundRootCA(object)
                        target_list = self.rootcas
                    elif object.get('distinguishedname').upper().startswith('CN=NTAUTHCERTIFICATES,CN=PUBLIC KEY SERVICES,CN=SERVICES,CN=CONFIGURATION,'):
                        bhObject = BloodHoundNTAuthStore(object)
                        target_list = self.ntauthstores
                elif 'top, msPKI-Enterprise-Oid' in object_class:
                    # only want these if flags property is 2, ref: https://github.com/BloodHoundAD/SharpHoundCommon/blob/ea6b097927c5bb795adb8589e9a843293d36ae37/src/CommonLib/Extensions.cs#L402
                    if 'flags' in object:
                        if object.get('flags') == '2':
                            bhObject = BloodHoundIssuancePolicy(object)
                            target_list = self.issuancepolicies
                elif 'top, pKIEnrollmentService' in object_class:
                    bhObject = BloodHoundEnterpriseCA(object)
                    target_list = self.enterprisecas
                # grab PKI Templates
                elif 'top, pKICertificateTemplate' in object_class:
                    bhObject = BloodHoundCertTemplate(object)
                    target_list = self.certtemplates
                elif 'top, container' in object_class:
                    if not (re.search(r'\{.*\},CN=Policies,CN=System,', object.get('distinguishedname')) or 'CN=Operations,CN=DomainUpdates,CN=System' in object.get('distinguishedname')):
                        bhObject = BloodHoundContainer(object)
                        target_list = self.containers
                # some well known SIDs dont return the accounttype property
                elif object.get(ADDS.AT_NAME) in ADUtils.WELLKNOWN_SIDS:
                    bhObject, target_list =  self._lookup_known_sid(object, object.get(ADDS.AT_NAME))
                elif object.get(ADDS.AT_COMMONNAME) in ADUtils.WELLKNOWN_SIDS:
                    bhObject, target_list =  self._lookup_known_sid(object, object.get(ADDS.AT_COMMONNAME))
                else:
                    self.unknown_objects.append(object)


            if originalObject:
                if bhObject:
                    originalObject.merge_entry(bhObject)
                else:
                    bhObject = BloodHoundObject(object)
                    originalObject.merge_entry(bhObject)
            elif bhObject:
                target_list.append(bhObject)
                if not isinstance(bhObject, BloodHoundDomainTrust): # trusts don't have SIDs
                    self.add_object_to_maps(bhObject)


    def add_object_to_maps(self, object:BloodHoundObject):
        if object.ObjectIdentifier:
            self.SID_MAP[object.ObjectIdentifier] = object

        if ADDS.AT_DISTINGUISHEDNAME in object.Properties:
           self.DN_MAP[object.Properties[ADDS.AT_DISTINGUISHEDNAME]] = object


    def add_domain(self, object:BloodHoundObject):
        if ADDS.AT_DISTINGUISHEDNAME in object.Properties and object.ObjectIdentifier:
            dn = object.Properties[ADDS.AT_DISTINGUISHEDNAME]
            dc = BloodHoundObject.get_domain_component(dn.upper())
            if dc not in self.DOMAIN_MAP:
                self.DOMAIN_MAP[dc] = object.ObjectIdentifier


    def retrieve_object(self, dn=None, sid=None):
        if dn:
            if dn in self.DN_MAP:
                return self.DN_MAP[dn]

        if sid:
            if sid in self.SID_MAP:
                return self.SID_MAP[sid]

        return None


    def recalculate_sid(self, object:BloodHoundObject):
        if 'distinguishedname' in object.Properties:
            # check for wellknown sid
            if object.ObjectIdentifier in ADUtils.WELLKNOWN_SIDS:
                object.Properties['domainsid'] = self.DOMAIN_MAP.get(
                    BloodHoundObject.get_domain_component(object.Properties['distinguishedname']),
                    f"S-????"
                )
                object.ObjectIdentifier = BloodHoundObject.get_sid(object.ObjectIdentifier, object.Properties['distinguishedname'])


    def build_relation(self, object, sid, relation, acetype='', inherited=False):
        if acetype != '':
            raise ValueError("BH 4.0 incompatible output called")

        PrincipalSid = BloodHoundObject.get_sid(sid, object.Properties["distinguishedname"])

        if sid in self.SID_MAP:
            PrincipalType = self.SID_MAP[sid]._entry_type
        elif sid in ADUtils.WELLKNOWN_SIDS:
            PrincipalType = ADUtils.WELLKNOWN_SIDS[sid][1].title()
        else:
            PrincipalType = "Unknown"

        return {'RightName': relation, 'PrincipalSID': PrincipalSid, 'IsInherited': inherited, 'PrincipalType': PrincipalType }

    def calculate_contained(self, object):

        if object._entry_type == "Domain":
            return

        dn = object.Properties['distinguishedname']
        start = dn.find(',') + 1
        contained_dn = dn[start:]
        start_contained = contained_dn[0:2]
        type_contained = ""
        id_contained = None

        match start_contained:
            case "CN":
                if contained_dn.startswith("CN=BUILTIN"):
                    id_contained = "S-1-5-32"
                    type_contained = "Domain"
                else:
                    for cn in self.containers:
                        if cn.Properties["distinguishedname"] == contained_dn:
                            id_contained = cn.ObjectIdentifier
                            type_contained = "Container"
                    if type_contained == "":
                        for obj in self.unknown_objects:
                            if str(obj.get('distinguishedname')).upper() == contained_dn:
                                id_contained = obj.get("objectguid").upper()
                                match obj.get('objectclass'):
                                    case 'top, NTDSService':
                                        type_contained = "Base"
                                    case 'top, container':
                                        type_contained = "Container"
                                    case 'top, configuration':
                                        type_contained = "Configuration"
            case "OU":
                type_contained = "OU"
                for ou in self.ous:
                    if ou.Properties["distinguishedname"] == contained_dn:
                        id_contained = ou.ObjectIdentifier
            case "DC":
                type_contained = "Domain"
                for domain in self.domains:
                    if domain.Properties["distinguishedname"] == contained_dn:
                        id_contained = domain.ObjectIdentifier
            case _:
                return

        if type_contained == "":
            return
        else:
            #
            # We've identified the containing object, set prop on the contained object
            #
            object.ContainedBy = {"ObjectIdentifier":id_contained, "ObjectType":type_contained}

    def process(self):
        all_objects = self.users + self.groups + self.computers + self.domains + self.ous + self.gpos + self.containers \
                        + self.aiacas + self.rootcas + self.enterprisecas + self.certtemplates + self.issuancepolicies \
                        + self.ntauthstores

        total_objects = len(all_objects)

        num_parsed_relations = 0

        with console.status(f" [bold] Processed {num_parsed_relations} ACLs", spinner="aesthetic") as status:
            for i, object in enumerate(all_objects):
                self.recalculate_sid(object)
                self.calculate_contained(object)
                self.add_domainsid_prop(object)
                try:
                    num_parsed_relations += self.parse_acl(object)
                    status.update(f" [bold] Processing {num_parsed_relations} ACLs --- {i}/{total_objects} objects parsed")
                except:
                    #
                    # Catch the occasional error parinsing ACLs
                    #
                    continue

        logger.info("Parsed %d ACL relationships", num_parsed_relations)

        with console.status(" [bold] Creating default users", spinner="aesthetic"):
            self.write_default_users()
        logger.info("Created default users")

        with console.status(" [bold] Creating default groups", spinner="aesthetic"):
            self.write_default_groups()
        logger.info("Created default groups")

        with console.status(" [bold] Resolving group memberships", spinner="aesthetic"):
            self.resolve_group_members()
        logger.info("Resolved group memberships")

        with console.status(" [bold] Resolving delegation relationships", spinner="aesthetic"):
            self.resolve_delegation_targets()
        logger.info("Resolved delegation relationships")

        with console.status(" [bold] Resolving OU memberships", spinner="aesthetic"):
            self.resolve_ou_members()
        logger.info("Resolved OU memberships")

        with console.status(" [bold] Linking GPOs to OUs", spinner="aesthetic"):
            self.link_gpos()
        logger.info("Linked GPOs to OUs")

        if len(self.trusts) > 0:
            with console.status(" [bold] Resolving domain trusts", spinner="aesthetic"):
                self.resolve_domain_trusts()
            logger.info("Resolved domain trusts")

        if len(self.aiacas) > 0 or len(self.enterprisecas) > 0:
            with console.status(" [bold] Building CA certificate chains", spinner="aesthetic"):
                self.build_certificate_chains()
            logger.info("Built CA certificate chains")

        if len(self.enterprisecas) > 0:
            with console.status(" [bold] Resolving enabled templates per CA", spinner="aesthetic"):
                for ca in self.enterprisecas:
                    self.resolve_published_templates(ca)
            logger.info("Resolved enabled templates per CA")

            with console.status(" [bold] Resolving hosting computers of CAs", spinner="aesthetic"):
                for ca in self.enterprisecas:
                    self.resolve_hosting_computer(ca)
            logger.info("Resolved hosting computers of CAs")

        with console.status(" [bold] Assigning IP addresses to computers", spinner="aesthetic"):
            for host_fqdn in self.DNSNODE_MAP:
                computer_found = False

                # try to find computer object based on its dNSHostName attribute
                for computer in self.computers:
                    if computer.matches_dnshostname(host_fqdn):
                        computer_found = True
                        break

                # look for a computer with samaccountname host$ and the domain's sid
                if not computer_found:
                    host_parts = host_fqdn.split(".")
                    host_name = host_parts[0]
                    host_domain = ".".join(host_parts[1:])
                    dc = BloodHoundObject.get_dn(host_domain.upper())
                    domain_sid = self.DOMAIN_MAP.get(dc, None)

                    if domain_sid is not None:
                        for computer in self.computers:
                            if computer.matches_samaccountname(host_name) and computer.ObjectIdentifier.startswith(domain_sid):
                                computer_found = True
                                break

                if not computer_found:
                    continue

                computer.ipaddresses = list(self.DNSNODE_MAP[host_fqdn])

        logger.info("Assigned IP addresses to computers")

    def get_sid_from_name(self, name):
        for entry in self.SID_MAP:
            if(self.SID_MAP[entry].Properties["name"].lower() == name):
                return (entry, self.SID_MAP[entry]._entry_type)
        return (None,None)


    def resolve_delegation_targets(self):
        for object in self.computers + self.users:
            delegatehosts = object.AllowedToDelegate
            resolved_delegation_list = []
            for host in delegatehosts:
                try:
                    target = host.split('/')[1]
                except IndexError:
                    logger.warning('Invalid delegation target: %s', host)
                    continue
                try:
                    (sid, object_type) = self.get_sid_from_name(target.lower())
                    if sid and object_type:
                        delegation_entry = {"ObjectIdentifier": sid, "ObjectType": object_type}
                        logger.debug("Resolved delegation Host: %s, target: %s, %s", host, target, delegation_entry)
                        resolved_delegation_list.append(delegation_entry)
                    else:
                        continue
                except KeyError:
                    if '.' in target:
                        resolved_delegation_list.append(target.upper())
            if len(delegatehosts) > 0:
                object.Properties['allowedtodelegate'] = delegatehosts
                object.AllowedToDelegate = resolved_delegation_list


    def write_default_users(self):
        """
        Write built-in users to users.json file
        """

        for domain in self.domains:
            domainsid = domain.ObjectIdentifier
            domainname = domain.Properties.get('name', 'UNKNOWN').upper()
            logger.debug(
                "Adding default groups for %s%s[/] (%s)", ColorScheme.domain, domainname, domainsid,
                extra=OBJ_EXTRA_FMT
            )

            user = BloodHoundUser()
            user.AllowedToDelegate = []
            user.ObjectIdentifier = f"{domainname}-S-1-5-20"
            user.PrimaryGroupSID = None
            user.Properties = {
                "domain": domainname,
                "domainsid": domainsid,
                "name": f"NT AUTHORITY@{domainname}",
                ADDS.AT_DISTINGUISHEDNAME: f"CN=S-1-5-20,CN=FOREIGNSECURITYPRINCIPALS,{BloodHoundObject.get_dn(domainname)}"
            }
            user.Aces = []
            user.SPNTargets = []
            user.HasSIDHistory = []
            user.IsDeleted = False
            user.IsACLProtected = False

            self.users.append(user)

    def write_default_groups(self):
        """
        Put default groups in the groups.json file
        """

        # Domain controllers
        # TODO: Determine root domains
        # 1. Look for Enterprise Admins
        # 2. If no enterprise admins group, treat all as forest roots
        #rootdomains = [ domain for domain in self.domains ]
        for domain in self.domains:
            domainsid = domain.ObjectIdentifier
            domainname = domain.Properties.get('name', 'UNKNOWN').upper()
            logger.debug(
                "Adding default groups for %s%s[/] (%s)", ColorScheme.domain, domainname, domainsid,
                extra=OBJ_EXTRA_FMT
            )

            domain_controllers = [ computer for computer in self.computers if computer.PrimaryGroupSid.endswith('-516') ]

            group = BloodHoundGroup({})
            group.IsDeleted = False
            group.IsACLProtected = False
            group.ObjectIdentifier = f"{domainname}-S-1-5-9"
            group.Properties = {
                "domain": domainname.upper(),
                "name": f"ENTERPRISE DOMAIN CONTROLLERS@{domainname}",
                ADDS.AT_DISTINGUISHEDNAME: f"CN=S-1-5-9,CN=FOREIGNSECURITYPRINCIPALS,{BloodHoundObject.get_dn(domainname)}"
            }
            group.Members = []
            group.Aces = []

            for computer in domain_controllers:
                memberdata = {
                    "ObjectIdentifier": computer.ObjectIdentifier,
                    "ObjectType": "Computer"
                }
                group.Members.append(memberdata)
            self.groups.append(group)


            # Everyone
            evgroup = BloodHoundGroup({})

            evgroup.IsDeleted = False
            evgroup.IsACLProtected = False
            evgroup.ObjectIdentifier = f"{domainname}-S-1-1-0"
            evgroup.Properties = {
                "domain": domainname,
                "domainsid": domainsid,
                "name": f"EVERYONE@{domainname}",
                ADDS.AT_DISTINGUISHEDNAME: f"CN=S-1-5-0,CN=FOREIGNSECURITYPRINCIPALS,{BloodHoundObject.get_dn(domainname)}"
            }
            evgroup.Members = []
            evgroup.Aces = []

            self.groups.append(evgroup)

            # Authenticated users
            augroup = BloodHoundGroup({})

            augroup.IsDeleted = False
            augroup.IsACLProtected = False
            augroup.ObjectIdentifier = f"{domainname}-S-1-5-11"
            # Was this a mistake? augroup.ObjectIdentifier = "S-1-5-11"
            augroup.Properties = {
                    "domain": domainname,
                    "domainsid": domainsid,
                    "name": f"AUTHENTICATED USERS@{domainname}",
                    ADDS.AT_DISTINGUISHEDNAME: f"CN=S-1-5-11,CN=FOREIGNSECURITYPRINCIPALS,{BloodHoundObject.get_dn(domainname)}"
                }
            augroup.Members = []
            augroup.Aces = []

            self.groups.append(augroup)

            # Interactive
            iugroup = BloodHoundGroup({})

            iugroup.IsDeleted = False
            iugroup.IsACLProtected = False
            iugroup.ObjectIdentifier = f"{domainname}-S-1-5-4"
            iugroup.Properties = {
                    "domain": domainname,
                    "domainsid": domainsid,
                    "name": f"INTERACTIVE@{domainname}",
                    ADDS.AT_DISTINGUISHEDNAME: f"CN=S-1-5-4,CN=FOREIGNSECURITYPRINCIPALS,{BloodHoundObject.get_dn(domainname)}"
                }
            iugroup.Members = []
            iugroup.Aces = []

            self.groups.append(iugroup)

    def resolve_group_members(self):
        """Resolve group memberships for users, groups, and computers"""

        # Build reverse map to reduce algorithmic complexity
        dn_to_groups: Dict[str, List[BloodHoundGroup]] = {}

        for group in self.groups:
            group_dn = group.Properties.get(ADDS.AT_DISTINGUISHEDNAME, None)
            if group_dn is None:
                continue
            for member in group.MemberDNs:
                if member not in dn_to_groups:
                    dn_to_groups[member] = []
                dn_to_groups[member].append(group)

        # Single pass to resolve memberships for users, computers, subgroups
        for user in self.users:
            user_dn = user.Properties.get(ADDS.AT_DISTINGUISHEDNAME, None)
            if user_dn is None:
                continue
            if user_dn in dn_to_groups:
                for group in dn_to_groups[user_dn]:
                    group.add_group_member(user, "User")
                    logger.debug(
                        "Resolved %s%s[/] as member of %s%s[/]",
                        ColorScheme.user, user.Properties['name'],
                        ColorScheme.group, group.Properties['name'],
                        extra=OBJ_EXTRA_FMT
                    )

        for computer in self.computers:
            computer_dn = computer.Properties.get(ADDS.AT_DISTINGUISHEDNAME, None)
            if computer_dn is None:
                continue
            if computer_dn in dn_to_groups:
                for group in dn_to_groups[computer_dn]:
                    group.add_group_member(computer, "Computer")
                    logger.debug(
                        "Resolved %s%s[/] as member of %s%s[/]",
                        ColorScheme.computer, computer.Properties['name'],
                        ColorScheme.group, group.Properties['name'],
                        extra=OBJ_EXTRA_FMT
                    )


        for subgroup in self.groups:
            subgroup_dn = subgroup.Properties.get(ADDS.AT_DISTINGUISHEDNAME, None)
            if subgroup_dn is None:
                continue
            if subgroup_dn in dn_to_groups:
                for group in dn_to_groups[subgroup_dn]:
                    group.add_group_member(subgroup, "Group")
                    logger.debug(
                        "Resolved %s%s[/] as nested member of %s%s[/]",
                        ColorScheme.group, subgroup.Properties['name'],
                        ColorScheme.group, group.Properties['name'],
                        extra=OBJ_EXTRA_FMT
                    )

    # TODO: Algorithm can be optimized
    def resolve_ou_members(self):
        """Resolve OU memberships for users, groups, computers, and nested OUs"""
        for user in self.users:
            ou = self._resolve_object_ou(user)
            if ou is not None:
                ou.add_ou_member(user, "User")
                logger.debug(
                    "Identified %s%s[/] as within OU %s%s[/]",
                    ColorScheme.user, user.Properties['name'],
                    ColorScheme.ou, ou.Properties['name'],
                    extra=OBJ_EXTRA_FMT
                )

        for group in self.groups:
            ou = self._resolve_object_ou(group)
            if ou is not None:
                ou.add_ou_member(group, "Group")
                logger.debug(
                    "Identified %s%s[/] as within OU %s%s[/]",
                    ColorScheme.group, group.Properties['name'],
                    ColorScheme.ou, ou.Properties['name'],
                    extra=OBJ_EXTRA_FMT
                )

        for computer in self.computers:
            ou = self._resolve_object_ou(computer)
            if ou is not None:
                ou.add_ou_member(computer, "Computer")
                logger.debug(
                    "Identified %s%s[/] as within OU %s%s[/]",
                    ColorScheme.computer, computer.Properties['name'],
                    ColorScheme.ou, ou.Properties['name'],
                    extra=OBJ_EXTRA_FMT
                )

        for nested_ou in self.ous:
            ou = self._resolve_nested_ou(nested_ou)
            if ou is not None:
                ou.add_ou_member(nested_ou, "OU")
                logger.debug(
                    "Identified %s%s[/] as within OU %s%s[/]",
                    ColorScheme.ou, nested_ou.Properties['name'],
                    ColorScheme.ou, ou.Properties['name'],
                    extra=OBJ_EXTRA_FMT
                )

        sorted_ous = sorted(self.ous, key=lambda x: len(x.Properties['distinguishedname']), reverse=True)

        for ou in sorted_ous:
            affectedcomputers = []
            affectedusers = []
            for childobject in ou.ChildObjects:
                match childobject["ObjectType"] :
                    case "Computer":
                        affectedcomputers.append(childobject)
                    case "User":
                        affectedusers.append(childobject)
                    case "OU":
                        childid = childobject["ObjectIdentifier"]
                        for childou in sorted_ous:
                            if childou.ObjectIdentifier == childid:
                                affectedcomputers = affectedcomputers + childou.AffectedComputers
                                affectedusers = affectedusers + childou.AffectedUsers

            ou.AffectedComputers = affectedcomputers
            ou.AffectedUsers = affectedusers

        sorted_domains = sorted(self.domains, key=lambda x: len(x.Properties['distinguishedname']), reverse=True)

        for domain in sorted_domains:
            affectedcomputers = []
            affectedusers = []
            for childobject in domain.ChildObjects:
                match childobject["ObjectType"] :
                    case "Computer":
                        affectedcomputers.append(childobject)
                    case "User":
                        affectedusers.append(childobject)
                    case "OU":
                        childid = childobject["ObjectIdentifier"]
                        for childou in sorted_ous:
                            if childou.ObjectIdentifier == childid:
                                affectedcomputers = affectedcomputers + childou.AffectedComputers
                                affectedusers = affectedusers + childou.AffectedUsers

            domain.AffectedComputers = affectedcomputers
            domain.AffectedUsers = affectedusers


    def link_gpos(self):
        # BHCE appears to now require domainsid prop on GPOs
        for gpo in self.gpos:
            self.add_domainsid_prop(gpo)

        for object in self.ous + self.domains:
            if object._entry_type == 'OU':
                self.add_domainsid_prop(object) # since OUs don't have a SID to get a domainsid from

            for gplink in object.GPLinks:
                if gplink[0] in self.DN_MAP:
                    gpo = self.DN_MAP[gplink[0]]
                    object.add_linked_gpo(gpo, gplink[1])

                    if object._entry_type == 'Domain':
                       logger.debug(
                           "Linked %s%s[/] to domain %s%s[/]",
                           ColorScheme.gpo, gpo.Properties['name'],
                           ColorScheme.domain, object.Properties['name'],
                           extra=OBJ_EXTRA_FMT
                       )
                    else:
                        logger.debug(
                            "Linked %s%s[/] to OU %s%s[/]",
                            ColorScheme.gpo, gpo.Properties['name'],
                            ColorScheme.ou, object.Properties['name'],
                            extra=OBJ_EXTRA_FMT
                        )

    def resolve_domain_trusts(self):
        """Resolve trust relationships between domains"""
        for trust in self.trusts:
            if trust.TrustProperties is not None:
                # Start by trying to add the target domain's sid if we have it
                target_domain_dn = ADUtils.domain2ldap(trust.TrustProperties['TargetDomainName'])
                if target_domain_dn in self.DOMAIN_MAP:
                    trust.TrustProperties['TargetDomainSid'] = self.DOMAIN_MAP[target_domain_dn]

                # Append the trust dict to the origin domain's trust list
                if trust.LocalDomainDn in self.DOMAIN_MAP:
                    for domain in self.domains:
                        if trust.LocalDomainDn == domain.Properties['distinguishedname']:
                            # don't add trust relationships more than once!
                            if (not any(
                                prior['TargetDomainName'] == trust.TrustProperties['TargetDomainName']
                                for prior in domain.Trusts)
                            ):
                                domain.Trusts.append(trust.TrustProperties)
                            break


    def add_domainsid_prop(self, item):
        """Add the domain SID property to the object. Assumes DOMAIN_MAP is populated."""
        dc = BloodHoundObject.get_domain_component(item.Properties["distinguishedname"])
        if dc in self.DOMAIN_MAP:
            item.Properties["domainsid"] = self.DOMAIN_MAP[dc]

    def resolve_trust_relationships(self):
        pass

    def resolve_published_templates(self, entry:BloodHoundEnterpriseCA):
        if hasattr(entry, 'CertTemplates') and entry.CertTemplates:
            for template_name in entry.CertTemplates :
                for template in self.certtemplates:
                    if template.Properties['name'].split('@')[0].lower() == template_name.lower() \
                    and template.Properties['domain'] == entry.Properties['domain']:
                        entry.EnabledCertTemplates.append({"ObjectIdentifier": template.ObjectIdentifier.upper(), "ObjectType": "CertTemplate"})

    def resolve_hosting_computer(self, ca:BloodHoundEnterpriseCA):
        if 'dnshostname' in ca.Properties:
            hostname = ca.Properties['dnshostname']
            for comp in self.computers:
                if comp.matches_dnshostname(hostname):
                    ca.HostingComputer = comp.ObjectIdentifier
                    logger.debug(f"Resolved CA hosting computer: {hostname} to {ca.HostingComputer}")
                    return
            logger.warning(f"Could not resolve CA hosting computer: {hostname}")

    def parse_acl(self, entry:BloodHoundObject):
        """
        Parse the nTSecurityDescriptor attribute of an AD object and extract BloodHound
        relationships

        Returns int: number of relations parsed
        """
        if not entry.RawAces:
            return 0

        try:
            value = base64.b64decode(entry.RawAces)
        except Exception as e:
            logger.warning(
                "Error base64 decoding nTSecurityDescriptor attribute on %s %s: %s",
                entry._entry_type, entry.Properties.get('name', 'UNKNOWN'), e
            )
            return 0

        if not value:
            return 0
        sd = SecurityDescriptor(BytesIO(value))
        # Check for protected DACL flag
        entry.IsACLProtected = sd.has_control(sd.PD)
        relations = []

        # Parse owner
        osid = str(sd.owner_sid)
        ignoresids = ["S-1-3-0", "S-1-5-18", "S-1-5-10"]
        # Ignore Creator Owner or Local System
        if osid not in ignoresids:
            relations.append(self.build_relation(entry, osid, 'Owns', inherited=False))
        for ace_object in sd.dacl.aces:
            if ace_object.ace.AceType != 0x05 and ace_object.ace.AceType != 0x00:
                # These are the only two aces we care about currently
                #logger.debug('Don\'t care about acetype %d', ace_object.ace.AceType)
                continue
            # Check if sid is ignored
            sid = str(ace_object.acedata.sid)
            # Ignore Creator Owner or Local System
            if sid in ignoresids:
                continue
            if ace_object.ace.AceType == 0x05:
                is_inherited = ace_object.has_flag(ACE.INHERITED_ACE)
                # ACCESS_ALLOWED_OBJECT_ACE
                if not ace_object.has_flag(ACE.INHERITED_ACE) and ace_object.has_flag(ACE.INHERIT_ONLY_ACE):
                    # ACE is set on this object, but only inherited, so not applicable to us
                    continue

                # Check if the ACE has restrictions on object type (inherited case)
                if ace_object.has_flag(ACE.INHERITED_ACE) \
                    and ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_INHERITED_OBJECT_TYPE_PRESENT):
                    # Verify if the ACE applies to this object typ
                    try:
                        if not ace_applies(ace_object.acedata.get_inherited_object_type().lower(), entry._entry_type, self.ObjectTypeGuidMap):
                            continue
                    except KeyError:
                        pass
                mask = ace_object.acedata.mask
                # Now the magic, we have to check all the rights BloodHound cares about

                # Check generic access masks first
                if mask.has_priv(ACCESS_MASK.GENERIC_ALL) or mask.has_priv(ACCESS_MASK.WRITE_DACL) \
                    or mask.has_priv(ACCESS_MASK.WRITE_OWNER) or mask.has_priv(ACCESS_MASK.GENERIC_WRITE):
                    # For all generic rights we should check if it applies to our object type

                    try:
                        if ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT) \
                            and not ace_applies(ace_object.acedata.get_object_type().lower(), entry._entry_type, self.ObjectTypeGuidMap):
                            # If it does not apply, break out of the loop here in order to
                            # avoid individual rights firing later on
                            continue
                    except KeyError:
                        pass

                    # Check from high to low, ignore lower privs which may also match the bitmask,
                    # even though this shouldn't happen since we check for exact matches currently
                    if mask.has_priv(ACCESS_MASK.GENERIC_ALL):
                        # Report this as LAPS rights if it's a computer object AND laps is enabled

                        if entry._entry_type.lower() == 'computer' and \
                        ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT) and \
                        'haslaps' in entry.Properties and \
                        'ms-mcs-admpwd' in self.ObjectTypeGuidMap:
                            if ace_object.acedata.get_object_type().lower() == self.ObjectTypeGuidMap['ms-mcs-admpwd']:
                                relations.append(self.build_relation(entry, sid, 'ReadLAPSPassword', inherited=is_inherited))
                        else:
                            relations.append(self.build_relation(entry, sid, 'GenericAll', inherited=is_inherited))
                        continue

                    if mask.has_priv(ACCESS_MASK.GENERIC_WRITE):
                        relations.append(self.build_relation(entry, sid, 'GenericWrite', inherited=is_inherited))
                        # Don't skip this if it's the domain object, since BloodHound reports duplicate
                        # rights as well, and this might influence some queries
                        if entry._entry_type.lower() != 'domain' and entry._entry_type.lower() != 'computer':
                            continue

                    # These are specific bitmasks so don't break the loop from here
                    if mask.has_priv(ACCESS_MASK.WRITE_DACL):
                        relations.append(self.build_relation(entry, sid, 'WriteDacl', inherited=is_inherited))

                    if mask.has_priv(ACCESS_MASK.WRITE_OWNER):
                        relations.append(self.build_relation(entry, sid, 'WriteOwner', inherited=is_inherited))

                # Property write privileges
                writeprivs = ace_object.acedata.mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_WRITE_PROP)
                if writeprivs:
                    # GenericWrite
                    if entry._entry_type.lower() in ['user', 'group', 'computer', 'gpo'] and not ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT):
                        relations.append(self.build_relation(entry, sid, 'GenericWrite', inherited=is_inherited))
                    if entry._entry_type.lower() == 'group' and can_write_property(ace_object, EXTRIGHTS_GUID_MAPPING['WriteMember']):
                        relations.append(self.build_relation(entry, sid, 'AddMember', '', inherited=is_inherited))
                    if entry._entry_type.lower() == 'computer' and can_write_property(ace_object, EXTRIGHTS_GUID_MAPPING['AllowedToAct']):
                        relations.append(self.build_relation(entry, sid, 'AddAllowedToAct', '', inherited=is_inherited))
                    # Property set, but ignore Domain Admins since they already have enough privileges anyway
                    if entry._entry_type.lower() == 'computer' and can_write_property(ace_object, EXTRIGHTS_GUID_MAPPING['UserAccountRestrictionsSet']) and not sid.endswith('-512'):
                        relations.append(self.build_relation(entry, sid, 'WriteAccountRestrictions', '', inherited=is_inherited))

                    # Since 4.0
                    # Key credential link property write rights
                    if entry._entry_type.lower() in ['user', 'computer'] and ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT) \
                    and 'ms-ds-key-credential-link' in self.ObjectTypeGuidMap and ace_object.acedata.get_object_type().lower() == self.ObjectTypeGuidMap['ms-ds-key-credential-link']:
                        relations.append(self.build_relation(entry, sid, 'AddKeyCredentialLink', inherited=is_inherited))

                    # ServicePrincipalName property write rights (exclude generic rights)
                    if entry._entry_type.lower() == 'user' and ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT) \
                    and ace_object.acedata.get_object_type().lower() == 'f3a64788-5306-11d1-a9c5-0000f80367c1':
                        relations.append(self.build_relation(entry, sid, 'WriteSPN', inherited=is_inherited))

                    #
                    # Rights for certificate templates
                    #
                    if entry._entry_type.lower() == 'pki template' and ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT) \
                    and ace_object.acedata.get_object_type().lower() == 'ea1dddc4-60ff-416e-8cc0-17cee534bce7':
                        relations.append(self.build_relation(entry, sid, 'WritePKINameFlag', inherited=is_inherited))

                    if entry._entry_type.lower() == 'pki template' and ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT) \
                    and ace_object.acedata.get_object_type().lower() == 'd15ef7d8-f226-46db-ae79-b34e560bd12c':
                        relations.append(self.build_relation(entry, sid, 'WritePKIEnrollmentFlag', inherited=is_inherited))

                elif ace_object.acedata.mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_SELF):
                    # Self add - since 4.0
                    if entry._entry_type.lower() == 'group' and ace_object.acedata.data.ObjectType == EXTRIGHTS_GUID_MAPPING['WriteMember']:
                        relations.append(self.build_relation(entry, sid, 'AddSelf', '', inherited=is_inherited))

                # Property read privileges
                if ace_object.acedata.mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_READ_PROP):
                    if entry._entry_type.lower() == 'computer' and \
                    ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT) and \
                    'haslaps' in entry.Properties and \
                    'ms-mcs-admpwd' in self.ObjectTypeGuidMap:
                        if ace_object.acedata.get_object_type().lower() == self.ObjectTypeGuidMap['ms-mcs-admpwd']:
                           relations.append(self.build_relation(entry, sid, 'ReadLAPSPassword', inherited=is_inherited))

                # Extended rights
                control_access = ace_object.acedata.mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_CONTROL_ACCESS)
                if control_access:
                    # All Extended
                    if entry._entry_type.lower() in ['user', 'domain'] and not ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT):
                        relations.append(self.build_relation(entry, sid, 'AllExtendedRights', '', inherited=is_inherited))
                    if entry._entry_type.lower() == 'computer' and not ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT):
                        relations.append(self.build_relation(entry, sid, 'AllExtendedRights', '', inherited=is_inherited))
                    if entry._entry_type.lower() == 'domain' and has_extended_right(ace_object, EXTRIGHTS_GUID_MAPPING['GetChanges']):
                        relations.append(self.build_relation(entry, sid, 'GetChanges', '', inherited=is_inherited))
                    if entry._entry_type.lower() == 'domain' and has_extended_right(ace_object, EXTRIGHTS_GUID_MAPPING['GetChangesAll']):
                        relations.append(self.build_relation(entry, sid, 'GetChangesAll', '', inherited=is_inherited))
                    if entry._entry_type.lower() == 'domain' and has_extended_right(ace_object, EXTRIGHTS_GUID_MAPPING['GetChangesInFilteredSet']):
                        relations.append(self.build_relation(entry, sid, 'GetChangesInFilteredSet', '', inherited=is_inherited))
                    if entry._entry_type.lower() == 'user' and has_extended_right(ace_object, EXTRIGHTS_GUID_MAPPING['UserForceChangePassword']):
                        relations.append(self.build_relation(entry, sid, 'ForceChangePassword', '', inherited=is_inherited))

                    #
                    # Rights for certificate templates
                    #
                    if entry._entry_type.lower() in ['pki template', 'enterpriseca'] and has_extended_right(ace_object, EXTRIGHTS_GUID_MAPPING['Enroll']):
                        relations.append(self.build_relation(entry, sid, 'Enroll', '', inherited=is_inherited))


            if ace_object.ace.AceType == 0x00:
                is_inherited = ace_object.has_flag(ACE.INHERITED_ACE)
                mask = ace_object.acedata.mask
                # ACCESS_ALLOWED_ACE
                if not ace_object.has_flag(ACE.INHERITED_ACE) and ace_object.has_flag(ACE.INHERIT_ONLY_ACE):
                    # ACE is set on this object, but only inherited, so not applicable to us
                    continue

                if mask.has_priv(ACCESS_MASK.GENERIC_ALL):
                    # Generic all includes all other rights, so skip from here
                    relations.append(self.build_relation(entry, sid, 'GenericAll', inherited=is_inherited))
                    continue

                if mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_WRITE_PROP):
                    # Genericwrite is only for properties, don't skip after
                    if entry._entry_type.lower() in ['user', 'group', 'computer', 'gpo']:
                        relations.append(self.build_relation(entry, sid, 'GenericWrite', inherited=is_inherited))

                if mask.has_priv(ACCESS_MASK.WRITE_OWNER):
                    relations.append(self.build_relation(entry, sid, 'WriteOwner', inherited=is_inherited))

                # For users and domain, check extended rights
                if entry._entry_type.lower() in ['user', 'domain'] and mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_CONTROL_ACCESS):
                    relations.append(self.build_relation(entry, sid, 'AllExtendedRights', '', inherited=is_inherited))

                if entry._entry_type.lower() == 'computer' and mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_CONTROL_ACCESS) and \
                sid != "S-1-5-32-544" and not sid.endswith('-512'):
                    relations.append(self.build_relation(entry, sid, 'AllExtendedRights', '', inherited=is_inherited))

                if mask.has_priv(ACCESS_MASK.WRITE_DACL):
                    relations.append(self.build_relation(entry, sid, 'WriteDacl', inherited=is_inherited))

        entry.Aces = relations

        return len(relations)


    def _is_member_of(self, member: BloodHoundObject, group: BloodHoundGroup):
        if ADDS.AT_DISTINGUISHEDNAME in member.Properties:
            if member.Properties["distinguishedname"] in group.MemberDNs:
                return True

        # BRc4 does not use DN in groups' member attribute, so we have
        # to check membership from the other side of the relationship
        if ADDS.AT_DISTINGUISHEDNAME in group.Properties:
            if group.Properties["distinguishedname"] in member.MemberOfDNs:
                return True

        if member.PrimaryGroupSid == group.ObjectIdentifier:
            return True

        return False


    def _is_nested_group(self, subgroup, group):
        if ADDS.AT_DISTINGUISHEDNAME in subgroup.Properties:
            if subgroup.Properties["distinguishedname"] in group.MemberDNs:
                return True

        if ADDS.AT_DISTINGUISHEDNAME in group.Properties:
            # BRc4 does not use DN in groups' member attribute, so we have
            # to check membership from the other side of the relationship
            if group.Properties["distinguishedname"] in subgroup.MemberOfDNs:
                return True

        return False


    def _resolve_object_ou(self, item):
        if "OU=" in item.Properties["distinguishedname"]:
            target_ou = "OU=" + item.Properties["distinguishedname"].split("OU=", 1)[1]
            for ou in self.ous:
                if ou.Properties["distinguishedname"] == target_ou:
                    return ou
        return None


    def _resolve_nested_ou(self, nested_ou):
        dn = nested_ou.Properties["distinguishedname"]
        # else is top-level OU
        if len(dn.split("OU=")) > 2:
            target_ou = "OU=" + dn.split("OU=", 2)[2]
            for ou in self.ous:
                if ou.Properties["distinguishedname"] == target_ou:
                    return ou
        else:
            dc = BloodHoundObject.get_domain_component(dn)
            for domain in self.domains:
                if dc == domain.Properties[self.AT_DISTINGUISHEDNAME]:
                    return domain
        return None


    def _lookup_known_sid(self, object, sid):
        known_sid_type = ADUtils.WELLKNOWN_SIDS[sid][1]
        if known_sid_type == "USER":
            bhObject = BloodHoundUser(object)
            target_list = self.users
        elif known_sid_type == "COMPUTER":
            bhObject = BloodHoundComputer(object)
            target_list = self.computers
        elif known_sid_type == "GROUP":
            bhObject = BloodHoundGroup(object)
            target_list = self.groups
        bhObject.Properties["name"] = ADUtils.WELLKNOWN_SIDS[sid][0].upper()
        return bhObject, target_list


    def _get_domain_sid_from_netbios_name(self, nbtns_domain):
        if nbtns_domain in self.CROSSREF_MAP:
            dn = self.CROSSREF_MAP[nbtns_domain].distinguishedName
            if dn in self.DOMAIN_MAP:
                return self.DOMAIN_MAP[dn]
        return None


    # process local group memberships and sessions
    def process_local_objects(self, broker):
        for computer in self.computers:
            self.process_privileged_sessions(broker.privileged_sessions, computer)
            self.process_registry_sessions(broker.registry_sessions, computer)
            self.process_sessions(broker.sessions, computer)
            self.process_local_group_memberships(broker.local_group_memberships, computer)


        if len(broker.local_group_memberships) > 0:
            logger.info("Resolved local group memberships")

        if len(broker.privileged_sessions) > 0 \
            or len(broker.registry_sessions) > 0 \
            or len(broker.sessions) > 0:

            logger.info("Resolved sessions")


    # correlate privileged sessions to BH Computer objects
    def process_privileged_sessions(self, privileged_sessions, computer_object):
        for session in privileged_sessions:
            # skip sessions that have already been matched to a computer object
            if session.matched:
                continue

            computer_found = False

            # first we'll try to directly match the session host's dns name to a
            # computer object's dNSHostName attribute
            if session.host_fqdn is not None:
                if computer_object.matches_dnshostname(session.host_fqdn):
                    computer_found = True

            # second we'll check to see if the host's DNS domain is a known domain
            # converting the host DNS suffix to a domain component could be problematic?
            if session.host_domain is not None and not computer_found:
                dc = BloodHoundObject.get_dn(session.host_domain.upper())
                domain_sid = self.DOMAIN_MAP.get(dc, None)

                # if we have the domain, check for a computer with samaccountname host$
                # and the domain's sid
                if domain_sid is not None:
                    if computer_object.matches_samaccountname(session.host_name) and \
                        computer_object.ObjectIdentifier.startswith(domain_sid):

                        computer_found = True

            # if we've got the computer, then try to find the user's SID
            if not computer_found:
                continue

            match_users = [user for user in self.users if user.Properties.get('samaccountname', '').lower() == session.user.lower()]
            if len(match_users) > 1:
                logger.warning("Multiple users with sAMAccountName %s found for privileged session",
                               ColorScheme.user + session.user + "[/]")
                # TODO: implement NetBIOS domain name handling
                continue
            elif len(match_users) == 1:
                user_sid = match_users[0].ObjectIdentifier
                computer_object.add_session(user_sid, "privileged")
                logger.debug(
                    "Resolved privileged session on %s",
                    ColorScheme.computer + computer_object.Properties['name'] + "[/]",
                    extra=OBJ_EXTRA_FMT
                )

    def process_registry_sessions(self, registry_sessions, computer_object):
        """Correlate registry sessions to a computer object."""
        for session in registry_sessions:
            # skip sessions that have already been matched to a computer object
            if session.matched:
                continue

            # first we'll try to directly match the session host's dns name to a
            # computer object's dNSHostName attribute
            if session.host_fqdn is not None:
                if computer_object.matches_dnshostname(session.host_name):
                    session.matched = True
                    computer_object.add_session(session.user_sid, "registry")
                    logger.debug(
                        "Resolved registry session on %s via dNSHostName match",
                        ColorScheme.computer + computer_object.Properties['name'] + "[/]",
                        extra=OBJ_EXTRA_FMT
                    )
                    continue

            # second we'll check to see if the host's DNS domain is a known domain
            # converting the host DNS suffix to a domain component could be problematic?
            if session.host_domain is not None:
                dc = BloodHoundObject.get_dn(session.host_domain.upper())
                domain_sid = self.DOMAIN_MAP.get(dc, None)

                # if we have the domain, check for a computer with samaccountname host$
                # and the domain's sid
                if domain_sid is not None:
                    if computer_object.matches_samaccountname(session.host_name) and \
                        computer_object.ObjectIdentifier.startswith(domain_sid):

                        session.matched = True
                        computer_object.add_session(session.user_sid, "registry")
                        logger.debug(
                            "Resolved registry session on %s via domain + sAMAccountName match",
                            ColorScheme.computer + computer_object.Properties['name'] + "[/]",
                            extra=OBJ_EXTRA_FMT
                        )
                        continue

            # if we don't have the host domain/FQDN from the session, we just try to match samaccountname
            # this is probably only error prone if there multiple domains with the same hostname
            elif computer_object.matches_samaccountname(session.host_name):
                session.matched = True
                computer_object.add_session(session.user_sid, "registry")
                logger.debug(
                    "Resolved registry session on %s via fuzzy sAMAccountName match",
                    ColorScheme.computer + computer_object.Properties['name'] + "[/]",
                    extra=OBJ_EXTRA_FMT
                )


    # TODO: Algorithm can be optimized
    def process_sessions(self, sessions, computer_object):
        """Correlate sessions to a computer object."""
        for session in sessions:
            # skip sessions that have already been matched to a computer object
            if session.matched:
                continue

            computer_found = False

            # case 1: we have the host's DNS name
            if session.ptr_record is not None:

                # first try to match dNSHostName
                if computer_object.matches_dnshostname(session.ptr_record):
                    computer_found = True

                # if that doesn't work, try to match the host's domain
                if session.computer_domain is not None and not computer_found:
                    dc = BloodHoundObject.get_dn(session.computer_domain.upper())
                    domain_sid = self.DOMAIN_MAP.get(dc, None)

                    # if we have the domain, check for a computer with samaccountname host$
                    # and the domain's sid
                    if domain_sid is not None:
                        if computer_object.matches_samaccountname(session.computer_name) and \
                            computer_object.ObjectIdentifier.startswith(domain_sid):

                            computer_found = True

            # case 2: we have the NETBIOS host and domain name
            elif session.computer_netbios_domain is not None:
                domain_sid = self._get_domain_sid_from_netbios_name(session.computer_netbios_domain)
                if domain_sid is not None:
                    if computer_object.matches_samaccountname(session.computer_name) and computer_object.ObjectIdentifier.startswith(domain_sid):
                        computer_found = True

            # if we've got the computer, then try to find the user's SID
            if not computer_found:
                continue

            match_users = [user for user in self.users if user.Properties.get('samaccountname', '').lower() == session.username.lower()]
            if len(match_users) > 1:
                logger.warning(
                    "Multiple users with sAMAccountName %s found for session",
                    ColorScheme.user + session.user + "[/]"
                )
                # TODO: implement NetBIOS domain name handling
                continue
            elif len(match_users) == 1:
                user_sid = match_users[0].ObjectIdentifier
                computer_object.add_session(user_sid, "session")
                logger.debug(
                    "Resolved session on %s",
                    ColorScheme.computer + computer_object.Properties['name'] + "[/]",
                    extra=OBJ_EXTRA_FMT
                )


    # correlate local group memberships to BH Computer objects
    def process_local_group_memberships(self, local_group_memberships, computer_object):
        for member in local_group_memberships:
            # skip memberships that have already been matched to a computer object
            if member.matched:
                continue

            computer_found = False

            # first we'll try to directly match the session host's dns name to a
            # computer object's dNSHostName attribute
            if member.host_fqdn is not None:
                if computer_object.matches_dnshostname(member.host_fqdn):
                    computer_found = True


            # second we'll check to see if the host's DNS domain is a known domain
            if member.host_domain is not None and not computer_found:
                dc = BloodHoundObject.get_dn(member.host_domain.upper())
                domain_sid = self.DOMAIN_MAP.get(dc, None)

                # if we have the domain, check for a computer with samaccountname host$
                # and the domain's sid
                if domain_sid is not None:
                    if computer_object.matches_samaccountname(member.host_name) and \
                        computer_object.ObjectIdentifier.startswith(domain_sid):

                        computer_found = True

            # if we've got the computer, then check the sid before submitting
            if not computer_found:
                continue

            color = ColorScheme.user if member.member_sid_type == "User" else ColorScheme.group

            computer_object.add_local_group_member(member.member_sid, member.member_sid_type, member.group)
            logger.debug(
                "Resolved %s as member of %s on %s",
                color + member.member + "[/]",
                ColorScheme.group + member.group + "[/]",
                ColorScheme.computer + computer_object.Properties['name'] + "[/]",
                extra=OBJ_EXTRA_FMT
            )


    @staticmethod
    def find_issuer_ca(start_ca_obj, all_ca_obj):
        for potential_issuer in all_ca_obj:
            if start_ca_obj.x509Certificate['issuer'] == potential_issuer.x509Certificate['subject']:
                return potential_issuer
        return None


    @staticmethod
    def build_certificate_chain(start_ca_obj, all_ca_obj):
        chain = [start_ca_obj]
        current_ca = start_ca_obj

        while True:
            if current_ca.x509Certificate is None:
                return None
            if current_ca.x509Certificate['subject'] == current_ca.x509Certificate['issuer']:
                # Found a self-signed certificate (root CA)
                break

            issuer_ca = ADDS.find_issuer_ca(start_ca_obj, all_ca_obj)
            if not issuer_ca:
                break
            chain.append(issuer_ca)

            if issuer_ca == current_ca:
                # Found a circular reference (potentially a stopgap solution)
                break
            current_ca = issuer_ca

        return [cert.Properties['certthumbprint'] for cert in chain]

    def build_certificate_chains(self):
        for enterpriseca in self.enterprisecas:
            enterpriseca.Properties['certchain'] = ADDS.build_certificate_chain(enterpriseca, self.enterprisecas+self.rootcas)

        for aiaca in self.aiacas:
            aiaca.Properties['certchain'] = ADDS.build_certificate_chain(aiaca, self.aiacas)
