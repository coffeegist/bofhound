import calendar
import hashlib
import base64
from asn1crypto import x509
from datetime import datetime
from bloodhound.enumeration.acls import SecurityDescriptor, ACL, ACCESS_ALLOWED_ACE, ACCESS_MASK, ACE, ACCESS_ALLOWED_OBJECT_ACE, has_extended_right, EXTRIGHTS_GUID_MAPPING, can_write_property, ace_applies
from bloodhound.ad.utils import ADUtils

from bofhound.logger import logger, OBJ_EXTRA_FMT, ColorScheme
from bofhound.ad.models.bloodhound_schema import BloodHoundSchema
from bofhound.ad.helpers import PropertiesLevel

# TODO: Move appropriate actions from this class to a super class of Users/Computers/maybe groups?


class BloodHoundObject():

    GUI_PROPERTIES = [
    ]

    COMMON_PROPERTIES = [
    ]

    NEVER_SHOW_PROPERTIES = [
        'ntsecuritydescriptor', 'serviceprincipalname'
    ]

    def __init__(self, object=None):
        self.ObjectIdentifier = None
        self.Aces = []
        self.RawAces = None
        self.Properties = {}

        if isinstance(object, dict):
            # Ensure all keys are lowercase
            for item in object.keys():
                self.Properties[item.lower()] = object[item]

            self.ObjectIdentifier = BloodHoundObject.get_sid(object.get('objectsid', None), object.get('distinguishedname', None))

            if 'distinguishedname' in object.keys():
                self.Properties["distinguishedname"] = object.get('distinguishedname', None).upper()

            self.__parse_whencreated(object)


    def get_primary_membership(self, object):
        """
        Construct primary membership from RID to SID (BloodHound 3.0 only)
        """
        try:
            primarygroupid = object.get('primarygroupid')
            return '%s-%s' % ('-'.join(object.get('objectsid').split('-')[:-1]), primarygroupid)
        except (TypeError, KeyError, AttributeError):
            # Doesn't have a primarygroupid, means it is probably a Group instead of a user
            return None


    def merge_entry(self, object, base_preference=False):
        """Merge the properties of another BloodHoundObject in with this one.

        Keyword arguments:
        object          -- the new object to merge (required)
        base_preference -- whether or not to prefer the base object. If true, self's properties could be overwritten (default False)
        """
        self_attributes = self.__dict__.keys()
        for attr, value in object.__dict__.items():
            if attr == 'Properties':
                for k, v in getattr(object, attr).items():
                    if not k in getattr(self, attr).keys():
                        getattr(self, attr)[k] = v
                    else:
                        if k == 'distinguishedname':
                            if not getattr(self, attr)[k]:
                                getattr(self, attr)[k] = v
                        if not base_preference:
                            if getattr(object, attr).get(k, None):
                                getattr(self, attr)[k] = v

            elif not attr in self_attributes:
                setattr(self, attr, value)
            else:
                if attr == 'ObjectIdentifier':
                    if not self.ObjectIdentifier:
                        setattr(self, attr, value)

                if not base_preference:
                    if getattr(object, attr):
                        setattr(self, attr, value)
    


    def get_distinguished_name(self):
        try:
            return self.Properties['distinguishedname'].upper()
        except KeyError:
            return None


    def get_property(self, property):
        try:
            return self.Properties[property]
        except KeyError:
            return None


    def to_json(self, properties_level):
        data = {
            "Properties": {}
        }

        match properties_level:
            case PropertiesLevel.Standard:
                for property in self.Properties.keys():
                    if property in self.GUI_PROPERTIES \
                        and property not in self.NEVER_SHOW_PROPERTIES:
                        data["Properties"][property] = self.Properties[property]
            case PropertiesLevel.Member:
                for property in self.Properties.keys():
                    if (property in self.COMMON_PROPERTIES or property in self.GUI_PROPERTIES) \
                        and property not in self.NEVER_SHOW_PROPERTIES:
                        data["Properties"][property] = self.Properties[property]
            case PropertiesLevel.All:
                data["Properties"] = self.Properties

        return data


    def __parse_whencreated(self, object):
        whencreated = object.get('whencreated', 0)
        try:
            if not isinstance(whencreated, int):
                whencreated = calendar.timegm(datetime.strptime(whencreated, "%Y%m%d%H%M%S.0Z").timetuple())
            self.Properties['whencreated'] = whencreated
        except:
            self.Properties['whencreated'] = whencreated


    # used by Domains and OUs
    def add_linked_gpo(self, object, gp_link_options):
        enforced = False
        if gp_link_options == '2':
            enforced = True

        link = {
            "GUID": object.ObjectIdentifier,
            "IsEnforced": False
        }
        self.Links.append(link)


    # used by Domains and OUs
    def add_ou_member(self, object, object_type):
        member = {
            "ObjectIdentifier": object.ObjectIdentifier,
            "ObjectType": object_type
        }
        self.ChildObjects.append(member)


    @staticmethod
    def get_sid(sid, dn=None):
        if sid in ADUtils.WELLKNOWN_SIDS:
            domain = ADUtils.ldap2domain(dn).upper()
            PrincipalSid = f'{domain}-{sid}'
        else:
            PrincipalSid = sid

        return PrincipalSid


    # Should probably move to ADDS?
    @staticmethod
    def get_domain_component(dn):
        dc = ''
        for component in dn.split(','):
            if component.startswith('DC='):
                dc += f"{component},"
        return dc[:-1]


    @staticmethod
    def get_dn(domain):
        components = domain.split('.')
        base = ''
        for comp in components:
            base += f',DC={comp}'
        
        return base[1:]
    
    
    @staticmethod
    def get_cn_from_dn(dn):
        for component in dn.split(',', 1):
            if component.startswith('CN='):
                return component[3:]
    
    #
    # for AIACAs, EnterpriseCAs, and RootCAs
    #
    def parse_cacertificate(self, object):
        certificate_b64 = object.get("cacertificate")
            
        certificate_byte_array = base64.b64decode(certificate_b64)
        
        #
        # thumbprint
        #
        thumbprint = hashlib.sha1(certificate_byte_array).hexdigest().upper()
        self.Properties['certthumbprint'] = thumbprint
        
        #
        # certname
        #
        certificate_byte_array = base64.b64decode(certificate_b64)
        ca_cert = x509.Certificate.load(certificate_byte_array)["tbs_certificate"]
        self.x509Certificate = ca_cert # set for post-processing
        self.Properties['certname'] = ca_cert['subject'].native.get('common_name', thumbprint)
        
        #
        # cert chain
        # not sure that Python libs offer a way to build the chain without access to the issuer cert like it seems SharpHound  does
        # https://github.com/BloodHoundAD/SharpHoundCommon/blob/ea6b097927c5bb795adb8589e9a843293d36ae37/src/CommonLib/Processors/LDAPPropertyProcessor.cs#L772
        # so we will have the build the chain manually in post-processing
        #
        self.Properties['certchain'] = []

        #
        # extensions (hasbasicconstraints, basicconstraintpathlength)
        #
        self.Properties['hasbasicconstraints'] = False
        self.Properties['basicconstraintpathlength'] = 0
        for ext in ca_cert['extensions']:
            if ext['extn_id'].native == 'basic_constraints':
                basic_constraints = ext['extn_value'].parsed
                if basic_constraints['path_len_constraint'].native is not None:
                    self.Properties['hasbasicconstraints'] = True
                    self.Properties['basicconstraintpathlength'] = basic_constraints['path_len_constraint'].native
                break

