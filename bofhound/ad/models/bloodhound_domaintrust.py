from bloodhound.ad.utils import ADUtils
from bloodhound.ad.trusts import ADDomainTrust
from impacket.ldap.ldaptypes import LDAP_SID

from bofhound.logger import logger, OBJ_EXTRA_FMT, ColorScheme
from bofhound.ad.models.bloodhound_object import BloodHoundObject
from bofhound.ad.helpers import TrustType, TrustDirection


class BloodHoundDomainTrust(object):
    
    def __init__(self, object):
        # Property for internal processing
        self.LocalDomainDn = ''

        # Property that holds final dict for domain JSON
        # {
        #     "TargetDomainName": "",
        #     "TargetDomainSid": "",
        #     "IsTransitive": "",
        #     "TrustDirection": "",
        #     "TrustType": "",
        #     "SidFilteringEnabled": ""
        # }
        self.TrustProperties = None

        if 'distinguishedname' in object.keys() and 'trustpartner' in object.keys() and \
            'trustdirection' in object.keys() and 'trusttype' in object.keys() and 'trustattributes' in object.keys() and \
            'securityidentifier' in object.keys():
            
            self.LocalDomainDn = BloodHoundObject.get_domain_component(object.get('distinguishedname')).upper()
            trust_partner = object.get('trustpartner').upper()
            domain = ADUtils.ldap2domain(object.get('distinguishedname')).upper()
            logger.debug(f'Reading trust relationship between {ColorScheme.domain}{domain}[/] and {ColorScheme.domain}{trust_partner}[/]', extra=OBJ_EXTRA_FMT)
            domainsid = LDAP_SID()
            domainsid.fromCanonical(object.get('securityidentifier'))
            trust = ADDomainTrust(trust_partner, int(object.get('trustdirection')), object.get('trusttype'), int(object.get('trustattributes')), domainsid.getData())
            self.TrustProperties = trust.to_output()

            # BHCE now wants trusttype and direction defined as string names instead of int values
            
            self.TrustProperties['TrustDirection'] = TrustDirection(self.TrustProperties['TrustDirection']).name
            self.TrustProperties['TrustType'] = TrustType(self.TrustProperties['TrustType']).name
