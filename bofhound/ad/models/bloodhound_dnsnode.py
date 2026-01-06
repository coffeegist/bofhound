from adidnsdump import dnsdump
from bofhound.logger import logger, OBJ_EXTRA_FMT, ColorScheme
import base64

class BloodHoundDnsNode(object):

    def __init__(self, object):
        self.distinguishedName = None
        self.ipaddresses = []
        self.name = None

        if 'dnsrecord' in object.keys() and 'name' in object.keys() and 'distinguishedname' in object.keys():
            dn = object.get('distinguishedname')
            self.distinguishedName = dn.upper()
            dn = dn.split(',')
            domain_name = dn[0].split('=')[1]
            domain_suffix = dn[1].split('=')[1]

            if domain_name in ['@', 'DomainDnsZones', 'ForestDnsZones'] or domain_suffix in ['RootDNSServers', '..TrustAnchors']:
                logger.debug(f"Ignoring dnsNode object {ColorScheme.dns}{self.distinguishedName}[/]", extra=OBJ_EXTRA_FMT)
                return

            if domain_suffix.endswith(".in-addr.arpa"):
                addr = domain_suffix.rstrip(".in-addr.arpa").split(".")
                addr.insert(0, object.get('name'))
                addr.reverse()
                self.ipaddresses.append('.'.join(addr))
            else:
                self.name = (object.get('name') + '.' + domain_suffix).lower()

            for b64dr in object.get('dnsrecord').split(', '):
                dr = dnsdump.DNS_RECORD(base64.b64decode(b64dr))
                if dr['Type'] == 1: # A
                    address =  dnsdump.DNS_RPC_RECORD_A(dr['Data'])
                    self.ipaddresses.append(address.formatCanonical())
                elif dr['Type'] == 28: # AAAA
                    address = dnsdump.DNS_RPC_RECORD_AAAA(dr['Data'])
                    self.ipaddresses.append(address.formatCanonical())
                elif dr['Type'] == 12: # PTR
                    address = dnsdump.DNS_RPC_RECORD_NODE_NAME(dr['Data'])
                    name = address[list(address.fields)[0]].toFqdn().rstrip('.')
                    if len(name.split('.')) == 1:
                        # not really correct, but useful first (stateless) approximization
                        self.name = '.'.join([name, dn[-2].split('=')[1], dn[-1].split('=')[1]]).lower()
                    else:
                        self.name = name.lower()

            if self.ipaddresses:
                logger.debug(f"Parsed dnsNode object {ColorScheme.dns}{self.distinguishedName}[/] {self.name} = {','.join(self.ipaddresses)}", extra=OBJ_EXTRA_FMT)

