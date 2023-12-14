from .models import LocalGroupMembership, LocalPrivilegedSession, LocalSession, LocalRegistrySession
from bofhound.parsers.shared_parsers import NetSessionBofParser, NetLoggedOnBofParser, NetLocalGroupBofParser, RegSessionBofParser


class LocalBroker:

    def __init__(self):
        self.privileged_sessions        = set()
        self.sessions                   = set()
        self.local_group_memberships    = set()
        self.registry_sessions          = set()


    # take in known domain sids so we can filter out local accounts 
    # and accounts with unknown domains
    def import_objects(self, objects, known_domain_sids):

        for object in objects:

            if object["ObjectType"] == NetLoggedOnBofParser.OBJECT_TYPE:
                priv_session = LocalPrivilegedSession(object)
                if priv_session.should_import():
                    self.privileged_sessions.add(priv_session)

            elif object["ObjectType"] == NetSessionBofParser.OBJECT_TYPE:
                session = LocalSession(object)
                if session.should_import():
                    self.sessions.add(session)
                    
            elif object["ObjectType"] == NetLocalGroupBofParser.OBJECT_TYPE:
                local_group_membership = LocalGroupMembership(object)
                if local_group_membership.should_import(known_domain_sids):
                    self.local_group_memberships.add(local_group_membership)

            elif object["ObjectType"] == RegSessionBofParser.OBJECT_TYPE:
                registry_session = LocalRegistrySession(object)
                if registry_session.should_import(known_domain_sids):
                    self.registry_sessions.add(registry_session)            
        