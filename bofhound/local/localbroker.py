"""""LocalBroker to store and manage local parsed objects."""
from bofhound.parsers import ParsingResult
from .models import LocalGroupMembership, LocalPrivilegedSession, LocalSession, LocalRegistrySession


class LocalBroker:
    """Broker to manage local parsed objects from various parsers."""

    def __init__(self):
        self.privileged_sessions        = set()
        self.sessions                   = set()
        self.local_group_memberships    = set()
        self.registry_sessions          = set()

    def import_objects(self, parsed_objects: ParsingResult, known_domain_sids):
        """
        Import parsed objects into the local broker. Take in known domain sids so we can filter out
        local accounts and accounts with unknown domains
        """
        for item in parsed_objects.get_privileged_sessions():
            priv_session = LocalPrivilegedSession(item)
            if priv_session.should_import():
                self.privileged_sessions.add(priv_session)

        for item in parsed_objects.get_sessions():
            session = LocalSession(item)
            if session.should_import():
                self.sessions.add(session)

        for item in parsed_objects.get_local_group_memberships():
            local_group_membership = LocalGroupMembership(item)
            if local_group_membership.should_import(known_domain_sids):
                self.local_group_memberships.add(local_group_membership)

        for item in parsed_objects.get_registry_sessions():
            registry_session = LocalRegistrySession(item)
            if registry_session.should_import(known_domain_sids):
                self.registry_sessions.add(registry_session)
