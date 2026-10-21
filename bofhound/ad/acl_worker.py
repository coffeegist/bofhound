"""Serializable process adapters for the authoritative ADDS ACL parser."""
from types import SimpleNamespace


def create_worker_context(sid_map, domain_map, object_type_guid_map):
    return {
        'sid_map': {sid: getattr(obj, '_entry_type', 'Unknown') for sid, obj in sid_map.items()},
        'domain_map': dict(domain_map),
        'object_type_guid_map': dict(object_type_guid_map),
    }


def _create_parser(context):
    from bofhound.ad import ADDS
    parser = ADDS()
    parser.SID_MAP = {
        sid: SimpleNamespace(_entry_type=entry_type)
        for sid, entry_type in context['sid_map'].items()
    }
    parser.DOMAIN_MAP = context['domain_map']
    parser.ObjectTypeGuidMap = context['object_type_guid_map']
    return parser


def _parse_entry(entry_data, parser):
    entry = SimpleNamespace(
        ObjectIdentifier=entry_data['object_id'],
        _entry_type=entry_data['entry_type'],
        RawAces=entry_data['raw_aces'],
        Properties={'distinguishedname': entry_data['dn'],
                    'haslaps': entry_data.get('has_laps', False)},
        Aces=[], IsACLProtected=False,
    )
    parser.parse_acl(entry)
    return entry.ObjectIdentifier, entry.Aces, entry.IsACLProtected


def parse_acl_standalone(entry_data, context):
    """Direct adapter, also useful for verifying worker/serial equivalence."""
    return _parse_entry(entry_data, _create_parser(context))


def _worker_init(context):
    global _worker_parser
    _worker_parser = _create_parser(context)


def _worker_process(entry_data):
    return _parse_entry(entry_data, _worker_parser)


def prepare_entry_for_worker(obj):
    return {
        'object_id': obj.ObjectIdentifier,
        'entry_type': obj._entry_type,
        'dn': obj.Properties.get('distinguishedname', ''),
        'raw_aces': obj.RawAces,
        'has_laps': bool(obj.Properties.get('haslaps')),
    }
