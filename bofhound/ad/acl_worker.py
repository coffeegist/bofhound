"""
Standalone ACL parsing worker for multiprocessing.

This module provides a picklable ACL parsing function that can be used
with ProcessPoolExecutor. It contains all the logic from ADDS.parse_acl
but in a standalone form that can be safely passed to worker processes.
"""
import base64
from io import BytesIO
from typing import Dict, List, Tuple, Any, Optional

from bloodhound.ad.utils import ADUtils
from bloodhound.enumeration.acls import (
    SecurityDescriptor, ACCESS_MASK, ACE, ACCESS_ALLOWED_OBJECT_ACE,
    has_extended_right, EXTRIGHTS_GUID_MAPPING, can_write_property, ace_applies
)
from impacket.uuid import string_to_bin

# Add the Enroll GUID to the mapping
EXTRIGHTS_GUID_MAPPING["Enroll"] = string_to_bin("0e10c968-78fb-11d2-90d4-00c04f79dc55")

# Type definitions for worker context
ACLWorkerContext = Dict[str, Any]
ACLEntry = Dict[str, Any]


def create_worker_context(
    sid_map: Dict[str, Any],
    domain_map: Dict[str, str],
    object_type_guid_map: Dict[str, str]
) -> ACLWorkerContext:
    """
    Create a serializable context dict for ACL workers.
    
    Args:
        sid_map: Maps SID -> object type (e.g., "User", "Computer", "Group")
        domain_map: Maps domain component (DC) -> domain SID
        object_type_guid_map: Maps schema name -> GUID
        
    Returns:
        Context dict that can be passed to worker processes
    """
    # Simplify SID_MAP to just SID -> type mapping (all we need for ACL parsing)
    simple_sid_map = {}
    for sid, obj in sid_map.items():
        if hasattr(obj, '_entry_type'):
            simple_sid_map[sid] = obj._entry_type
        else:
            simple_sid_map[sid] = "Unknown"
    
    return {
        'sid_map': simple_sid_map,
        'domain_map': domain_map,
        'object_type_guid_map': object_type_guid_map,
    }


def _get_domain_component(dn: str) -> str:
    """Extract domain component from DN (e.g., 'DC=ESSOS,DC=LOCAL')."""
    parts = dn.upper().split(',')
    dc_parts = [p for p in parts if p.startswith('DC=')]
    return ','.join(dc_parts)


def _get_sid(sid: str, dn: str, domain_map: Dict[str, str]) -> str:
    """
    Get full SID, prepending domain if it's a well-known SID.
    
    For well-known SIDs like S-1-5-32-544, we need to prepend the domain.
    """
    if sid in ADUtils.WELLKNOWN_SIDS:
        dc = _get_domain_component(dn)
        domain_sid = domain_map.get(dc, "S-????")
        # Format: DOMAIN-SID (e.g., "ESSOS.LOCAL-S-1-5-11")
        return f"{dc.replace(',DC=', '.').replace('DC=', '')}-{sid}"
    return sid


def _build_relation(
    entry_dn: str,
    entry_type: str,
    sid: str,
    relation: str,
    inherited: bool,
    sid_map: Dict[str, str],
    domain_map: Dict[str, str]
) -> Dict[str, Any]:
    """
    Build an ACL relationship dict.
    
    Args:
        entry_dn: Distinguished name of the target object
        entry_type: Type of the target object
        sid: SID of the principal
        relation: Relationship name (e.g., 'GenericAll', 'WriteDacl')
        inherited: Whether the ACE is inherited
        sid_map: Maps SID -> object type
        domain_map: Maps DC -> domain SID
        
    Returns:
        Relationship dict for BloodHound
    """
    principal_sid = _get_sid(sid, entry_dn, domain_map)
    
    if sid in sid_map:
        principal_type = sid_map[sid]
    elif sid in ADUtils.WELLKNOWN_SIDS:
        principal_type = ADUtils.WELLKNOWN_SIDS[sid][1].title()
    else:
        principal_type = "Unknown"
    
    return {
        'RightName': relation,
        'PrincipalSID': principal_sid,
        'IsInherited': inherited,
        'PrincipalType': principal_type
    }


def parse_acl_standalone(
    entry_data: ACLEntry,
    context: ACLWorkerContext
) -> Tuple[str, List[Dict[str, Any]], bool]:
    """
    Parse ACL for a single entry in a standalone (picklable) manner.
    
    Args:
        entry_data: Dict containing:
            - object_id: Object identifier (SID/GUID)
            - entry_type: Object type (User, Computer, Group, etc.)
            - dn: Distinguished name
            - raw_aces: Base64-encoded nTSecurityDescriptor
            - has_laps: Whether LAPS is enabled (for computers)
        context: Worker context from create_worker_context()
        
    Returns:
        Tuple of (object_id, relations_list, is_acl_protected)
    """
    object_id = entry_data['object_id']
    entry_type = entry_data['entry_type']
    entry_dn = entry_data['dn']
    raw_aces = entry_data['raw_aces']
    has_laps = entry_data.get('has_laps', False)
    
    sid_map = context['sid_map']
    domain_map = context['domain_map']
    object_type_guid_map = context['object_type_guid_map']
    
    if not raw_aces:
        return (object_id, [], False)
    
    try:
        value = base64.b64decode(raw_aces)
    except Exception:
        return (object_id, [], False)
    
    if not value:
        return (object_id, [], False)
    
    sd = SecurityDescriptor(BytesIO(value))
    is_acl_protected = sd.has_control(sd.PD)
    relations = []
    
    # Ignore these SIDs (Creator Owner, Local System, Principal Self)
    ignore_sids = {"S-1-3-0", "S-1-5-18", "S-1-5-10"}
    
    # Parse owner
    owner_sid = str(sd.owner_sid)
    if owner_sid not in ignore_sids:
        relations.append(_build_relation(
            entry_dn, entry_type, owner_sid, 'Owns', False,
            sid_map, domain_map
        ))
    
    # Parse DACLs
    for ace_object in sd.dacl.aces:
        # Only care about ACCESS_ALLOWED_OBJECT_ACE (0x05) and ACCESS_ALLOWED_ACE (0x00)
        if ace_object.ace.AceType not in (0x05, 0x00):
            continue
        
        sid = str(ace_object.acedata.sid)
        if sid in ignore_sids:
            continue
        
        is_inherited = ace_object.has_flag(ACE.INHERITED_ACE)
        
        if ace_object.ace.AceType == 0x05:
            # ACCESS_ALLOWED_OBJECT_ACE
            if not ace_object.has_flag(ACE.INHERITED_ACE) and ace_object.has_flag(ACE.INHERIT_ONLY_ACE):
                continue
            
            # Check if ACE applies to this object type
            if ace_object.has_flag(ACE.INHERITED_ACE) and \
               ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_INHERITED_OBJECT_TYPE_PRESENT):
                try:
                    if not ace_applies(
                        ace_object.acedata.get_inherited_object_type().lower(),
                        entry_type,
                        object_type_guid_map
                    ):
                        continue
                except KeyError:
                    pass
            
            mask = ace_object.acedata.mask
            
            # Generic access masks
            if mask.has_priv(ACCESS_MASK.GENERIC_ALL) or mask.has_priv(ACCESS_MASK.WRITE_DACL) or \
               mask.has_priv(ACCESS_MASK.WRITE_OWNER) or mask.has_priv(ACCESS_MASK.GENERIC_WRITE):
                
                try:
                    if ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT) and \
                       not ace_applies(ace_object.acedata.get_object_type().lower(), entry_type, object_type_guid_map):
                        continue
                except KeyError:
                    pass
                
                if mask.has_priv(ACCESS_MASK.GENERIC_ALL):
                    # Check LAPS rights for computers
                    if entry_type.lower() == 'computer' and \
                       ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT) and \
                       has_laps and 'ms-mcs-admpwd' in object_type_guid_map:
                        if ace_object.acedata.get_object_type().lower() == object_type_guid_map['ms-mcs-admpwd']:
                            relations.append(_build_relation(
                                entry_dn, entry_type, sid, 'ReadLAPSPassword', is_inherited,
                                sid_map, domain_map
                            ))
                    else:
                        relations.append(_build_relation(
                            entry_dn, entry_type, sid, 'GenericAll', is_inherited,
                            sid_map, domain_map
                        ))
                    continue
                
                if mask.has_priv(ACCESS_MASK.GENERIC_WRITE):
                    relations.append(_build_relation(
                        entry_dn, entry_type, sid, 'GenericWrite', is_inherited,
                        sid_map, domain_map
                    ))
                    if entry_type.lower() not in ('domain', 'computer'):
                        continue
                
                if mask.has_priv(ACCESS_MASK.WRITE_DACL):
                    relations.append(_build_relation(
                        entry_dn, entry_type, sid, 'WriteDacl', is_inherited,
                        sid_map, domain_map
                    ))
                
                if mask.has_priv(ACCESS_MASK.WRITE_OWNER):
                    relations.append(_build_relation(
                        entry_dn, entry_type, sid, 'WriteOwner', is_inherited,
                        sid_map, domain_map
                    ))
            
            # Property write privileges
            if ace_object.acedata.mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_WRITE_PROP):
                if entry_type.lower() in ('user', 'group', 'computer', 'gpo') and \
                   not ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT):
                    relations.append(_build_relation(
                        entry_dn, entry_type, sid, 'GenericWrite', is_inherited,
                        sid_map, domain_map
                    ))
                
                if entry_type.lower() == 'group' and can_write_property(ace_object, EXTRIGHTS_GUID_MAPPING['WriteMember']):
                    relations.append(_build_relation(
                        entry_dn, entry_type, sid, 'AddMember', is_inherited,
                        sid_map, domain_map
                    ))
                
                if entry_type.lower() == 'computer' and can_write_property(ace_object, EXTRIGHTS_GUID_MAPPING['AllowedToAct']):
                    relations.append(_build_relation(
                        entry_dn, entry_type, sid, 'AddAllowedToAct', is_inherited,
                        sid_map, domain_map
                    ))
                
                if entry_type.lower() == 'computer' and \
                   can_write_property(ace_object, EXTRIGHTS_GUID_MAPPING['UserAccountRestrictionsSet']) and \
                   not sid.endswith('-512'):
                    relations.append(_build_relation(
                        entry_dn, entry_type, sid, 'WriteAccountRestrictions', is_inherited,
                        sid_map, domain_map
                    ))
                
                # Key credential link
                if entry_type.lower() in ('user', 'computer') and \
                   ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT) and \
                   'ms-ds-key-credential-link' in object_type_guid_map and \
                   ace_object.acedata.get_object_type().lower() == object_type_guid_map['ms-ds-key-credential-link']:
                    relations.append(_build_relation(
                        entry_dn, entry_type, sid, 'AddKeyCredentialLink', is_inherited,
                        sid_map, domain_map
                    ))
                
                # SPN write rights
                if entry_type.lower() == 'user' and \
                   ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT) and \
                   ace_object.acedata.get_object_type().lower() == 'f3a64788-5306-11d1-a9c5-0000f80367c1':
                    relations.append(_build_relation(
                        entry_dn, entry_type, sid, 'WriteSPN', is_inherited,
                        sid_map, domain_map
                    ))
                
                # Certificate template rights
                if entry_type.lower() == 'pki template' and \
                   ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT) and \
                   ace_object.acedata.get_object_type().lower() == 'ea1dddc4-60ff-416e-8cc0-17cee534bce7':
                    relations.append(_build_relation(
                        entry_dn, entry_type, sid, 'WritePKINameFlag', is_inherited,
                        sid_map, domain_map
                    ))
                
                if entry_type.lower() == 'pki template' and \
                   ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT) and \
                   ace_object.acedata.get_object_type().lower() == 'd15ef7d8-f226-46db-ae79-b34e560bd12c':
                    relations.append(_build_relation(
                        entry_dn, entry_type, sid, 'WritePKIEnrollmentFlag', is_inherited,
                        sid_map, domain_map
                    ))
            
            elif ace_object.acedata.mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_SELF):
                # Self add
                if entry_type.lower() == 'group' and ace_object.acedata.data.ObjectType == EXTRIGHTS_GUID_MAPPING['WriteMember']:
                    relations.append(_build_relation(
                        entry_dn, entry_type, sid, 'AddSelf', is_inherited,
                        sid_map, domain_map
                    ))
            
            # Property read privileges (LAPS)
            if ace_object.acedata.mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_READ_PROP):
                if entry_type.lower() == 'computer' and \
                   ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT) and \
                   has_laps and 'ms-mcs-admpwd' in object_type_guid_map:
                    if ace_object.acedata.get_object_type().lower() == object_type_guid_map['ms-mcs-admpwd']:
                        relations.append(_build_relation(
                            entry_dn, entry_type, sid, 'ReadLAPSPassword', is_inherited,
                            sid_map, domain_map
                        ))
            
            # Extended rights
            if ace_object.acedata.mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_CONTROL_ACCESS):
                if entry_type.lower() in ('user', 'domain') and \
                   not ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT):
                    relations.append(_build_relation(
                        entry_dn, entry_type, sid, 'AllExtendedRights', is_inherited,
                        sid_map, domain_map
                    ))
                
                if entry_type.lower() == 'computer' and \
                   not ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT):
                    relations.append(_build_relation(
                        entry_dn, entry_type, sid, 'AllExtendedRights', is_inherited,
                        sid_map, domain_map
                    ))
                
                if entry_type.lower() == 'domain' and has_extended_right(ace_object, EXTRIGHTS_GUID_MAPPING['GetChanges']):
                    relations.append(_build_relation(
                        entry_dn, entry_type, sid, 'GetChanges', is_inherited,
                        sid_map, domain_map
                    ))
                
                if entry_type.lower() == 'domain' and has_extended_right(ace_object, EXTRIGHTS_GUID_MAPPING['GetChangesAll']):
                    relations.append(_build_relation(
                        entry_dn, entry_type, sid, 'GetChangesAll', is_inherited,
                        sid_map, domain_map
                    ))
                
                if entry_type.lower() == 'domain' and has_extended_right(ace_object, EXTRIGHTS_GUID_MAPPING['GetChangesInFilteredSet']):
                    relations.append(_build_relation(
                        entry_dn, entry_type, sid, 'GetChangesInFilteredSet', is_inherited,
                        sid_map, domain_map
                    ))
                
                if entry_type.lower() == 'user' and has_extended_right(ace_object, EXTRIGHTS_GUID_MAPPING['UserForceChangePassword']):
                    relations.append(_build_relation(
                        entry_dn, entry_type, sid, 'ForceChangePassword', is_inherited,
                        sid_map, domain_map
                    ))
                
                # Certificate enrollment rights
                if entry_type.lower() in ('pki template', 'enterpriseca') and \
                   has_extended_right(ace_object, EXTRIGHTS_GUID_MAPPING['Enroll']):
                    relations.append(_build_relation(
                        entry_dn, entry_type, sid, 'Enroll', is_inherited,
                        sid_map, domain_map
                    ))
        
        elif ace_object.ace.AceType == 0x00:
            # ACCESS_ALLOWED_ACE
            if not ace_object.has_flag(ACE.INHERITED_ACE) and ace_object.has_flag(ACE.INHERIT_ONLY_ACE):
                continue
            
            mask = ace_object.acedata.mask
            
            if mask.has_priv(ACCESS_MASK.GENERIC_ALL):
                relations.append(_build_relation(
                    entry_dn, entry_type, sid, 'GenericAll', is_inherited,
                    sid_map, domain_map
                ))
                continue
            
            if mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_WRITE_PROP):
                if entry_type.lower() in ('user', 'group', 'computer', 'gpo'):
                    relations.append(_build_relation(
                        entry_dn, entry_type, sid, 'GenericWrite', is_inherited,
                        sid_map, domain_map
                    ))
            
            if mask.has_priv(ACCESS_MASK.WRITE_OWNER):
                relations.append(_build_relation(
                    entry_dn, entry_type, sid, 'WriteOwner', is_inherited,
                    sid_map, domain_map
                ))
            
            if entry_type.lower() in ('user', 'domain') and mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_CONTROL_ACCESS):
                relations.append(_build_relation(
                    entry_dn, entry_type, sid, 'AllExtendedRights', is_inherited,
                    sid_map, domain_map
                ))
            
            if entry_type.lower() == 'computer' and mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_CONTROL_ACCESS) and \
               sid != "S-1-5-32-544" and not sid.endswith('-512'):
                relations.append(_build_relation(
                    entry_dn, entry_type, sid, 'AllExtendedRights', is_inherited,
                    sid_map, domain_map
                ))
            
            if mask.has_priv(ACCESS_MASK.WRITE_DACL):
                relations.append(_build_relation(
                    entry_dn, entry_type, sid, 'WriteDacl', is_inherited,
                    sid_map, domain_map
                ))
    
    return (object_id, relations, is_acl_protected)


def _worker_init(ctx: ACLWorkerContext):
    """Initialize worker process with shared context."""
    global _worker_context
    _worker_context = ctx


def _worker_process(entry_data: ACLEntry) -> Tuple[str, List[Dict[str, Any]], bool]:
    """Worker function that uses global context."""
    global _worker_context
    return parse_acl_standalone(entry_data, _worker_context)


def prepare_entry_for_worker(obj) -> ACLEntry:
    """
    Prepare a BloodHound object for multiprocess ACL parsing.
    
    Args:
        obj: BloodHoundObject instance
        
    Returns:
        Serializable dict with data needed for ACL parsing
    """
    return {
        'object_id': obj.ObjectIdentifier,
        'entry_type': obj._entry_type,
        'dn': obj.Properties.get('distinguishedname', ''),
        'raw_aces': obj.RawAces,
        'has_laps': 'haslaps' in obj.Properties and obj.Properties.get('haslaps', False),
    }
