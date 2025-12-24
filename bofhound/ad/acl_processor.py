"""
Parallel ACL processor for BOFHound performance improvements.

This module enables multiprocessing of ACL parsing to leverage multiple CPU cores.
"""

import base64
from io import BytesIO
from typing import Dict, List, Tuple, Any
from multiprocessing import Pool, cpu_count
from functools import partial
from bloodhound.enumeration.acls import SecurityDescriptor, ACCESS_MASK, ACE, ACCESS_ALLOWED_OBJECT_ACE
from bloodhound.enumeration.acls import has_extended_right, EXTRIGHTS_GUID_MAPPING, can_write_property, ace_applies
from bloodhound.ad.utils import ADUtils
from bofhound.logger import logger


class ACLProcessorContext:
    """Minimal context needed for ACL parsing in worker processes"""
    
    def __init__(self, sid_map: Dict[str, str], domain_map: Dict[str, str], 
                 guid_map: Dict[str, str]):
        """
        Initialize ACL processor context with lookup maps.
        
        Args:
            sid_map: {sid: object_type} mapping
            domain_map: {dc: domain_sid} mapping
            guid_map: {name: guid} mapping for ObjectTypeGuidMap
        """
        self.sid_map = sid_map
        self.domain_map = domain_map
        self.guid_map = guid_map


def parse_acl_for_object(obj_data: Tuple[str, str, bytes, str, Dict], 
                         context: ACLProcessorContext) -> Tuple[str, List[Dict], bool, int]:
    """
    Parse ACLs for a single object in a worker process.
    
    Args:
        obj_data: Tuple of (object_id, entry_type, raw_aces, dn, properties)
        context: ACLProcessorContext with lookup maps
        
    Returns:
        Tuple of (object_id, aces_list, is_acl_protected, num_relations)
    """
    object_id, entry_type, raw_aces, dn, properties = obj_data
    
    if not raw_aces:
        return (object_id, [], False, 0)
    
    try:
        value = base64.b64decode(raw_aces)
    except Exception as e:
        logger.warning(f"Error base64 decoding ACL for {object_id}: {e}")
        return (object_id, [], False, 0)
    
    if not value:
        return (object_id, [], False, 0)
    
    try:
        sd = SecurityDescriptor(BytesIO(value))
    except Exception as e:
        logger.warning(f"Error parsing SecurityDescriptor for {object_id}: {e}")
        return (object_id, [], False, 0)
    
    is_acl_protected = sd.has_control(sd.PD)
    aces = []
    num_relations = 0
    
    # Parse owner
    osid = str(sd.owner_sid)
    ignoresids = ["S-1-3-0", "S-1-5-18", "S-1-5-10"]
    
    if osid not in ignoresids:
        principal_type = context.sid_map.get(osid, "Unknown")
        if osid in ADUtils.WELLKNOWN_SIDS:
            principal_type = ADUtils.WELLKNOWN_SIDS[osid][1].title()
        
        aces.append({
            'RightName': 'Owner',
            'PrincipalSID': osid,
            'IsInherited': False,
            'PrincipalType': principal_type
        })
        num_relations += 1
    
    # Parse DACL
    if sd.dacl is None:
        return (object_id, aces, is_acl_protected, num_relations)
    
    for ace in sd.dacl.aces:
        sid = str(ace.sid)
        
        if sid in ignoresids:
            continue
        
        # Determine principal type
        principal_type = context.sid_map.get(sid, "Unknown")
        if sid in ADUtils.WELLKNOWN_SIDS:
            principal_type = ADUtils.WELLKNOWN_SIDS[sid][1].title()
        
        # Process ACE based on type
        if ace.has_flag(ACE.INHERITED_ACE):
            inherited = True
        else:
            inherited = False
        
        # GenericAll
        if ace.has_priv(ACCESS_MASK.GENERIC_ALL):
            aces.append({
                'RightName': 'GenericAll',
                'PrincipalSID': sid,
                'IsInherited': inherited,
                'PrincipalType': principal_type
            })
            num_relations += 1
        
        # WriteDacl
        if ace.has_priv(ACCESS_MASK.WRITE_DACL):
            aces.append({
                'RightName': 'WriteDacl',
                'PrincipalSID': sid,
                'IsInherited': inherited,
                'PrincipalType': principal_type
            })
            num_relations += 1
        
        # WriteOwner
        if ace.has_priv(ACCESS_MASK.WRITE_OWNER):
            aces.append({
                'RightName': 'WriteOwner',
                'PrincipalSID': sid,
                'IsInherited': inherited,
                'PrincipalType': principal_type
            })
            num_relations += 1
        
        # Additional ACE processing logic can be added here
        # (Extended rights, property writes, etc.)
        
    return (object_id, aces, is_acl_protected, num_relations)


def process_acls_parallel(objects: List[Any], sid_map: Dict, domain_map: Dict, 
                          guid_map: Dict, num_workers: int = None) -> Dict[str, Tuple]:
    """
    Process ACLs for multiple objects in parallel.
    
    Args:
        objects: List of BloodHound objects to process
        sid_map: SID to object type mapping
        domain_map: Domain component to SID mapping
        guid_map: ObjectTypeGuidMap
        num_workers: Number of worker processes (default: cpu_count - 1)
        
    Returns:
        Dict mapping object_id to (aces, is_protected, num_relations)
    """
    if num_workers is None:
        num_workers = max(1, cpu_count() - 1)
    
    # Prepare context
    context = ACLProcessorContext(
        sid_map={sid: obj._entry_type for sid, obj in sid_map.items()},
        domain_map=dict(domain_map),
        guid_map=dict(guid_map)
    )
    
    # Prepare object data for workers
    obj_data_list = []
    for obj in objects:
        if hasattr(obj, 'RawAces') and obj.RawAces:
            obj_data = (
                obj.ObjectIdentifier,
                obj._entry_type,
                obj.RawAces,
                obj.Properties.get('distinguishedname', ''),
                dict(obj.Properties)
            )
            obj_data_list.append(obj_data)
    
    if not obj_data_list:
        return {}
    
    # Process in parallel
    logger.info(f"Processing {len(obj_data_list)} ACLs using {num_workers} workers")
    
    results = {}
    
    if len(obj_data_list) < 100 or num_workers == 1:
        # For small datasets, multiprocessing overhead isn't worth it
        for obj_data in obj_data_list:
            obj_id, aces, is_protected, num_rels = parse_acl_for_object(obj_data, context)
            results[obj_id] = (aces, is_protected, num_rels)
    else:
        # Use multiprocessing for large datasets
        with Pool(num_workers) as pool:
            process_func = partial(parse_acl_for_object, context=context)
            parallel_results = pool.map(process_func, obj_data_list)
            
            for obj_id, aces, is_protected, num_rels in parallel_results:
                results[obj_id] = (aces, is_protected, num_rels)
    
    return results
