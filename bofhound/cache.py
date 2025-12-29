"""
Object cache system for incremental BOFHound processing.

Enables storing processed objects in SQLite database for fast incremental updates.
"""

import sqlite3
import pickle
import hashlib
import time
from typing import Dict, List, Optional, Any, Set
from pathlib import Path
from bofhound.logger import logger
from bofhound.ad.models.bloodhound_object import BloodHoundObject


class ObjectCache:
    """SQLite-based cache for storing processed BloodHound objects."""
    
    # Version for cache compatibility
    CACHE_VERSION = "1.1.0"  # Bumped for SID mapping tables
    
    def __init__(self, cache_path: str):
        """
        Initialize object cache.
        
        Args:
            cache_path: Path to SQLite database file
        """
        self.cache_path = cache_path
        self.conn = None
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database schema."""
        self.conn = sqlite3.connect(self.cache_path)
        self.conn.row_factory = sqlite3.Row
        
        cursor = self.conn.cursor()
        
        # Create objects table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS objects (
                sid TEXT,
                dn TEXT,
                object_type TEXT,
                data BLOB,
                attr_hash TEXT,
                timestamp REAL,
                source_file TEXT,
                PRIMARY KEY (sid, dn)
            )
        ''')
        
        # Create indexes for fast lookups
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sid ON objects(sid)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_dn ON objects(dn)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_type ON objects(object_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_hash ON objects(attr_hash)')
        
        # Create SID mappings table for ACL context
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sid_mappings (
                sid TEXT PRIMARY KEY,
                name TEXT,
                object_type TEXT,
                domain TEXT,
                timestamp REAL
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sid_name ON sid_mappings(name)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sid_domain ON sid_mappings(domain)')
        
        # Create domain mappings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS domain_mappings (
                dc TEXT PRIMARY KEY,
                domain_sid TEXT,
                domain_name TEXT,
                timestamp REAL
            )
        ''')
        
        # Create DN to SID mappings for resolution
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dn_mappings (
                dn TEXT PRIMARY KEY,
                sid TEXT,
                object_type TEXT,
                timestamp REAL
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_dn_sid ON dn_mappings(sid)')
        
        # Create schema GUID mappings
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS schema_guids (
                name TEXT PRIMARY KEY,
                guid TEXT,
                timestamp REAL
            )
        ''')
        
        # Create metadata table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')
        
        # Store cache version
        cursor.execute(
            'INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)',
            ('cache_version', self.CACHE_VERSION)
        )
        
        # Store creation timestamp if new
        cursor.execute('SELECT value FROM metadata WHERE key = ?', ('created_at',))
        if not cursor.fetchone():
            cursor.execute(
                'INSERT INTO metadata (key, value) VALUES (?, ?)',
                ('created_at', str(time.time()))
            )
        
        # Update last accessed
        cursor.execute(
            'INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)',
            ('last_accessed', str(time.time()))
        )
        
        self.conn.commit()
    
    def _hash_object(self, obj: Dict[str, Any]) -> str:
        """
        Calculate hash of object attributes for change detection.
        
        Args:
            obj: LDAP object dictionary
            
        Returns:
            MD5 hash of normalized object attributes
        """
        # Exclude volatile attributes from hash calculation
        exclude_attrs = {
            'whencreated', 'whenchanged', 'usnchanged', 'usncreated',
            'dscorepropagationdata', 'lastlogon', 'lastlogontimestamp',
            'badpasswordtime', 'logoncount'
        }
        
        # Create sorted list of key-value pairs for consistent hashing
        items = []
        for key in sorted(obj.keys()):
            if key.lower() not in exclude_attrs:
                value = obj[key]
                # Convert bytes to string for hashing
                if isinstance(value, bytes):
                    try:
                        value = value.decode('utf-8', errors='ignore')
                    except:
                        value = str(value)
                items.append(f"{key}:{value}")
        
        hash_string = '|'.join(items)
        return hashlib.md5(hash_string.encode('utf-8')).hexdigest()
    
    def get_cached_object(self, sid: Optional[str] = None, 
                         dn: Optional[str] = None) -> Optional[Dict]:
        """
        Retrieve cached object by SID or DN.
        
        Args:
            sid: Object SID
            dn: Object Distinguished Name
            
        Returns:
            Dict with cached object data or None
        """
        cursor = self.conn.cursor()
        
        if sid and dn:
            cursor.execute(
                'SELECT * FROM objects WHERE sid = ? AND dn = ?',
                (sid, dn)
            )
        elif sid:
            cursor.execute('SELECT * FROM objects WHERE sid = ?', (sid,))
        elif dn:
            cursor.execute('SELECT * FROM objects WHERE dn = ?', (dn,))
        else:
            return None
        
        row = cursor.fetchone()
        if row:
            return {
                'sid': row['sid'],
                'dn': row['dn'],
                'object_type': row['object_type'],
                'data': pickle.loads(row['data']),
                'hash': row['attr_hash'],
                'timestamp': row['timestamp'],
                'source_file': row['source_file']
            }
        return None
    
    def store_object(self, obj: Any, source_file: str = ''):
        """
        Store processed BloodHound object in cache.
        
        Args:
            obj: BloodHoundObject instance
            source_file: Source log file name
        """
        sid = obj.ObjectIdentifier if obj.ObjectIdentifier else ''
        dn = obj.Properties.get('distinguishedname', '')
        object_type = obj._entry_type if hasattr(obj, '_entry_type') else 'Unknown'
        
        # Calculate hash from original properties
        attr_hash = self._hash_object(obj.Properties)
        
        # Serialize object
        data = pickle.dumps(obj)
        
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO objects 
            (sid, dn, object_type, data, attr_hash, timestamp, source_file)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (sid, dn, object_type, data, attr_hash, time.time(), source_file))
    
    def get_changed_objects(self, ldap_objects: List[Dict]) -> List[Dict]:
        """
        Filter LDAP objects to return only new or changed ones.
        
        Args:
            ldap_objects: List of LDAP object dictionaries
            
        Returns:
            List of objects that are new or have changed
        """
        changed = []
        unchanged_count = 0
        
        for ldap_obj in ldap_objects:
            sid = ldap_obj.get('objectsid', '')
            dn = ldap_obj.get('distinguishedname', '').upper()
            
            # Calculate hash of new object
            new_hash = self._hash_object(ldap_obj)
            
            # Look up in cache
            cached = self.get_cached_object(sid=sid, dn=dn)
            
            if not cached:
                changed.append(ldap_obj)
            else:
                # Skip cached objects
                unchanged_count += 1
        
        logger.info(f"Cache: {unchanged_count} unchanged, {len(changed)} new/changed")
        return changed
    
    def get_all_cached_objects(self) -> List[Any]:
        """
        Retrieve all cached BloodHound objects.
        
        Returns:
            List of deserialized BloodHound objects
        """
        cursor = self.conn.cursor()
        cursor.execute('SELECT data FROM objects')
        
        objects = []
        for row in cursor.fetchall():
            try:
                obj = pickle.loads(row['data'])
                objects.append(obj)
            except Exception as e:
                logger.warning(f"Failed to deserialize cached object: {e}")
        
        return objects
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Dict with cache stats
        """
        from datetime import datetime
        cursor = self.conn.cursor()
        
        # Total objects
        cursor.execute('SELECT COUNT(*) as count FROM objects')
        total_count = cursor.fetchone()['count']
        
        # Objects by type
        cursor.execute('''
            SELECT object_type, COUNT(*) as count 
            FROM objects 
            GROUP BY object_type
        ''')
        by_type = {row['object_type']: row['count'] for row in cursor.fetchall()}
        
        # Metadata
        cursor.execute('SELECT key, value FROM metadata')
        metadata = {row['key']: row['value'] for row in cursor.fetchall()}
        
        # File size
        file_size = Path(self.cache_path).stat().st_size / (1024 * 1024)  # MB
        
        # Format timestamps
        created_at = metadata.get('created_at')
        last_accessed = metadata.get('last_accessed')
        
        if created_at:
            try:
                created_at = datetime.fromtimestamp(float(created_at)).strftime('%Y-%m-%d %H:%M:%S')
            except (ValueError, TypeError):
                pass
        
        if last_accessed:
            try:
                last_accessed = datetime.fromtimestamp(float(last_accessed)).strftime('%Y-%m-%d %H:%M:%S')
            except (ValueError, TypeError):
                pass
        
        return {
            'total_objects': total_count,
            'by_type': by_type,
            'cache_version': metadata.get('cache_version'),
            'created_at': created_at,
            'last_accessed': last_accessed,
            'file_size_mb': round(file_size, 2)
        }
    
    def commit(self):
        """Commit pending transactions."""
        if self.conn:
            self.conn.commit()
    
    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.commit()
            self.conn.close()
    
    # ===== SID Mapping Methods =====
    
    def store_sid_mapping(self, sid: str, name: str, object_type: str, domain: str = ''):
        """
        Store a SID to name mapping.
        
        Args:
            sid: Object SID
            name: Object name (sAMAccountName or CN)
            object_type: BloodHound object type (User, Computer, Group, etc.)
            domain: Domain name
        """
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO sid_mappings (sid, name, object_type, domain, timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', (sid, name, object_type, domain, time.time()))
    
    def store_sid_mappings_bulk(self, mappings: List[tuple]):
        """
        Bulk store SID mappings for efficiency.
        
        Args:
            mappings: List of (sid, name, object_type, domain) tuples
        """
        cursor = self.conn.cursor()
        timestamp = time.time()
        cursor.executemany('''
            INSERT OR REPLACE INTO sid_mappings (sid, name, object_type, domain, timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', [(sid, name, obj_type, domain, timestamp) for sid, name, obj_type, domain in mappings])
        self.conn.commit()
    
    def get_sid_mapping(self, sid: str) -> Optional[Dict]:
        """
        Retrieve SID mapping by SID.
        
        Args:
            sid: Object SID
            
        Returns:
            Dict with name, object_type, domain or None
        """
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM sid_mappings WHERE sid = ?', (sid,))
        row = cursor.fetchone()
        if row:
            return {
                'sid': row['sid'],
                'name': row['name'],
                'object_type': row['object_type'],
                'domain': row['domain']
            }
        return None
    
    def get_all_sid_mappings(self) -> Dict[str, Dict]:
        """
        Get all SID mappings as a dictionary.
        
        Returns:
            Dict mapping SID -> {name, object_type, domain}
        """
        cursor = self.conn.cursor()
        cursor.execute('SELECT sid, name, object_type, domain FROM sid_mappings')
        return {
            row['sid']: {
                'name': row['name'],
                'object_type': row['object_type'],
                'domain': row['domain']
            }
            for row in cursor.fetchall()
        }
    
    # ===== Domain Mapping Methods =====
    
    def store_domain_mapping(self, dc: str, domain_sid: str, domain_name: str = ''):
        """
        Store a domain component to SID mapping.
        
        Args:
            dc: Domain component (e.g., 'DC=ESSOS,DC=LOCAL')
            domain_sid: Domain SID
            domain_name: Domain DNS name (optional)
        """
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO domain_mappings (dc, domain_sid, domain_name, timestamp)
            VALUES (?, ?, ?, ?)
        ''', (dc, domain_sid, domain_name, time.time()))
    
    def get_domain_mapping(self, dc: str) -> Optional[str]:
        """
        Get domain SID by domain component.
        
        Args:
            dc: Domain component (e.g., 'DC=ESSOS,DC=LOCAL')
            
        Returns:
            Domain SID or None
        """
        cursor = self.conn.cursor()
        cursor.execute('SELECT domain_sid FROM domain_mappings WHERE dc = ?', (dc,))
        row = cursor.fetchone()
        return row['domain_sid'] if row else None
    
    def get_all_domain_mappings(self) -> Dict[str, str]:
        """
        Get all domain mappings.
        
        Returns:
            Dict mapping DC -> domain_sid
        """
        cursor = self.conn.cursor()
        cursor.execute('SELECT dc, domain_sid FROM domain_mappings')
        return {row['dc']: row['domain_sid'] for row in cursor.fetchall()}
    
    # ===== DN Mapping Methods =====
    
    def store_dn_mapping(self, dn: str, sid: str, object_type: str):
        """
        Store a DN to SID mapping.
        
        Args:
            dn: Distinguished Name
            sid: Object SID
            object_type: BloodHound object type
        """
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO dn_mappings (dn, sid, object_type, timestamp)
            VALUES (?, ?, ?, ?)
        ''', (dn, sid, object_type, time.time()))
    
    def store_dn_mappings_bulk(self, mappings: List[tuple]):
        """
        Bulk store DN mappings.
        
        Args:
            mappings: List of (dn, sid, object_type) tuples
        """
        cursor = self.conn.cursor()
        timestamp = time.time()
        cursor.executemany('''
            INSERT OR REPLACE INTO dn_mappings (dn, sid, object_type, timestamp)
            VALUES (?, ?, ?, ?)
        ''', [(dn, sid, obj_type, timestamp) for dn, sid, obj_type in mappings])
        self.conn.commit()
    
    def get_dn_mapping(self, dn: str) -> Optional[Dict]:
        """
        Get object info by DN.
        
        Args:
            dn: Distinguished Name
            
        Returns:
            Dict with sid, object_type or None
        """
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM dn_mappings WHERE dn = ?', (dn,))
        row = cursor.fetchone()
        if row:
            return {
                'dn': row['dn'],
                'sid': row['sid'],
                'object_type': row['object_type']
            }
        return None
    
    def get_all_dn_mappings(self) -> Dict[str, Dict]:
        """
        Get all DN mappings.
        
        Returns:
            Dict mapping DN -> {sid, object_type}
        """
        cursor = self.conn.cursor()
        cursor.execute('SELECT dn, sid, object_type FROM dn_mappings')
        return {
            row['dn']: {
                'sid': row['sid'],
                'object_type': row['object_type']
            }
            for row in cursor.fetchall()
        }
    
    # ===== Schema GUID Methods =====
    
    def store_schema_guid(self, name: str, guid: str):
        """
        Store a schema name to GUID mapping.
        
        Args:
            name: Schema attribute name
            guid: Schema ID GUID
        """
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO schema_guids (name, guid, timestamp)
            VALUES (?, ?, ?)
        ''', (name, guid, time.time()))
    
    def store_schema_guids_bulk(self, mappings: Dict[str, str]):
        """
        Bulk store schema GUID mappings.
        
        Args:
            mappings: Dict of name -> guid
        """
        cursor = self.conn.cursor()
        timestamp = time.time()
        cursor.executemany('''
            INSERT OR REPLACE INTO schema_guids (name, guid, timestamp)
            VALUES (?, ?, ?)
        ''', [(name, guid, timestamp) for name, guid in mappings.items()])
        self.conn.commit()
    
    def get_all_schema_guids(self) -> Dict[str, str]:
        """
        Get all schema GUID mappings.
        
        Returns:
            Dict mapping name -> guid
        """
        cursor = self.conn.cursor()
        cursor.execute('SELECT name, guid FROM schema_guids')
        return {row['name']: row['guid'] for row in cursor.fetchall()}
    
    # ===== Context Export/Import =====
    
    def export_context_for_workers(self) -> Dict[str, Any]:
        """
        Export all context data needed for ACL parsing in workers.
        
        Returns:
            Dict containing sid_map, domain_map, and schema_guids
        """
        return {
            'sid_map': self.get_all_sid_mappings(),
            'domain_map': self.get_all_domain_mappings(),
            'dn_map': self.get_all_dn_mappings(),
            'schema_guids': self.get_all_schema_guids()
        }
    
    def get_context_statistics(self) -> Dict[str, int]:
        """
        Get statistics about stored context data.
        
        Returns:
            Dict with counts of each mapping type
        """
        cursor = self.conn.cursor()
        
        cursor.execute('SELECT COUNT(*) as c FROM sid_mappings')
        sid_count = cursor.fetchone()['c']
        
        cursor.execute('SELECT COUNT(*) as c FROM domain_mappings')
        domain_count = cursor.fetchone()['c']
        
        cursor.execute('SELECT COUNT(*) as c FROM dn_mappings')
        dn_count = cursor.fetchone()['c']
        
        cursor.execute('SELECT COUNT(*) as c FROM schema_guids')
        schema_count = cursor.fetchone()['c']
        
        return {
            'sid_mappings': sid_count,
            'domain_mappings': domain_count,
            'dn_mappings': dn_count,
            'schema_guids': schema_count
        }
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
