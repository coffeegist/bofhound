"""
Object cache system for incremental BOFHound processing.

Stores raw LDAP snapshots and resolution mappings for incremental collections.
"""

import base64
import hashlib
import json
import sqlite3
import time
from typing import Dict, List, Optional, Any, Set
from pathlib import Path
from bofhound.logger import logger
from bofhound.ad.models.bloodhound_object import BloodHoundObject

_JSON_BYTES_KEY = "__bofhound_bytes_b64__"

def _json_default(value):
    """Encode binary LDAP values without making the cache executable."""
    if isinstance(value, bytes):
        return {_JSON_BYTES_KEY: base64.b64encode(value).decode('ascii')}
    raise TypeError(f'Object of type {value.__class__.__name__} is not JSON serializable')

def _json_object_hook(value):
    """Restore binary LDAP values encoded by :func:`_json_default`."""
    if set(value) != {_JSON_BYTES_KEY}:
        return value
    encoded = value[_JSON_BYTES_KEY]
    if not isinstance(encoded, str):
        raise ValueError("Invalid cache object: malformed binary value")
    try:
        return base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid cache object: malformed binary value") from exc

class ObjectCache:
    """SQLite cache of data-only LDAP snapshots and resolution mappings."""

    # Version for cache compatibility
    CACHE_VERSION = "4.0.0"  # Raw LDAP snapshots, never processed Python objects.

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

        # Never interpret or silently upgrade databases containing executable pickles.
        tables = {row[0] for row in cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
        if "objects" in tables or "metadata" in tables:
            version = None
            if "metadata" in tables:
                row = cursor.execute(
                    "SELECT value FROM metadata WHERE key = 'cache_version'"
                ).fetchone()
                version = row[0] if row else None
            if version != self.CACHE_VERSION:
                self.conn.close()
                self.conn = None
                raise ValueError(
                    "Incompatible cache version; use a new --cache-file or remove "
                    "the old cache and rebuild it from the original logs"
                )

        # Create objects table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS objects (
                sid TEXT,
                dn TEXT,
                guid TEXT,
                object_type TEXT,
                data BLOB,
                attr_hash TEXT,
                timestamp REAL,
                source_file TEXT,
                PRIMARY KEY (sid, dn)
            )
        ''')

        # Create indexes for fast lookups
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_sid ON objects(sid) WHERE sid != ''")
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_dn ON objects(dn) WHERE dn != ''")
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_guid ON objects(guid) WHERE guid != ''")
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

    @staticmethod
    def _normalize_object(obj):
        if not isinstance(obj, dict) or not all(isinstance(key, str) for key in obj):
            raise ValueError("Cache objects must be LDAP attribute dictionaries")
        value = {key.lower(): item for key, item in obj.items()}
        # Validate and detach from the caller. Never discard output-relevant attributes.
        return json.loads(json.dumps(value, sort_keys=True, allow_nan=False, default=_json_default),object_hook=_json_object_hook,)

    @staticmethod
    def _identity(obj):
        dn = obj.get('distinguishedname', '').upper()
        sid = BloodHoundObject.get_sid(obj.get('objectsid'), dn) or obj.get('objectguid', '')
        return str(sid).upper() if sid else '', dn

    def _hash_object(self, obj):
        normalized = self._normalize_object(obj)
        if normalized.get('distinguishedname'):
            normalized['distinguishedname'] = normalized['distinguishedname'].upper()
        data = json.dumps(normalized, sort_keys=True, separators=(',', ':'),allow_nan=False, default=_json_default)
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    def merge_ldap_objects(self, incoming):
        """Combine incremental collections before rebuilding the complete graph.

        Present attributes supersede earlier values, including empty strings.
        Absent objects/attributes are retained: absence in a partial collection
        cannot prove deletion. A fresh cache gives a fresh snapshot.
        """
        cached = self.get_all_cached_objects()
        objects = {}
        fresh_memberships = {}
        by_sid, by_guid, by_dn = {}, {}, {}
        indexes = (by_sid, by_guid, by_dn)
        displaced = set()
        next_key = 0

        def aliases(raw):
            dn = raw.get('distinguishedname', '').upper()
            sid = BloodHoundObject.get_sid(raw.get('objectsid'), dn)
            guid = raw.get('objectguid')
            return str(sid).upper() if sid else '', str(guid).upper() if guid else '', dn

        def remove(key):
            displaced.discard(key)
            fresh_memberships.pop(key, None)
            record = objects.pop(key)
            for index, alias in zip(indexes, aliases(record)):
                if alias and index.get(alias) == key:
                    del index[alias]

        cached_targets = {aliases(raw)[2]: aliases(raw) for raw in cached if aliases(raw)[2]}
        membership_fields = ('member', 'memberof')
        for position, raw in enumerate(cached + incoming):
            obj = self._normalize_object(raw)
            sid, guid, dn = aliases(obj)
            owners = {index[alias] for index, alias in ((by_sid, sid), (by_guid, guid))
                      if alias and alias in index}
            if not owners and dn in by_dn:
                owners.add(by_dn[dn])

            merged = {}
            fresh = 0
            for key in sorted(owners):
                previous = objects[key]
                old_sid, old_guid, _ = aliases(previous)
                conflict = ((sid and old_sid and sid != old_sid)
                            or (guid and old_guid and guid != old_guid))
                if not conflict:
                    merged.update(previous)
                    fresh |= fresh_memberships[key]
            merged.update(obj)
            if position >= len(cached):
                for bit, field in enumerate(membership_fields):
                    if field in obj:
                        fresh |= 1 << bit

            key = min(owners) if owners else next_key
            if not owners:
                next_key += 1
            # Keep a displaced identity's own attributes available for a later
            # same-batch rename, but never use them to enrich the new DN owner.
            destination_dn = aliases(merged)[2]
            destination_owner = by_dn.get(destination_dn)
            if destination_owner is not None and destination_owner not in owners:
                displaced.add(destination_owner)
                del by_dn[destination_dn]
            for owner in owners:
                remove(owner)
            objects[key] = merged
            fresh_memberships[key] = fresh
            for index, alias in zip(indexes, aliases(merged)):
                if alias:
                    index[alias] = key
        # Unobserved displaced identities are stale and must not reach export/disk.
        for key in list(displaced):
            remove(key)
        # Cached DN links refer to the identity observed at collection time, not
        # an arbitrary future occupant of that DN. Fresh links use current DNs.
        for key, record in objects.items():
            for bit, field in enumerate(membership_fields):
                value = record.get(field)
                if fresh_memberships[key] & (1 << bit) or not isinstance(value, str):
                    continue
                resolved = []
                for reference in value.split(', '):
                    prior = cached_targets.get(reference.upper())
                    if prior is None or not (prior[0] or prior[1]):
                        resolved.append(reference)
                        continue
                    sid, guid, _ = prior
                    targets = {index[alias] for index, alias in ((by_sid, sid), (by_guid, guid))
                               if alias and alias in index}
                    if len(targets) != 1:
                        continue
                    target = objects[next(iter(targets))]
                    new_sid, new_guid, new_dn = aliases(target)
                    if ((sid and new_sid and sid != new_sid)
                            or (guid and new_guid and guid != new_guid) or not new_dn):
                        continue
                    resolved.append(reference if new_dn == reference.upper()
                                    else target['distinguishedname'])
                record[field] = ', '.join(resolved)

        # A freshly collected DN member list supersedes old memberOf backlinks.
        # BRc4 may render account names instead of DNs; those lists cannot disprove
        # a backlink. Missing member attributes likewise provide no new evidence.
        fresh_group_members = {}
        for key, record in objects.items():
            value = record.get('member')
            if not fresh_memberships[key] & 1 or not isinstance(value, str):
                continue
            members = {dn.upper() for dn in value.split(', ') if dn}
            if any(dn.partition('=')[0] not in {'CN', 'OU', 'DC'} for dn in members):
                continue
            group_dn = record.get('distinguishedname', '').upper()
            if group_dn:
                fresh_group_members[group_dn] = members

        for key, record in objects.items():
            value = record.get('memberof')
            if fresh_memberships[key] & 2 or not isinstance(value, str):
                continue
            member_dn = record.get('distinguishedname', '').upper()
            record['memberof'] = ', '.join(
                group_dn for group_dn in value.split(', ')
                if (group_dn.upper() not in fresh_group_members
                    or member_dn in fresh_group_members[group_dn.upper()])
            )
        return [objects[key] for key in sorted(objects)]

    def clear_context(self):
        """Stage replacement of derived mappings with the current snapshot's context."""
        for table in ('sid_mappings', 'dn_mappings', 'domain_mappings', 'schema_guids'):
            self.conn.execute(f'DELETE FROM {table}')

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

        if sid:
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
                'data': self._decode_object(row['data']),
                'hash': row['attr_hash'],
                'timestamp': row['timestamp'],
                'source_file': row['source_file']
            }
        return None

    def store_object(self, obj, source_file=''):
        """Stage a raw LDAP snapshot; callers commit only after writing output."""
        obj = self._normalize_object(obj)
        sid, dn = self._identity(obj)
        if not sid and not dn:
            return
        guid = str(obj.get('objectguid') or '').upper()
        # Independent aliases prevent GUID-only rows surviving SID enrichment/renames.
        predicates, values = [], []
        for column, value in (('sid', sid), ('guid', guid), ('dn', dn)):
            if value:
                predicates.append(f'{column} = ?')
                values.append(value)
        self.conn.execute('DELETE FROM objects WHERE ' + ' OR '.join(predicates), values)
        self.conn.execute(
            'INSERT OR REPLACE INTO objects '
            '(sid, dn, guid, object_type, data, attr_hash, timestamp, source_file) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            (sid, dn, guid, obj.get('objectclass', ''),
             json.dumps(obj, sort_keys=True, allow_nan=False, default=_json_default),
             self._hash_object(obj), time.time(), source_file)
        )

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
            sid, dn = self._identity(ldap_obj)

            # Calculate hash of new object
            new_hash = self._hash_object(ldap_obj)

            # Look up in cache
            cached = self.get_cached_object(sid=sid, dn=dn)

            if not cached or cached['hash'] != new_hash:
                changed.append(ldap_obj)
            else:
                # Skip cached objects
                unchanged_count += 1

        logger.info(f"Cache: {unchanged_count} unchanged, {len(changed)} new/changed")
        return changed

    def get_all_cached_objects(self) -> List[Any]:
        """
        Retrieve all cached raw LDAP attribute dictionaries.

        Returns:
            List of data-only LDAP dictionaries
        """
        cursor = self.conn.cursor()
        cursor.execute('SELECT data FROM objects')

        return [self._decode_object(row['data']) for row in cursor.fetchall()]

    @staticmethod
    def _decode_object(data):
        """Read data only; cache content can never select a Python constructor."""
        value = json.loads(data, object_hook=_json_object_hook)
        if not isinstance(value, dict):
            raise ValueError("Invalid cache object: expected a JSON object")
        return value

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
            self.conn.close()
            self.conn = None

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
        """Commit successful scopes and roll back failed scopes."""
        try:
            if exc_type is None:
                self.commit()
            elif self.conn:
                self.conn.rollback()
        finally:
            self.close()
