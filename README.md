```
              _____________________________ __    __    ______    __    __   __   __   _______
             |   _   /  /  __   / |   ____/|  |  |  |  /  __  \  |  |  |  | |  \ |  | |       \
             |  |_)  | |  |  |  | |  |__   |  |__|  | |  |  |  | |  |  |  | |   \|  | |  .--.  |
             |   _  <  |  |  |  | |   __|  |   __   | |  |  |  | |  |  |  | |  . `  | |  |  |  |
             |  |_)  | |  `--'  | |  |     |  |  |  | |  `--'  | |  `--'  | |  |\   | |  '--'  |
             |______/   \______/  |__|     |__|  |___\_\________\_\________\|__| \___\|_________\

                                         << @coffeegist | @Tw1sm >>
```

<h1 align="center">

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![PyPi](https://img.shields.io/pypi/v/bofhound?style=for-the-badge)
</h1>

BOFHound turns collected Active Directory data into BloodHound CE JSON. It supports LDAP results from Cobalt Strike, Brute Ratel, Havoc, OutflankC2, and Mythic, as well as [pyldapsearch](https://github.com/fortalice/pyldapsearch) logs and raw LDIF from OpenLDAP's `ldapsearch` client. It can also parse AD CS objects, sessions, and local group membership data, and optionally upload the resulting files to BloodHound CE.

You control which LDAP queries to run and when to run them. BOFHound processes the results afterward, letting you account for expensive queries, honeypot accounts, and other detection mechanisms during collection.

Check this [PR](https://github.com/trustedsec/CS-Situational-Awareness-BOF/pull/114) to the SA BOF repo for BOFs that collect session and local group membership data and can be parsed by BOFHound.

### References

Blog Posts:

| Title| Date|
|------|-----|
| [*BOFHound: AD CS Integration*](https://medium.com/specter-ops-posts/bofhound-ad-cs-integration-91b706bc7958) | Oct 30, 2024 |
| [*BOFHound: Session Integration*](https://posts.specterops.io/bofhound-session-integration-7b88b6f18423) | Jan 30, 2024 |
| [*Granularize Your AD Recon Game Part 2*](https://web.archive.org/web/20221205144115/https://www.fortalicesolutions.com/posts/granularize-your-active-directory-reconnaissance-game-part-2) | Jun 15, 2022 |
| [*Granularize Your AD Recon Game*](https://web.archive.org/web/20220813221840/https://www.fortalicesolutions.com/posts/bofhound-granularize-your-active-directory-reconnaissance-game) | May 10, 2022  |

Presentations:

| Conference| Materials| Date|
|-----------|----------|-----|
| *SO-CON 2024*| [Slides](https://github.com/SpecterOps/presentations/blob/main/SO-CON%202024/Matt%20Creel%20%26%20Adam%20Brown%20-%20Manually%20Enumerating%20AD%20Attack%20Paths%20with%20BOFHound/Matt%20Creel%20and%20Adam%20Brown%20-%20Manually%20Enumerating%20AD%20Attack%20Paths%20With%20BOFHound%20-%20SO-CON%202024.pdf) & [Recording](https://www.youtube.com/watch?v=Xxm4YktSKVY)| Mar 11, 2024|

# Installation

BOFHound requires Python 3.10 or newer. Install the published package with:

```sh
python3 -m pip install bofhound
```

For a source checkout, see [Development](#development).

# Usage

Run `bofhound --help` for the full CLI reference. This README follows the development branch; use the README at your release tag when working with an older version.

Print the installed version with `bofhound --version` or `bofhound -V`:

```text
v0.5.1
```

The startup banner shows `bofhound v0.5.1` unless suppressed with `--quiet`. The version comes from the installed package metadata; if that metadata is unavailable, the version flags print `unknown`.

## Supported Inputs

Select a parser with `--parser`. Parser names are case-insensitive; the default is `ldapsearch`.

| Parser | Source | Files selected when `--input` is a directory |
| --- | --- | --- |
| `ldapsearch` | [TrustedSec ldapsearch BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF) output from Cobalt Strike, or pyldapsearch logs | `beacon*.log`; falls back to `*.log` if no beacon logs are found |
| `ldif` | Raw LDIF from the OpenLDAP ldapsearch client | `*.ldif`, `*.ldif.txt`, `*.txt`, `*.log` |
| `BRC4` | Brute Ratel LDAP Sentinel logs | `b-*.log` |
| `Havoc` | ldapsearch BOF output from Havoc | `Console_*.log` |
| `OutflankC2` | OutflankC2 JSON logs | `*.json` |
| `Mythic` | ldapsearch BOF output from Mythic callbacks | Uses `--mythic-server` and `--mythic-token` instead of local input files |

Directory searches are recursive and files are processed in modification-time order. An explicit input file bypasses the filename filters.

## Options

| Option | Purpose |
| --- | --- |
| `--input`, `-i` | Input file or directory. Defaults to `/opt/cobaltstrike/logs`; BRC4 and Havoc change that default to `/opt/bruteratel/logs` and `/opt/havoc/data/loot`, respectively. |
| `--output`, `-o` | Output directory; defaults to the current directory. |
| `--parser` | Input format; see the table above. |
| `--properties-level`, `-p` | `Standard` exports common BloodHound properties; `Member` also includes MemberOf and Member; `All` includes all properties. Defaults to `Member`; values are case-insensitive. |
| `--zip`, `-z` | Create a zip archive and remove the individual generated JSON files after archiving. With `--upload-only`, selects existing archives instead. |
| `--quiet`, `-q` | Hide the startup banner. |
| `--debug` | Enable debug output. |
| `--version`, `-V` | Print the installed version and exit before processing inputs. |
| `--help`, `-h` | Show CLI help. |

| Performance option | Purpose |
| --- | --- |
| `--workers N` | Worker count for file and ACL processing; defaults to about 90% of CPU cores. |
| `--no-cache` | Disable accumulated LDAP snapshots. |
| `--cache-file PATH` | Set the cache path; defaults to `bofhound_cache.db` inside the output directory. |
| `--cache-stats` | Show cache statistics and exit. |
| `--context-from PATH` | Load SID/domain/schema mappings and CA-host identities from a previous cache without exporting its objects. |

| Connection option | Purpose |
| --- | --- |
| `--mythic-server` | Mythic server IP or hostname; defaults to `127.0.0.1`. |
| `--mythic-token` | Mythic API token; required with the Mythic parser. |
| `--bh-server` | BloodHound CE URL; defaults to `http://127.0.0.1:8080`. |
| `--bh-token-id` | BloodHound API token ID. |
| `--bh-token-key` | BloodHound API token key. |
| `--upload-only` | Skip parsing and upload exports already in the output directory. |

See [Performance & Cache](#performance--cache) and [Uploading to BloodHound CE](#uploading-to-bloodhound-ce) for details.

## Example Usage

Parse ldapsearch BOF results from the default Cobalt Strike log directory and write exports to `/data/`:

```sh
bofhound -o /data/
```

Parse pyldapsearch logs and include all properties:

```sh
bofhound -i ~/.pyldapsearch/logs/ --properties-level all
```

Parse a raw LDIF file:

```sh
bofhound --parser ldif -i ./directory.ldif -o ./output
```

Parse LDAP Sentinel data from the default Brute Ratel log directory:

```sh
bofhound --parser brc4
```

Parse Havoc loot logs from the default directory and zip the resulting JSON files:

```sh
bofhound --parser havoc --zip
```

Parse OutflankC2 JSON logs:

```sh
bofhound --parser outflankc2 -i ./outflank-logs -o ./output
```

Read results from Mythic callbacks:

```sh
bofhound --parser mythic --mythic-server MYTHIC_HOST --mythic-token API_TOKEN -o ./output
```

## Uploading to BloodHound CE

Supply `--bh-server`, `--bh-token-id`, and `--bh-token-key` to upload after parsing.
BOFHound checks connectivity and credentials before parsing, then creates an upload
job after generating the files. Upload permissions are checked when that job starts.
Requests use a 10-second connect timeout and a 300-second read timeout.

Retry an upload without parsing the logs again:

```sh
bofhound --upload-only --output ./output \
  --bh-server http://127.0.0.1:8080 \
  --bh-token-id TOKEN_ID --bh-token-key TOKEN_KEY
```

This uploads all regular `*.json` files directly inside `--output` (default: current
directory). To upload existing `*.zip` archives instead, add `--zip`. In upload-only
mode, `--zip` selects archives; it does not create them. Use a directory containing
only the exports you intend to upload. Both token options are required; the server
defaults to `http://127.0.0.1:8080`.

An unsuccessful upload or job completion returns a nonzero exit status. Generated
files remain available for retrying; retrying a folder resends all selected files,
including any that were accepted in an earlier attempt. A successful exit confirms
upload acceptance and job completion, not the outcome of server-side ingestion.


## Performance & Cache

`--workers N` controls parallel file and ACL processing. Use `--workers 1` for
sequential processing. The default uses about 90% of available CPU cores. Actual pools are limited to the
number of tasks and the platform limit (61 processes on Windows). Files with
incomplete records and custom stateful parsers use sequential parsing to preserve
records spanning files. BRC4 and LDIF file parsing is always sequential; their ACL
processing can still use multiple workers. Pending tasks are bounded; input or ACL worker failures abort before output/cache updates.

Caching is enabled by default at `--output/bofhound_cache.db`; override it with
`--cache-file PATH`, disable it with `--no-cache`, or inspect it with `--cache-stats`.
The cache stores data-only raw LDAP snapshots. Each run combines cached and current
LDAP data and rebuilds relationships against that complete snapshot. It does not
skip ACL processing or reuse computed relationships, because newly collected
objects can change existing relationships.

Present attributes replace earlier values, including empty strings. Cached group
membership links follow known identities through renames and are removed when the
known target is displaced; explicitly supplied membership attributes use current DNs.
A freshly collected group member list takes precedence over stale cached memberOf
links, so those links cannot restore members explicitly removed from the group. Objects and
attributes absent from a partial collection remain cached; absence does not prove
deletion. Use a new cache file to start a fresh snapshot. Local sessions and local
group records are processed from the current logs and are not retained in the cache.
`--context-from PATH` loads SID/domain/schema mappings and CA-host identities from
a prior cache (or a directory containing `bofhound_cache.db`) without exporting its
objects. Current collected computers take precedence over cached host identities.
Legacy or incompatible cache versions are rejected without being loaded or changed;
choose a new cache path or remove the old database and rebuild from the original logs.

```sh
bofhound -i ./logs --output ./out --workers 4
bofhound -i ./logs --output ./out --no-cache
bofhound --output ./out --cache-stats
```

# Collecting ldapsearch BOF Data

The queries below use the ldapsearch BOF / pyldapsearch command syntax. OpenLDAP's `ldapsearch` executable uses different options; parse its LDIF output with `--parser ldif`.

Include `*,ntsecuritydescriptor` in the requested attributes to collect the security descriptors needed for ACL edges.

## Required Data

For users, groups, and computers, collect `samaccounttype`, `distinguishedname`, and `objectsid`. For objects identified by GUID, such as OUs, GPOs, and AD CS objects, also collect `objectguid` and `objectclass`. The available properties and relationships depend on what you collect; include domain objects and schema mappings for domain and ACL resolution.

Some object classes rely on domain objects being populated within BOFHound. Domains can be queried with either of the following commands
```
ldapsearch (objectclass=domain) --attributes *,ntsecuritydescriptor
ldapsearch (distinguishedname=DC=windomain,DC=local) --attributes *,ntsecuritydescriptor
```

## Example ldapsearch Queries
```
# Get All the Data (Maybe Run BloodHound Instead?)
ldapsearch (objectclass=*) --attributes *,ntsecuritydescriptor

# Retrieve All Schema Info
ldapsearch (schemaIDGUID=*) --attributes name,schemaidguid --dn CN=Schema,CN=Configuration,DC=windomain,DC=local

# Retrieve Only the ms-Mcs-AdmPwd schemaIDGUID
ldapsearch (name=ms-mcs-admpwd) --attributes name,schemaidguid --count 1 --dn CN=Schema,CN=Configuration,DC=windomain,DC=local

# Retrieve Domain NetBIOS Names (useful if collecting data via `netsession2/netloggedon2` BOFs)
ldapsearch (netbiosname=*) --dn "CN=Partitions,CN=Configuration,DC=windomain,DC=local"

# Unroll a group's nested members
ldapsearch (memberOf:1.2.840.113556.1.4.1941:=CN=TargetGroup,CN=Users,DC=windomain,DC=local) --attributes *,ntsecuritydescriptor

# Query domain trusts
ldapsearch (objectclass=trusteddomain) --attributes *,ntsecuritydescriptor

# Query across a trust
ldapsearch (objectclass=domain) --attributes *,ntsecuritydescriptor --hostname dc1.trusted.windomain.local --dn "DC=TRUSTED,DC=WINDOMAIN,DC=LOCAL"

#####
# Queries below populate objects for AD CS parsing

# Query the domain object
ldapsearch (objectclass=domain) --attributes *,ntsecuritydescriptor

# Query Enterprise CAs
ldapsearch (objectclass=pKIEnrollmentService) --attributes *,ntsecuritydescriptor --dn "CN=Configuration,DC=domain,DC=local"

# Query AIACAs, Root CAs and NTAuth Stores
ldapsearch (objectclass=certificationAuthority) --attributes *,ntsecuritydescriptor --dn "CN=Configuration,DC=domain,DC=local"

# Query Certificate Templates
ldapsearch (objectclass=pKICertificateTemplate) --attributes *,ntsecuritydescriptor --dn "CN=Configuration,DC=domain,DC=local"

# Query Issuance Policies
ldapsearch (objectclass=msPKI-Enterprise-Oid) --attributes *,ntsecuritydescriptor --dn "CN=Configuration,DC=domain,DC=local"
```

# Versions

See the [tagged releases](https://github.com/coffeegist/bofhound/releases) to download a specific version.

- v0.4.0 and onward support parsing AD CS objects and edges
- v0.3.0 and onward support session/local group data
- v0.2.1 and onward are compatible with BloodHound CE
- v0.2.0 is the last release supporting BloodHound Legacy

# Development
BOFHound uses Poetry to manage dependencies and the test environment. Set up a source checkout with:

```shell
git clone https://github.com/coffeegist/bofhound.git
cd bofhound
poetry install
poetry run bofhound --help
poetry run pytest -q
```

Release maintainers: see [the release guide](docs/RELEASING.md) for the manual GitHub Actions publishing process.

# References and Credits
- [@_dirkjan](https://twitter.com/_dirkjan) (and other contributors) for [BloodHound.py](https://github.com/fox-it/BloodHound.py)
- TrustedSec for [CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF)
- [P-aLu](https://github.com/P-aLu) for collaboration on BOFHound's [AD CS support](https://github.com/coffeegist/bofhound/pull/8)
