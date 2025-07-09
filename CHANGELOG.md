# Changelog
## [0.4.10] - 7/9/2025
### Changed
- Targeted logfile name syntax changed to be more generic (no longer tied to pyldapsearch) to work with SoaPy

## [0.4.9] - 6/25/2025
### Added
- Support for pasing ldapsearch BOF results from Mythic C2 callbacks
- Ability to upload output files directly to BHCE

## [0.4.8] - 5/12/2025
### Fixed
- Check for `operatingsystemservicepack` property to prevent key error - [merge #30](https://github.com/coffeegist/bofhound/pull/30)
- Check for `CertTemplates` property to prevent type error - [merge #31](https://github.com/coffeegist/bofhound/pull/31)

## [0.4.7] - 04/29/2025
### Added
- Ability to handle schemaIdGuids from ADExplorer LDIF output

### Fixed
- Improved fix for [#12](https://github.com/coffeegist/bofhound/issues/12) by keying on the `securityIdentifier` attribute on trust objects

## [0.4.6] - 04/07/2025
#### Fixed
- Removed log statement clogging debug output [#19](https://github.com/coffeegist/bofhound/issues/19) 
- Update deprecated pyproject.toml syntax [#20](https://github.com/coffeegist/bofhound/issues/20) 

## [0.4.5] - 12/17/2024
#### Added
- Support for pasing ldapsearch BOF results within OutflankC2 log files

## [0.4.4] - 12/13/2024
### Fixed
- Addressed [#13](https://github.com/coffeegist/bofhound/issues/13)
- Catch error is ACL paring fails for an object 

## [0.4.3] - 10/30/2024
### Added
- Support for pasing ldapsearch BOF results within Havoc log files

### Changed
- Parsers now can inherit from the `LdapSearchBofParser` (since support for other C2s usually still relies on the same BOF) to cut down on code copypasta
- The `GenericParser` class (used to parse local group memberships, session data) is now called from main parsers (`LdapSearchBofParser`, `HavocParser`, etc.) to prevent each logfile from being opened, read, formatted, and parsed twice (each file is now read once and just parsed twice, once for LDAP objects and once for local objects)

## [0.4.2] - 10/24/2024
### Fixed
- Addressed [#12](https://github.com/coffeegist/bofhound/issues/12), an issue with duplicate trusted domain objects

## [0.4.1] - 10/22/2024
### Fixed
- Addressed [#10](https://github.com/coffeegist/bofhound/issues/10), an issue with the `ContainedBy` attribute in output JSON

## [0.4.0] - 10/20/2024
### Added
- Models for ADCS objects and abuse
    - AIACAs
    - Root CAs
    - Enterprise CAs
    - Certificate Templates
    - Issuance Policies
    - NTAuth Stores

### Changed
- Split `--all-properties` into 3 levels of properties
    - `Standard` to closely mirror object attributes shown by SharpHound/BHCE
    - `Member` to include `member` and `memberOf` properties (and a few others)
    - `All` to include all properties parsed by bofhound

## [0.3.1] - 1/25/2024
### Fixed
- GPO JSON file not matching JSON definition for BHCE
    - `domainsid` property gets set on all GPO objects now (requires domain objects to be queried)

## [0.3.0] - 12/27/2023
### Added
- ADDS model for AD crossRef objects (referrals)
- Models for Local objects (sessions and local group memberships) 
- Parsers for registry sessions, privileged sessions, sessions and local group memberships
- ADDS processing logic to tie local group/session data to a computer object

## [0.2.1] - 08/09/2023
### Changed
- Updated output JSON to v5 (BloodHound CE) specs

## [0.2.0] - 03/28/2023
### Added
- New parser to support parsing LDAP Sentinel data from BRc4 logs

### Changed
- Modified logic for how group memberships are determined
    - Prior method was iterate through DNs in groups' `member` attribute and adding objects with matching DNs
    - Since BRc4 does not store DNs in the `member` attibute, added iteration over objects' `memberOf` attribute and add to groups with matching DN (i.e. membership is now calculated from both sides of relationship)

## [v0.1.2] - 2/10/2023
### Changed
- Updated ACL parsing function to current version BloodHound.py
- Updated `typer` and `bloodhound-python` dependencies
- Added the `memberof` attrbute to the common properties displayed for users, computers and groups

## [v0.1.1] - 8/11/2022
### Fixed
- Bug where domain trusts queried more than once would appear duplicated in the BH UI

## [v0.1.0] - 6/9/2022
### Added
- Parsing support for Group Policy Objects
- Parsing support for Organizational Unit objects
- Parsing support for Trusted Domain objects

### Fixed
- Bug causing crash when handling non-base64 encoded SchemaIDGUID/nTSecurityDescriptor attributes

## [v0.0.1] - 5/9/2022
### Added
- Prepped for initial release and PyPI package
