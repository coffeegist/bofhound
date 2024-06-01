import os
import json
import codecs
import datetime
import logging
from zipfile import ZipFile
from pathlib import PurePath, Path
from bofhound import console
from bofhound.ad.models import BloodHoundDomain, BloodHoundComputer, BloodHoundUser, BloodHoundGroup, BloodHoundSchema, BloodHoundEnterpriseCA, BloodHoundAIACA, BloodHoundRootCA, BloodHoundCertTemplate, BloodHoundContainer

class BloodHoundWriter():
    files = []
    ct = None

    @staticmethod
    def write(out_dir='.', domains=None, computers=None, users=None,
          groups=None, ous=None, containers=None, gpos=None, enterprisecas=None, aiacas=None,
          rootcas=None, ntauthstores=None, issuancepolicies=None, certtemplates=None, 
          trusts=None, trustaccounts=None, common_properties_only=True, zip_files=False):

        os.makedirs(out_dir, exist_ok=True)
        BloodHoundWriter.ct = BloodHoundWriter.timestamp()

        if domains is not None:
            # print(BloodHoundSchema.ObjectTypeGuidMap)
            with console.status(" [bold] Writing domains to JSON...\n", spinner="aesthetic"):
                BloodHoundWriter.write_domain_file(out_dir, domains, common_properties_only)

        if computers is not None:
            with console.status(" [bold] Writing computers to JSON...\n", spinner="aesthetic"):
                BloodHoundWriter.write_computers_file(out_dir, computers, common_properties_only)

        if users is not None:
            with console.status(" [bold] Writing users to JSON...\n", spinner="aesthetic"):
                BloodHoundWriter.write_users_file(out_dir, users, common_properties_only)

        if groups is not None:
            with console.status(" [bold] Writing groups to JSON...\n", spinner="aesthetic"):
                BloodHoundWriter.write_groups_file(out_dir, groups, common_properties_only)

        if ous is not None:
            with console.status(" [bold] Writing OUs to JSON...\n", spinner="aesthetic"):
                BloodHoundWriter.write_ous_file(out_dir, ous, common_properties_only)
        
        if containers is not None:
            with console.status(" [bold] Writing Containers to JSON...\n", spinner="aesthetic"):
                BloodHoundWriter.write_containers_file(out_dir, containers, common_properties_only)

        if gpos is not None:
            with console.status(" [bold] Writing GPOs to JSON...\n", spinner="aesthetic"):
                BloodHoundWriter.write_gpos_file(out_dir, gpos, common_properties_only)

        if enterprisecas is not None:
            with console.status(" [bold] Writing Enterprise CAs to JSON...\n", spinner="aesthetic"):
                BloodHoundWriter.write_enterprisecas_file(out_dir, enterprisecas, common_properties_only)

        if aiacas is not None:
            with console.status(" [bold] Writing AIA CAs to JSON...\n", spinner="aesthetic"):
                BloodHoundWriter.write_aiacas_file(out_dir, aiacas, common_properties_only)

        if rootcas is not None:
            with console.status(" [bold] Writing Root CAs to JSON...\n", spinner="aesthetic"):
                BloodHoundWriter.write_rootcas_file(out_dir, rootcas, common_properties_only)

        if ntauthstores is not None:
            with console.status(" [bold] Writing NTAuth Stores to JSON...\n", spinner="aesthetic"):
                BloodHoundWriter.write_ntauthstores_file(out_dir, ntauthstores, common_properties_only)

        if issuancepolicies is not None:
            with console.status(" [bold] Writing Issuance Policies to JSON...\n", spinner="aesthetic"):
                BloodHoundWriter.write_issuancepolicies_file(out_dir, issuancepolicies, common_properties_only)
        
        if certtemplates is not None:
            with console.status(" [bold] Writing Cert Templates to JSON...\n", spinner="aesthetic"):
                BloodHoundWriter.write_certtemplates_file(out_dir, certtemplates, common_properties_only)

        if trusts is not None:
            BloodHoundWriter.write_trusts_file(out_dir, trusts, common_properties_only)

        if trustaccounts is not None:
            BloodHoundWriter.write_trustaccounts_file(out_dir, trustaccounts, common_properties_only)

        if out_dir == ".":
            logging.info(f'JSON files written to current directory')
        else:
            logging.info(f'JSON files written to {out_dir}')

        if zip_files:
            zip_name = PurePath(out_dir, f"bloodhound_{BloodHoundWriter.ct}.zip")
            with ZipFile(zip_name, "w") as zip:
                for bh_file in BloodHoundWriter.files:
                    zip.write(bh_file, bh_file.name)
                    Path(bh_file).unlink()
            logging.info(f'Files compressed into {zip_name}')



    @staticmethod
    def write_domain_file(out_dir, domains, common_properties_only):
        if len(domains) == 0:
            return

        datastruct = {
            "data": [],
            "meta": {
                "type": "domains",
                "count": 0,
                "methods": 0,
                "version": 5
            }
        }

        for domain in domains:
            datastruct['data'].append(domain.to_json(common_properties_only))
            datastruct['meta']['count'] += 1

        out_file = PurePath(out_dir, f'domains_{BloodHoundWriter.ct}.json')
        BloodHoundWriter.files.append(out_file)
        with codecs.open(out_file, 'w', 'utf-8') as f:
            json.dump(datastruct, f, ensure_ascii=False)

    @staticmethod
    def write_computers_file(out_dir, computers, common_properties_only):
        if len(computers) == 0:
            return

        datastruct = {
            "data": [],
            "meta": {
                "type": "computers",
                "count": 0,
                "methods": 521215,
                "version": 6
            }
        }

        for computer in computers:
            datastruct['data'].append(computer.to_json(common_properties_only))
            datastruct['meta']['count'] += 1

        out_file = PurePath(out_dir, f'computers_{BloodHoundWriter.ct}.json')
        BloodHoundWriter.files.append(out_file)
        with codecs.open(out_file, 'w', 'utf-8') as f:
            json.dump(datastruct, f, ensure_ascii=False)


    @staticmethod
    def write_users_file(out_dir, users, common_properties_only):
        if len(users) == 0:
            return

        datastruct = {
            "data": [],
            "meta": {
                "type": "users",
                "count": 0,
                "methods": 521215,
                "version": 6
            }
        }

        for user in users:
            datastruct['data'].append(user.to_json(common_properties_only))
            datastruct['meta']['count'] += 1

        out_file = PurePath(out_dir, f'users_{BloodHoundWriter.ct}.json')
        BloodHoundWriter.files.append(out_file)
        with codecs.open(out_file, 'w', 'utf-8') as f:
            json.dump(datastruct, f, ensure_ascii=False)


    @staticmethod
    def write_groups_file(out_dir, groups, common_properties_only):
        if len(groups) == 0:
            return

        datastruct = {
            "data": [],
            "meta": {
                "type": "groups",
                "count": 0,
                "methods": 521215,
                "version": 6
            }
        }

        for group in groups:
            datastruct['data'].append(group.to_json(common_properties_only))
            datastruct['meta']['count'] += 1

        out_file = PurePath(out_dir, f'groups_{BloodHoundWriter.ct}.json')
        BloodHoundWriter.files.append(out_file)
        with codecs.open(out_file, 'w', 'utf-8') as f:
            json.dump(datastruct, f, ensure_ascii=False)

    
    @staticmethod
    def write_ous_file(out_dir, ous, common_properties_only):
        if len(ous) == 0:
            return

        datastruct = {
            "data": [],
            "meta": {
                "type": "ous",
                "count": 0,
                "methods": 521215,
                "version": 6
            }
        }

        for ou in ous:
            datastruct['data'].append(ou.to_json(common_properties_only))
            datastruct['meta']['count'] += 1

        out_file = PurePath(out_dir, f'ous_{BloodHoundWriter.ct}.json')
        BloodHoundWriter.files.append(out_file)
        with codecs.open(out_file, 'w', 'utf-8') as f:
            json.dump(datastruct, f, ensure_ascii=False)


    @staticmethod
    def write_containers_file(out_dir, containers, common_properties_only):
        if len(containers) == 0:
            return

        datastruct = {
            "data": [],
            "meta": {
                "type": "containers",
                "count": 0,
                "methods": 521215,
                "version": 6
            }
        }

        for container in containers:
            datastruct['data'].append(container.to_json(common_properties_only))
            datastruct['meta']['count'] += 1

        out_file = PurePath(out_dir, f'containers_{BloodHoundWriter.ct}.json')
        BloodHoundWriter.files.append(out_file)
        with codecs.open(out_file, 'w', 'utf-8') as f:
            json.dump(datastruct, f, ensure_ascii=False)


    @staticmethod
    def write_gpos_file(out_dir, gpos, common_properties_only):
        if len(gpos) == 0:
            return

        datastruct = {
            "data": [],
            "meta": {
                "type": "gpos",
                "count": 0,
                "methods": 0,
                "version": 5
            }
        }

        for gpo in gpos:
            datastruct['data'].append(gpo.to_json(common_properties_only))
            datastruct['meta']['count'] += 1

        out_file = PurePath(out_dir, f'gpos_{BloodHoundWriter.ct}.json')
        BloodHoundWriter.files.append(out_file)
        with codecs.open(out_file, 'w', 'utf-8') as f:
            json.dump(datastruct, f, ensure_ascii=False)

    @staticmethod
    def write_enterprisecas_file(out_dir, enterprisecas, common_properties_only):
        if len(enterprisecas) == 0:
            return

        datastruct = {
            "data": [],
            "meta": {
                "methods" : 521215,
                "type": "enterprisecas",
                "count": 0,
                "version": 6
            }
        }

        for enterpriseca in enterprisecas:
            datastruct['data'].append(enterpriseca.to_json(common_properties_only))
            datastruct['meta']['count'] += 1

        out_file = PurePath(out_dir, f'enterprisecas_{BloodHoundWriter.ct}.json')
        BloodHoundWriter.files.append(out_file)
        with codecs.open(out_file, 'w', 'utf-8') as f:
            json.dump(datastruct, f, ensure_ascii=False)

    @staticmethod
    def write_aiacas_file(out_dir, aiacas, common_properties_only):
        if len(aiacas) == 0:
            return

        datastruct = {
            "data": [],
            "meta": {
                "methods" : 521215,
                "type": "aiacas",
                "count": 0,
                "version": 6
            }
        }

        for aiaca in aiacas:
            datastruct['data'].append(aiaca.to_json(common_properties_only))
            datastruct['meta']['count'] += 1

        out_file = PurePath(out_dir, f'aiacas_{BloodHoundWriter.ct}.json')
        BloodHoundWriter.files.append(out_file)
        with codecs.open(out_file, 'w', 'utf-8') as f:
            json.dump(datastruct, f, ensure_ascii=False)

    
    @staticmethod
    def write_rootcas_file(out_dir, rootcas, common_properties_only):
        if len(rootcas) == 0:
            return

        datastruct = {
            "data": [],
            "meta": {
                "methods" : 521215,
                "type": "rootcas",
                "count": 0,
                "version": 6
            }
        }

        for rootca in rootcas:
            datastruct['data'].append(rootca.to_json(common_properties_only))
            datastruct['meta']['count'] += 1

        out_file = PurePath(out_dir, f'rootcas_{BloodHoundWriter.ct}.json')
        BloodHoundWriter.files.append(out_file)
        with codecs.open(out_file, 'w', 'utf-8') as f:
            json.dump(datastruct, f, ensure_ascii=False)

    
    @staticmethod
    def write_ntauthstores_file(out_dir, ntauthstores, common_properties_only):
        if len(ntauthstores) == 0:
            return

        datastruct = {
            "data": [],
            "meta": {
                "methods" : 0,
                "type": "ntauthstores",
                "count": 0,
                "version": 6
            }
        }

        for ntauthstore in ntauthstores:
            datastruct['data'].append(ntauthstore.to_json(common_properties_only))
            datastruct['meta']['count'] += 1

        out_file = PurePath(out_dir, f'ntauthstores_{BloodHoundWriter.ct}.json')
        BloodHoundWriter.files.append(out_file)
        with codecs.open(out_file, 'w', 'utf-8') as f:
            json.dump(datastruct, f, ensure_ascii=False)


    @staticmethod
    def write_issuancepolicies_file(out_dir, issuancepolicies, common_properties_only):
        if len(issuancepolicies) == 0:
            return

        datastruct = {
            "data": [],
            "meta": {
                "methods" : 0,
                "type": "issuancepolicies",
                "count": 0,
                "version": 6
            }
        }

        for issuancepolicy in issuancepolicies:
            datastruct['data'].append(issuancepolicy.to_json(common_properties_only))
            datastruct['meta']['count'] += 1

        out_file = PurePath(out_dir, f'issuancepolicies_{BloodHoundWriter.ct}.json')
        BloodHoundWriter.files.append(out_file)
        with codecs.open(out_file, 'w', 'utf-8') as f:
            json.dump(datastruct, f, ensure_ascii=False)

    
    @staticmethod
    def write_certtemplates_file(out_dir, certtemplates, common_properties_only):
        if len(certtemplates) == 0:
            return

        datastruct = {
            "data": [],
            "meta": {
                "methods": 521215,
                "type": "certtemplates",
                "count": 0,
                "version": 6
            }
        }

        for certtemplate in certtemplates:
            datastruct['data'].append(certtemplate.to_json(common_properties_only))
            datastruct['meta']['count'] += 1

        out_file = PurePath(out_dir, f'certtemplates_{BloodHoundWriter.ct}.json')
        BloodHoundWriter.files.append(out_file)
        with codecs.open(out_file, 'w', 'utf-8') as f:
            json.dump(datastruct, f, ensure_ascii=False)


    @staticmethod
    def write_trusts_file(out_dir, trusts, common_properties_only):
        pass


    @staticmethod
    def write_trustaccounts_file(out_dir, trustaccounts, common_properties_only):
        pass

    @staticmethod
    def timestamp():
        ct = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        return ct
