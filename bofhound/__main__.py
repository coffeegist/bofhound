import sys
import os
import logging
import typer
import glob
from bofhound.parsers import LdapSearchBofParser, Brc4LdapSentinelParser, HavocParser, ParserType, OutflankC2JsonParser
from bofhound.writer import BloodHoundWriter
from bofhound.ad import ADDS
from bofhound.local import LocalBroker
from bofhound import console
from bofhound.ad.helpers import PropertiesLevel

app = typer.Typer(
    add_completion=False,
    rich_markup_mode="rich",
    context_settings={'help_option_names': ['-h', '--help']}
)

@app.command()
def main(
    input_files: str = typer.Option("/opt/cobaltstrike/logs", "--input", "-i", help="Directory or file containing logs of ldapsearch results"),
    output_folder: str = typer.Option(".", "--output", "-o", help="Location to export bloodhound files"),
    properties_level: PropertiesLevel = typer.Option(PropertiesLevel.Member.value, "--properties-level", "-p", case_sensitive=False, help='Change the verbosity of properties exported to JSON: Standard - Common BH properties | Member - Includes MemberOf and Member | All - Includes all properties'),
    parser: ParserType = typer.Option(ParserType.LdapsearchBof.value, "--parser", case_sensitive=False, help="Parser to use for log files. ldapsearch parser (default) supports ldapsearch BOF logs from Cobalt Strike and pyldapsearch logs"),
    debug: bool = typer.Option(False, "--debug", help="Enable debug output"),
    zip_files: bool = typer.Option(False, "--zip", "-z", help="Compress the JSON output files into a zip archive")):
    """
    Generate BloodHound compatible JSON from logs written by ldapsearch BOF, pyldapsearch and Brute Ratel's LDAP Sentinel
    """

    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    banner()

     # default to Cobalt logfile naming format
    logfile_name_format = "beacon*.log"

    match parser:
        
        case ParserType.LdapsearchBof:
            logging.debug('Using ldapsearch parser')
            parser = LdapSearchBofParser
        
        case ParserType.BRC4:
            logging.debug('Using Brute Ratel parser')
            parser = Brc4LdapSentinelParser
            logfile_name_format = "b-*.log"
            if input_files == "/opt/cobaltstrike/logs":
                input_files = "/opt/bruteratel/logs"

        case ParserType.HAVOC:
            logging.debug('Using Havoc parser')
            parser = HavocParser
            logfile_name_format = "Console_*.log"
            if input_files == "/opt/cobaltstrike/logs":
                input_files = "/opt/havoc/data/loot"

        case ParserType.OUTFLANKC2:
            logging.debug('Using OutflankC2 parser')
            parser = OutflankC2JsonParser
            logfile_name_format = "*.json"
        
        case _:
            raise ValueError(f"Unknown parser type: {parser}")
        
    if os.path.isfile(input_files):
        cs_logs = [input_files]
        logging.debug(f"Log file explicitly provided {input_files}")
    elif os.path.isdir(input_files):
        # recurisively get a list of all .log files in the input directory, sorted by last modified time
        cs_logs = glob.glob(f"{input_files}/**/{logfile_name_format}", recursive=True)
        if len(cs_logs) == 0:
            # check for ldapsearch python logs
            cs_logs = glob.glob(f"{input_files}/pyldapsearch*.log", recursive=True)

        cs_logs.sort(key=os.path.getmtime)

        if len(cs_logs) == 0:
            logging.error(f"No log files found in {input_files}!")
            return
        else:
            logging.info(f"Located {len(cs_logs)} beacon log files")
    else:
        logging.error(f"Could not find {input_files} on disk")
        sys.exit(-1)

    parsed_ldap_objects = []
    parsed_local_objects = []
    with console.status(f"", spinner="aesthetic") as status:
        for log in cs_logs:
            status.update(f" [bold] Parsing {log}")
            formatted_data = parser.prep_file(log)
            new_objects = parser.parse_data(formatted_data)
            
            # jank insert to reparse outflank logs for local data
            if parser == OutflankC2JsonParser:
                new_local_objects = parser.parse_local_objects(log)
            else:
                new_local_objects = parser.parse_local_objects(formatted_data)
            
            logging.debug(f"Parsed {log}")
            logging.debug(f"Found {len(new_objects)} objects in {log}")
            parsed_ldap_objects.extend(new_objects)
            parsed_local_objects.extend(new_local_objects)

    logging.info(f"Parsed {len(parsed_ldap_objects)} LDAP objects from {len(cs_logs)} log files")
    logging.info(f"Parsed {len(parsed_local_objects)} local group/session objects from {len(cs_logs)} log files")

    ad = ADDS()
    broker = LocalBroker()

    logging.info("Sorting parsed objects by type...")
    ad.import_objects(parsed_ldap_objects)
    broker.import_objects(parsed_local_objects, ad.DOMAIN_MAP.values())

    logging.info(f"Parsed {len(ad.users)} Users")
    logging.info(f"Parsed {len(ad.groups)} Groups")
    logging.info(f"Parsed {len(ad.computers)} Computers")
    logging.info(f"Parsed {len(ad.domains)} Domains")
    logging.info(f"Parsed {len(ad.trustaccounts)} Trust Accounts")
    logging.info(f"Parsed {len(ad.ous)} OUs")
    logging.info(f"Parsed {len(ad.containers)} Containers")
    logging.info(f"Parsed {len(ad.gpos)} GPOs")
    logging.info(f"Parsed {len(ad.enterprisecas)} Enterprise CAs")
    logging.info(f"Parsed {len(ad.aiacas)} AIA CAs")
    logging.info(f"Parsed {len(ad.rootcas)} Root CAs")
    logging.info(f"Parsed {len(ad.ntauthstores)} NTAuth Stores")
    logging.info(f"Parsed {len(ad.issuancepolicies)} Issuance Policies")
    logging.info(f"Parsed {len(ad.certtemplates)} Cert Templates")
    logging.info(f"Parsed {len(ad.schemas)} Schemas")
    logging.info(f"Parsed {len(ad.CROSSREF_MAP)} Referrals")
    logging.info(f"Parsed {len(ad.unknown_objects)} Unknown Objects")
    logging.info(f"Parsed {len(broker.sessions)} Sessions")
    logging.info(f"Parsed {len(broker.privileged_sessions)} Privileged Sessions")
    logging.info(f"Parsed {len(broker.registry_sessions)} Registry Sessions")
    logging.info(f"Parsed {len(broker.local_group_memberships)} Local Group Memberships")

    ad.process()
    ad.process_local_objects(broker)

    BloodHoundWriter.write(
        output_folder,
        domains=ad.domains,
        computers=ad.computers,
        users=ad.users,
        groups=ad.groups,
        ous=ad.ous,
        containers=ad.containers,
        gpos=ad.gpos,
        enterprisecas=ad.enterprisecas,
        aiacas=ad.aiacas,
        rootcas=ad.rootcas,
        ntauthstores=ad.ntauthstores,
        issuancepolicies=ad.issuancepolicies,
        certtemplates = ad.certtemplates,
        properties_level=properties_level,
        zip_files=zip_files
    )


def banner():
    print('''
 _____________________________ __    __    ______    __    __   __   __   _______
|   _   /  /  __   / |   ____/|  |  |  |  /  __  \\  |  |  |  | |  \\ |  | |       \\
|  |_)  | |  |  |  | |  |__   |  |__|  | |  |  |  | |  |  |  | |   \\|  | |  .--.  |
|   _  <  |  |  |  | |   __|  |   __   | |  |  |  | |  |  |  | |  . `  | |  |  |  |
|  |_)  | |  `--'  | |  |     |  |  |  | |  `--'  | |  `--'  | |  |\\   | |  '--'  |
|______/   \\______/  |__|     |__|  |___\\_\\________\\_\\________\\|__| \\___\\|_________\\

                            << @coffeegist | @Tw1sm >>
    ''')


if __name__ == "__main__":
    app(prog_name="bofhound")
