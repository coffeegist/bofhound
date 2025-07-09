import sys
import os
import logging
import typer
import glob
from syncer import sync

from bofhound.parsers import LdapSearchBofParser, Brc4LdapSentinelParser, HavocParser, \
    ParserType, OutflankC2JsonParser, MythicParser
from bofhound.writer import BloodHoundWriter
from bofhound.uploader import BloodHoundUploader
from bofhound.ad import ADDS
from bofhound.local import LocalBroker
from bofhound import console
from bofhound.ad.helpers import PropertiesLevel
from bofhound.logger import logger

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
    zip_files: bool = typer.Option(False, "--zip", "-z", help="Compress the JSON output files into a zip archive"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress banner"),
    mythic_server: str = typer.Option("127.0.0.1", "--mythic-server", help="IP or hostname of Mythic server to connect to", rich_help_panel="Mythic Options"),
    mythic_token: str = typer.Option(None, "--mythic-token", help="Mythic API token", rich_help_panel="Mythic Options"),
    bh_token_id: str = typer.Option(None, "--bh-token-id", help="BloodHound API token ID", rich_help_panel="BloodHound CE Options"),
    bh_token_key: str = typer.Option(None, "--bh-token-key", help="BloodHound API token key", rich_help_panel="BloodHound CE Options"),
    bh_server: str = typer.Option("http://127.0.0.1:8080", "--bh-server", help="BloodHound CE URL", rich_help_panel="BloodHound CE Options")):
    """
    Generate BloodHound compatible JSON from logs written by the ldapsearch BOF, pyldapsearch and specific C2 frameworks
    """

    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    if not quiet:
        banner()

     # default to Cobalt logfile naming format
    logfile_name_format = "beacon*.log"

    match parser:
        
        case ParserType.LdapsearchBof:
            logger.debug("Using ldapsearch parser")
            parser = LdapSearchBofParser
        
        case ParserType.BRC4:
            logger.debug("Using Brute Ratel parser")
            parser = Brc4LdapSentinelParser
            logfile_name_format = "b-*.log"
            if input_files == "/opt/cobaltstrike/logs":
                input_files = "/opt/bruteratel/logs"

        case ParserType.HAVOC:
            logger.debug("Using Havoc parser")
            parser = HavocParser
            logfile_name_format = "Console_*.log"
            if input_files == "/opt/cobaltstrike/logs":
                input_files = "/opt/havoc/data/loot"

        case ParserType.OUTFLANKC2:
            logger.debug("Using OutflankC2 parser")
            parser = OutflankC2JsonParser
            logfile_name_format = "*.json"

        case ParserType.MYTHIC:
            logger.debug("Using Mythic parser")
            parser = MythicParser()
            if mythic_token is None:
                logger.error("Mythic server and API token must be provided")
                sys.exit(-1)
            #
            # instead of iteraitng over log files on disk, we'll iterate over
            # Mythic callback objects
            #
            sync(parser.connect(mythic_server, mythic_token))
            cs_logs = sync(parser.collect_callbacks())

        
        case _:
            raise ValueError(f"Unknown parser type: {parser}")

    if os.path.isfile(input_files):
        cs_logs = [input_files]
        logger.debug(f"Log file explicitly provided {input_files}")
    elif os.path.isdir(input_files):
        # recurisively get a list of all .log files in the input directory, sorted by last modified time
        cs_logs = glob.glob(f"{input_files}/**/{logfile_name_format}", recursive=True)
        if len(cs_logs) == 0:
            # check for pyldapsearch/soapy logs
            cs_logs = glob.glob(f"{input_files}/*.log", recursive=True)

        cs_logs.sort(key=os.path.getmtime)

        if len(cs_logs) == 0:
            logger.error(f"No log files found in {input_files}!")
            return
        else:
            logger.info(f"Located {len(cs_logs)} beacon log files")
    else:
        if not isinstance(parser, MythicParser):
            logger.error(f"Could not find {input_files} on disk")
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
            
            logger.debug(f"Parsed {log}")
            logger.debug(f"Found {len(new_objects)} objects in {log}")
            parsed_ldap_objects.extend(new_objects)
            parsed_local_objects.extend(new_local_objects)

    logger.info(f"Parsed {len(parsed_ldap_objects)} LDAP objects from {len(cs_logs)} log files")
    logger.info(f"Parsed {len(parsed_local_objects)} local group/session objects from {len(cs_logs)} log files")

    ad = ADDS()
    broker = LocalBroker()

    logger.info("Sorting parsed objects by type...")
    ad.import_objects(parsed_ldap_objects)
    broker.import_objects(parsed_local_objects, ad.DOMAIN_MAP.values())

    logger.info(f"Parsed {len(ad.users)} Users")
    logger.info(f"Parsed {len(ad.groups)} Groups")
    logger.info(f"Parsed {len(ad.computers)} Computers")
    logger.info(f"Parsed {len(ad.domains)} Domains")
    logger.info(f"Parsed {len(ad.trustaccounts)} Trust Accounts")
    logger.info(f"Parsed {len(ad.ous)} OUs")
    logger.info(f"Parsed {len(ad.containers)} Containers")
    logger.info(f"Parsed {len(ad.gpos)} GPOs")
    logger.info(f"Parsed {len(ad.enterprisecas)} Enterprise CAs")
    logger.info(f"Parsed {len(ad.aiacas)} AIA CAs")
    logger.info(f"Parsed {len(ad.rootcas)} Root CAs")
    logger.info(f"Parsed {len(ad.ntauthstores)} NTAuth Stores")
    logger.info(f"Parsed {len(ad.issuancepolicies)} Issuance Policies")
    logger.info(f"Parsed {len(ad.certtemplates)} Cert Templates")
    logger.info(f"Parsed {len(ad.schemas)} Schemas")
    logger.info(f"Parsed {len(ad.CROSSREF_MAP)} Referrals")
    logger.info(f"Parsed {len(ad.unknown_objects)} Unknown Objects")
    logger.info(f"Parsed {len(broker.sessions)} Sessions")
    logger.info(f"Parsed {len(broker.privileged_sessions)} Privileged Sessions")
    logger.info(f"Parsed {len(broker.registry_sessions)} Registry Sessions")
    logger.info(f"Parsed {len(broker.local_group_memberships)} Local Group Memberships")

    ad.process()
    ad.process_local_objects(broker)

    #
    # Write out the BloodHound JSON files
    #
    outfiles = BloodHoundWriter.write(
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

    #
    # Upload files to BloodHound CE
    #
    if bh_token_id and bh_token_key and bh_server:
        with console.status(f"", spinner="aesthetic") as status:
            status.update(f" [bold] Uploading files to BloodHound server...")
            uploader = BloodHoundUploader(bh_server, bh_token_id, bh_token_key)
            
            if not uploader.create_upload_job():
                return

            for file in outfiles:
                uploader.upload_file(file)

            uploader.close_upload_job()
        logger.info("Files uploaded to BloodHound server")


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
