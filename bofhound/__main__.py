"""Entry point for bofhound CLI application."""
import sys
import logging
import typer
from bofhound.parsers import ParserType, ParsingPipelineFactory
from bofhound.parsers.data_sources import FileDataSource, MythicDataSource, OutflankDataStream
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
    input_files: str = typer.Option(
        "/opt/cobaltstrike/logs", "--input", "-i",
        help="Directory or file containing logs of ldapsearch results"
    ),
    output_folder: str = typer.Option(
        ".", "--output", "-o", help="Location to export bloodhound files"
    ),
    properties_level: PropertiesLevel = typer.Option(
        PropertiesLevel.Member.value, "--properties-level", "-p", case_sensitive=False,
        help=("Change the verbosity of properties exported to JSON: "
              "Standard - Common BH properties | Member - Includes MemberOf and Member | "
              "All - Includes all properties")
    ),
    parser_type: ParserType = typer.Option(
        ParserType.LdapsearchBof.value, "--parser", case_sensitive=False,
        help=("Parser to use for log files. ldapsearch parser (default) supports ldapsearch BOF "
              "logs from Cobalt Strike and pyldapsearch logs")
    ),
    debug: bool = typer.Option(False, "--debug", help="Enable debug output"),
    zip_files: bool = typer.Option(
        False, "--zip", "-z",
        help="Compress the JSON output files into a zip archive"
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress banner"),
    mythic_server: str = typer.Option(
        "127.0.0.1", "--mythic-server", help="IP or hostname of Mythic server to connect to",
        rich_help_panel="Mythic Options"
    ),
    mythic_token: str = typer.Option(
        None, "--mythic-token", help="Mythic API token", rich_help_panel="Mythic Options"
    ),
    bh_token_id: str = typer.Option(
        None, "--bh-token-id", help="BloodHound API token ID",
        rich_help_panel="BloodHound CE Options"
    ),
    bh_token_key: str = typer.Option(
        None, "--bh-token-key", help="BloodHound API token key",
        rich_help_panel="BloodHound CE Options"
    ),
    bh_server: str = typer.Option(
        "http://127.0.0.1:8080", "--bh-server", help="BloodHound CE URL",
        rich_help_panel="BloodHound CE Options"
    )):
    """
    Generate BloodHound compatible JSON from logs written by the ldapsearch BOF, pyldapsearch and
    specific C2 frameworks
    """

    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    if not quiet:
        banner()

     # default to Cobalt logfile naming format
    data_source = None

    match parser_type:

        case ParserType.LdapsearchBof:
            logger.debug("Using ldapsearch parser")
            data_source = FileDataSource(str(input_files), "beacon*.log")

            # if no CS logs were found, search for pyldapsearch logs or SoaPy logs
            if len(list(data_source.get_data_streams())) == 0:
                data_source = FileDataSource(str(input_files), "*.log")

        case ParserType.BRC4:
            logger.debug("Using Brute Ratel parser")
            if input_files == "/opt/cobaltstrike/logs":
                input_files = "/opt/bruteratel/logs"
            data_source = FileDataSource(str(input_files), "b-*.log")

        case ParserType.HAVOC:
            logger.debug("Using Havoc parser")
            if input_files == "/opt/cobaltstrike/logs":
                input_files = "/opt/havoc/data/loot"
            data_source = FileDataSource(str(input_files), "Console_*.log")

        case ParserType.OUTFLANKC2:
            logger.debug("Using OutflankC2 parser")
            data_source = FileDataSource(
                str(input_files), "*.json", stream_type=OutflankDataStream
            )

        case ParserType.MYTHIC:
            logger.debug("Using Mythic parser")
            if mythic_token is None:
                logger.error("Mythic server and API token must be provided")
                sys.exit(-1)
            data_source = MythicDataSource(mythic_server, mythic_token)

        case _:
            raise ValueError(f"Unknown parser type: {parser_type}")

    ad = ADDS()
    broker = LocalBroker()
    pipeline = ParsingPipelineFactory.create_pipeline(parser_type=parser_type)

    with console.status("", spinner="aesthetic") as status:
        results = pipeline.process_data_source(
            data_source,
            progress_callback=lambda id: status.update(f"Processing {id}")
        )

    ldap_objects = results.get_ldap_objects()
    local_objects = results.get_local_group_memberships() + results.get_sessions() + \
        results.get_privileged_sessions() + results.get_registry_sessions()
    logger.info("Parsed %d LDAP objects", len(ldap_objects))
    logger.info("Parsed %d local group/session objects", len(local_objects))
    logger.info("Sorting parsed objects by type...")

    ad.import_objects(ldap_objects)
    broker.import_objects(results, ad.DOMAIN_MAP.values())

    logger.info("Parsed %d Users", len(ad.users))
    logger.info("Parsed %d Groups", len(ad.groups))
    logger.info("Parsed %d Computers", len(ad.computers))
    logger.info("Parsed %d Domains", len(ad.domains))
    logger.info("Parsed %d Trust Accounts", len(ad.trustaccounts))
    logger.info("Parsed %d OUs", len(ad.ous))
    logger.info("Parsed %d Containers", len(ad.containers))
    logger.info("Parsed %d GPOs", len(ad.gpos))
    logger.info("Parsed %d Enterprise CAs", len(ad.enterprisecas))
    logger.info("Parsed %d AIA CAs", len(ad.aiacas))
    logger.info("Parsed %d Root CAs", len(ad.rootcas))
    logger.info("Parsed %d NTAuth Stores", len(ad.ntauthstores))
    logger.info("Parsed %d Issuance Policies", len(ad.issuancepolicies))
    logger.info("Parsed %d Cert Templates", len(ad.certtemplates))
    logger.info("Parsed %d Schemas", len(ad.schemas))
    logger.info("Parsed %d Referrals", len(ad.CROSSREF_MAP))
    logger.info("Parsed %d DNS nodes", len(ad.DNSNODE_MAP))
    logger.info("Parsed %d Unknown Objects", len(ad.unknown_objects))
    logger.info("Parsed %d Sessions", len(broker.sessions))
    logger.info("Parsed %d Privileged Sessions", len(broker.privileged_sessions))
    logger.info("Parsed %d Registry Sessions", len(broker.registry_sessions))
    logger.info("Parsed %d Local Group Memberships", len(broker.local_group_memberships))

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
        with console.status("", spinner="aesthetic") as status:
            status.update(" [bold] Uploading files to BloodHound server...")
            uploader = BloodHoundUploader(bh_server, bh_token_id, bh_token_key)

            if not uploader.create_upload_job():
                return

            for file in outfiles:
                uploader.upload_file(file)

            uploader.close_upload_job()
        logger.info("Files uploaded to BloodHound server")


def banner():
    """Display the bofhound banner."""
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
