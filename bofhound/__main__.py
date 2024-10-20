import sys
import os

# Debug helpful
# root = os.path.abspath(os.path.dirname(os.path.abspath(__file__)) + "/..")
# if root not in sys.path:
#   sys.path.insert(0, root)
  
import logging
import typer
import glob
from bofhound.parsers import LdapSearchBofParser, Brc4LdapSentinelParser, GenericParser
from bofhound.writer import BloodHoundWriter
from bofhound.ad import ADDS
from bofhound.local import LocalBroker
from bofhound import console
from bofhound.ad.helpers import PropertiesLevel

app = typer.Typer(
    add_completion=False,
    rich_markup_mode="rich"
)

@app.command()
def main(
    input_files: str = typer.Option("/opt/cobaltstrike/logs", "--input", "-i", help="Directory or file containing logs of ldapsearch results. Will default to [green]/opt/bruteratel/logs[/] if --brute-ratel is specified"),
    output_folder: str = typer.Option(".", "--output", "-o", help="Location to export bloodhound files"),
    properties_level: PropertiesLevel = typer.Option(PropertiesLevel.Member.value, "--properties-level", "-p", case_sensitive=False, help='Change the verbosity of properties exported to JSON: Standard - Common BH properties | Member - Includes MemberOf and Member | All - Includes all properties'),
    brute_ratel: bool = typer.Option(False, "--brute-ratel", help="Parse logs from Brute Ratel's LDAP Sentinel"),
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

    # if BRc4 and input_files is the default, set it to the default BRc4 logs directory
    if brute_ratel and input_files == "/opt/cobaltstrike/logs":
        input_files = "/opt/bruteratel/logs"

    # default to Cobalt logfile naming format
    logfile_name_format = "beacon*.log"
    if brute_ratel:
        logfile_name_format = "b-*.log"

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

    parser = LdapSearchBofParser
    if brute_ratel:
        logging.debug('Using Brute Ratel parser')
        parser = Brc4LdapSentinelParser

    parsed_ldap_objects = []
    parsed_local_objects = []
    with console.status(f"", spinner="aesthetic") as status:
        for log in cs_logs:
            status.update(f" [bold] Parsing {log}")
            new_objects = parser.parse_file(log)
            new_local_objects = GenericParser.parse_file(log)
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
