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
from bofhound.cache import ObjectCache

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
    no_cache: bool = typer.Option(
        False, "--no-cache",
        help="Disable object caching (cache is enabled by default)",
        rich_help_panel="Performance Options"
    ),
    cache_file: str = typer.Option(
        None, "--cache-file",
        help="Custom path to cache database (default: bofhound_cache.db in output folder)",
        rich_help_panel="Performance Options"
    ),
    context_from: str = typer.Option(
        None, "--context-from",
        help="Load SID/domain context from a previous run's cache file for ACL resolution. Use when processing late data (e.g., certificates) separately.",
        rich_help_panel="Performance Options"
    ),
    workers: int = typer.Option(
        None, "--workers",
        help='Number of worker processes for parallel ACL parsing. Default: ~90%% of CPU cores (auto-detected). Check your system: python -c "import os; print(f\'CPU cores: {os.cpu_count()}\')"',
        rich_help_panel="Performance Options"
    ),
    cache_stats: bool = typer.Option(
        False, "--cache-stats",
        help="Display cache statistics and exit",
        rich_help_panel="Performance Options"
    ),
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

    # Handle cache stats display
    if cache_stats:
        # Determine cache file path
        if not cache_file:
            cache_file = f"{output_folder}/bofhound_cache.db"
        
        import os
        if not os.path.exists(cache_file):
            console.print(f"[yellow]Cache file not found: {cache_file}[/yellow]")
            console.print("Run bofhound first to create the cache.")
            sys.exit(0)
        
        try:
            with ObjectCache(cache_file) as cache:
                stats = cache.get_statistics()
                console.print("\n[bold cyan]Cache Statistics[/bold cyan]")
                console.print(f"Cache file: {cache_file}")
                console.print(f"Version: {stats['cache_version']}")
                console.print(f"Total objects: {stats['total_objects']:,}")
                console.print("\n[bold]Objects by type:[/bold]")
                for obj_type, count in sorted(stats['by_type'].items(), key=lambda x: x[1], reverse=True):
                    console.print(f"  {obj_type}: {count:,}")
                console.print(f"\nCache size: {stats['file_size_mb']} MB")
                console.print(f"Created: {stats.get('created_at', 'Unknown')}")
                console.print(f"Last accessed: {stats.get('last_accessed', 'Unknown')}")
        except Exception as e:
            console.print(f"[red]Error reading cache: {e}[/red]")
            sys.exit(1)
        return

    if not quiet:
        banner()

    # Auto-detect worker count if not specified
    import os
    cpu_count = os.cpu_count() or 4
    
    if workers is None:
        # Use ~90% of cores by default - leave headroom for OS and other processes
        workers = max(1, int(cpu_count * 0.9))
    elif workers < 1:
        console.print("[red]Error: --workers must be at least 1[/red]")
        sys.exit(1)
    elif workers > cpu_count:
        console.print(f"[yellow]Warning: {workers} workers exceeds CPU count ({cpu_count})[/yellow]")
        console.print("This may reduce performance. Recommended: --workers {}".format(int(cpu_count * 0.9)))
    
    # Log worker and CPU info in one line
    worker_pct = int((workers / cpu_count) * 100)
    logger.info(f"Using {workers}/{cpu_count} CPU cores ({worker_pct}%)")

    # Create output directory if it doesn't exist
    os.makedirs(output_folder, exist_ok=True)

    # Initialize cache (enabled by default unless --no-cache)
    cache = None
    if not no_cache:
        # Determine cache file path
        if not cache_file:
            cache_file = f"{output_folder}/bofhound_cache.db"
        
        cache_exists = os.path.exists(cache_file)
        
        try:
            cache = ObjectCache(cache_file)
            if cache_exists:
                stats = cache.get_statistics()
                logger.info(f"Found existing cache: {cache_file} ({stats['total_objects']:,} objects)")
                logger.info("Only new/changed objects will be processed (incremental mode)")
                logger.info("To disable caching, use --no-cache or delete/rename the cache file")
            else:
                logger.info(f"Creating new cache: {cache_file}")
        except Exception as e:
            logger.error(f"Failed to initialize cache: {e}")
            sys.exit(1)
    else:
        logger.info("Caching disabled (--no-cache)")

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
    
    # Load context from external cache if specified
    if context_from:
        import os
        context_cache_path = context_from
        
        # If directory, look for cache file inside it
        if os.path.isdir(context_from):
            context_cache_path = os.path.join(context_from, 'bofhound_cache.db')
        
        if not os.path.exists(context_cache_path):
            logger.error(f"Context cache file not found: {context_cache_path}")
            sys.exit(1)
        
        try:
            logger.info(f"Loading context from: {context_cache_path}")
            with ObjectCache(context_cache_path) as context_cache:
                ctx_stats = context_cache.get_context_statistics()
                if ctx_stats['sid_mappings'] == 0:
                    logger.warning("Context cache has no SID mappings - ACL resolution may be incomplete")
                else:
                    ad.load_context_from_cache(context_cache)
        except Exception as e:
            logger.error(f"Failed to load context: {e}")
            sys.exit(1)

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
    
    # Apply cache filtering (automatic when cache exists)
    if cache and ldap_objects:
        original_count = len(ldap_objects)
        stats = cache.get_statistics()
        if stats['total_objects'] > 0:
            logger.info("Filtering against cache (%d existing objects)...", stats['total_objects'])
            ldap_objects = cache.get_changed_objects(ldap_objects)
            logger.info("After cache filter: %d new/changed, %d skipped", 
                       len(ldap_objects), original_count - len(ldap_objects))
        else:
            logger.info("Cache is empty - all objects will be processed")
    
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
    logger.info("Parsed %d Unknown Objects", len(ad.unknown_objects))
    logger.info("Parsed %d Sessions", len(broker.sessions))
    logger.info("Parsed %d Privileged Sessions", len(broker.privileged_sessions))
    logger.info("Parsed %d Registry Sessions", len(broker.registry_sessions))
    logger.info("Parsed %d Local Group Memberships", len(broker.local_group_memberships))

    ad.process(num_workers=workers)
    ad.process_local_objects(broker)

    # Store processed objects in cache
    if cache:
        logger.info("Updating cache with processed objects...")
        all_objects = (ad.users + ad.groups + ad.computers + ad.domains + 
                      ad.ous + ad.gpos + ad.containers + ad.aiacas + ad.rootcas +
                      ad.enterprisecas + ad.certtemplates + ad.issuancepolicies + 
                      ad.ntauthstores + ad.trustaccounts + ad.schemas)
        # Note: ad.unknown_objects are raw dicts, not BloodHoundObject instances, so they can't be cached
        
        stored_count = 0
        for obj in all_objects:
            try:
                cache.store_object(obj)
                stored_count += 1
            except Exception as e:
                logger.debug(f"Failed to cache object {getattr(obj, 'ObjectIdentifier', 'unknown')}: {e}")
        
        # Store SID mappings for context in future runs
        logger.debug("Storing SID mappings in cache...")
        sid_mappings = []
        dn_mappings = []
        for sid, obj in ad.SID_MAP.items():
            if hasattr(obj, '_entry_type') and hasattr(obj, 'Properties'):
                name = obj.Properties.get('name', '')
                dn = obj.Properties.get('distinguishedname', '')
                domain = obj.Properties.get('domain', '')
                obj_type = obj._entry_type
                sid_mappings.append((sid, name, obj_type, domain))
                if dn:
                    dn_mappings.append((dn, sid, obj_type))
        
        if sid_mappings:
            cache.store_sid_mappings_bulk(sid_mappings)
        if dn_mappings:
            cache.store_dn_mappings_bulk(dn_mappings)
        
        # Store domain mappings
        for dc, domain_sid in ad.DOMAIN_MAP.items():
            cache.store_domain_mapping(dc, domain_sid)
        
        # Store schema GUIDs
        if ad.ObjectTypeGuidMap:
            cache.store_schema_guids_bulk(ad.ObjectTypeGuidMap)
        
        cache.commit()
        
        # Log context statistics
        ctx_stats = cache.get_context_statistics()
        logger.info(f"Cache updated successfully ({stored_count:,} objects stored)")
        logger.debug(f"Context stored: {ctx_stats['sid_mappings']} SID mappings, "
                    f"{ctx_stats['domain_mappings']} domain mappings, "
                    f"{ctx_stats['schema_guids']} schema GUIDs")

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

    # Close cache
    if cache:
        cache.close()
        logger.info("Cache closed")


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
