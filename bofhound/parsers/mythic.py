import sys
import asyncio
import logging
import warnings
import base64
from mythic import mythic
from syncer import sync

from bofhound.parsers import LdapSearchBofParser
from bofhound.logger import logger

# Suppress the specific aiohttp ssl warning
warnings.filterwarnings(
    "ignore",
    message="WARNING: By default, AIOHTTPTransport does not verify ssl certificates.*"
)

RETURN_ATTRIBUTES = [
    "id",
    "display_id",
    "domain",
    "user",
    "host",
    "agent_callback_id"
]

###
# Quick and dirty class to hold Mythic callback information
# and allow print statments from the main logic to still work
class MythicCallback:
    def __init__(self, callback, mythic_instance=None):
        self.callback_id = callback["id"]
        self.display_id = callback["display_id"]
        self.domain = callback["domain"]
        self.user = callback["user"]
        self.host = callback["host"]
        self.uuid = callback["agent_callback_id"]
        self.mythic_instance = mythic_instance
    
    
    def __repr__(self):
        return f"Mythic callback {self.callback_id} [{self.uuid}]"


class MythicParser(LdapSearchBofParser):
    mythic_instance = None


    def __init__(self):
        super().__init__()


    async def connect(self, mythic_server, mythic_token):
        logger.debug("Logging into Mythic...")
        try:
            self.mythic_instance = await mythic.login(
                apitoken=mythic_token,
                server_ip=mythic_server,
                server_port=7443,
                timeout=-1,
                logging_level=logging.CRITICAL,
            )
        except Exception as e:
            logger.error("Error logging into Mythic")
            logger.error(e)
            sys.exit(-1)
        
        logger.debug("Logged into Mythic successfully")


    async def collect_callbacks(self):
        logger.debug("Retrieving callbacks from Mythic...")
        try:
            raw_callbacks = await mythic.get_all_callbacks(
                self.mythic_instance,
                custom_return_attributes=",".join(RETURN_ATTRIBUTES)
            )
        except Exception as e:
            logger.error("Error retrieving callbacks from Mythic")
            logger.error(e)
            sys.exit(-1)

        all_callbacks = []
        for callback in raw_callbacks:
            mythic_callback = MythicCallback(callback, self.mythic_instance)
            all_callbacks.append(mythic_callback)

        logger.debug(f"Retrieved {len(all_callbacks)} callbacks from Mythic")
        return all_callbacks


    ###
    # For mythic, instead of processing individual log "files"
    # we will processes the taskings given to individual callbacks
    @staticmethod
    def prep_file(callback):
        tasks = sync(
            MythicParser.get_tasks(
                callback.mythic_instance,
                callback.display_id
            )
        )
        
        data = ""

        # 
        # TODO: can we iterate over only relevant tasks?
        #
        for task in tasks:
            output = sync(
                MythicParser.get_task_output(
                    callback.mythic_instance,
                    task["display_id"]
                )
            )

            for response in output:
                data += base64.b64decode(response["response_text"]).decode("utf-8")
                data += "\n"
        
        return data
    

    @staticmethod
    async def get_task_output(mythic_instance, task_id):
        try:
            output = await mythic.get_all_task_output_by_id(
                mythic_instance,
                task_id
            )
        except Exception as e:
            logger.warning(f"Error retrieving task output from Mythic for task {task_id}")
            logger.warning(e)

        return output
    

    @staticmethod
    async def get_tasks(mythic_instance, id):
        try:
            tasks = await mythic.get_all_tasks(
                mythic_instance,
                callback_display_id=id,
                #custom_return_attributes=",".join(RETURN_ATTRIBUTES)
            )
        except Exception as e:
            logger.warning(f"Error retrieving tasks from Mythic for callback {id}")
            logger.warning(e)

        return tasks