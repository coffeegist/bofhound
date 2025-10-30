"""Data source abstractions for BOFHound parsing pipeline."""

import os
import sys
import glob
import json
import logging
import base64
import asyncio
import warnings
from abc import ABC, abstractmethod
from typing import Iterator, AsyncIterator, TypeVar
from typing_extensions import override
from mythic import mythic
from syncer import sync
from bofhound.logger import logger

T = TypeVar('T')

class DataSource(ABC):
    """Abstract base class for data sources that provide lines to parse."""

    @abstractmethod
    def get_data_streams(self) -> Iterator['DataStream']:
        """Return an iterator of data streams to process."""


class DataStream(ABC):
    """Abstract base class representing a single stream of data to parse."""

    @property
    @abstractmethod
    def identifier(self) -> str:
        """Unique identifier for this data stream (e.g., filename, callback ID)."""

    @abstractmethod
    def lines(self) -> Iterator[str]:
        """Return an iterator of lines from this data stream."""

    def __str__(self) -> str:
        return self.identifier


class FileDataSource(DataSource):
    """Data source that reads from local files."""

    def __init__(self, input_path: str, filename_pattern: str = "*.log",
                 stream_type=None):
        self.input_path = input_path
        self.filename_pattern = filename_pattern
        self.stream_type = stream_type or FileDataStream

    def get_data_streams(self) -> Iterator['FileDataStream']:
        """Get file-based data streams."""
        if os.path.isfile(self.input_path):
            yield self.stream_type(self.input_path)
        elif os.path.isdir(self.input_path):
            pattern = f"{self.input_path}/**/{self.filename_pattern}"
            files = glob.glob(pattern, recursive=True)
            files.sort(key=os.path.getmtime)

            for file_path in files:
                yield self.stream_type(file_path)
        else:
            raise ValueError(f"Input path does not exist: {self.input_path}")


class FileDataStream(DataStream):
    """Data stream that reads from a local file."""

    def __init__(self, file_path: str):
        self.file_path = file_path

    @property
    def identifier(self) -> str:
        return self.file_path

    def lines(self) -> Iterator[str]:
        """Read lines from the file."""
        with open(self.file_path, 'r', encoding='utf-8') as f:
            for line in f:
                yield line.rstrip('\n\r')


class OutflankDataStream(FileDataStream):
    """Data stream for Outflank logs, inherits from FileDataStream."""
    def lines(self) -> Iterator[str]:
        """Read lines from the Outflank log file."""
        with open(self.file_path, 'r', encoding='utf-8') as f:
            bofname = 'ldapsearch'
            for line in f:
                event_json = json.loads(line.split('UTC ', 1)[1])

                # we only care about task_resonse events
                if (event_json['event_type'] == 'task_response'
                    and event_json['task']['name'].lower() == bofname):
                    # now we have a block of ldapsearch data we can parse through for objects
                    response_lines = event_json['task']['response']
                    for response_line in response_lines.splitlines():
                        yield response_line


class MythicDataSource(DataSource):
    """Data source that fetches data from Mythic server."""

    def __init__(self, mythic_server: str, mythic_token: str):
        # suppress warning
        warnings.filterwarnings("ignore",
                       message=".*AIOHTTPTransport does not verify ssl certificates.*",
                       category=UserWarning)
        self.mythic_server = mythic_server
        self.mythic_token = mythic_token
        self._mythic_instance = None

    def _connect(self):
        logger.debug("Logging into Mythic...")
        try:
            self._mythic_instance = sync(mythic.login(
                apitoken=self.mythic_token,
                server_ip=self.mythic_server,
                server_port=7443,
                timeout=-1,
                logging_level=logging.CRITICAL
            ))
        except Exception as e:
            logger.error("Error logging into Mythic")
            logger.error(e)
            sys.exit(-1)

        logger.debug("Logged into Mythic successfully")

    def _async_iterable_to_sync_iterable(self, iterator: AsyncIterator[T]) -> Iterator[T]:
        """Convert an async iterator to a sync iterator."""
        loop = asyncio.get_event_loop()

        while True:
            try:
                result = loop.run_until_complete(anext(iterator))
                yield result
            except StopAsyncIteration:
                break

    @override
    def get_data_streams(self) -> Iterator['MythicDataStream']:
        """
        Get Mythic output data streams.
        For mythic, instead of processing individual log "files"
        we will processes the outputs from the API server
        """
        if self._mythic_instance is None:
            self._connect()

        async_batch_iterator = mythic.get_all_task_output(self._mythic_instance, batch_size=100)

        for batch in self._async_iterable_to_sync_iterable(async_batch_iterator):
            yield from (MythicDataStream(output) for output in batch)


class MythicDataStream(DataStream):
    """Data stream that reads from a Mythic callback's task outputs."""

    def __init__(self, output: dict):
        """Initialize with Mythic task output data."""
        self._output = output

    @property
    def identifier(self) -> str:
        return f"mythic_output_{self._output.get('id', '-1')}"

    def lines(self) -> Iterator[str]:
        """Get lines from Mythic callback task outputs."""
        # Decode and yield each line
        try:
            decoded_data = base64.b64decode(self._output.get("response_text")).decode("utf-8")
            for line in decoded_data.splitlines():
                if line.strip():  # Skip empty lines
                    yield line
        except Exception:
            pass  # Skip malformed responses
