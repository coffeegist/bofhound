"""Parsing pipeline to coordinate multiple tool parsers for C2 framework logs."""
import os
import multiprocessing
from typing import List, Dict, Any
from .types import ObjectType, ToolParser
from .data_sources import DataSource, FileDataSource, FileDataStream
from . import (
    NetLocalGroupBofParser, NetLoggedOnBofParser, NetSessionBofParser, RegSessionBofParser,
    LdapSearchBofParser, ParserType, Brc4LdapSentinelParser, LdifParser
)

# Only these parsers have the standard record/state model that can be combined
# across independent, complete files. Custom stateful implementations stay serial.
_PARALLEL_PARSER_TYPES = {
    NetLocalGroupBofParser, NetLoggedOnBofParser, NetSessionBofParser,
    RegSessionBofParser, LdapSearchBofParser,
}

class ParsingResult:
    """Container for categorized parsing results"""

    def __init__(self):
        self.objects_by_type: Dict[ObjectType, List[Dict[str, Any]]] = {
            obj_type: [] for obj_type in ObjectType
        }

    def add_objects(self, obj_type: ObjectType, objects: List[Dict[str, Any]]):
        """Add objects of a specific type"""
        self.objects_by_type[obj_type].extend(objects)

    def get_objects_by_type(self, obj_type: ObjectType) -> List[Dict[str, Any]]:
        """Get all parsed objects of a specific type"""
        return self.objects_by_type[obj_type]

    def get_ldap_objects(self) -> List[Dict[str, Any]]:
        """Get all parsed LDAP objects"""
        return self.objects_by_type[ObjectType.LDAP_OBJECT]

    def get_sessions(self) -> List[Dict[str, Any]]:
        """Get all parsed session objects"""
        return self.objects_by_type[ObjectType.SESSION]

    def get_local_group_memberships(self) -> List[Dict[str, Any]]:
        """Get all parsed local group membership objects"""
        return self.objects_by_type[ObjectType.LOCAL_GROUP]

    def get_registry_sessions(self) -> List[Dict[str, Any]]:
        """Get all parsed registry session objects"""
        return self.objects_by_type[ObjectType.REGISTRY_SESSION]

    def get_privileged_sessions(self) -> List[Dict[str, Any]]:
        """Get all parsed privileged session objects"""
        return self.objects_by_type[ObjectType.PRIVILEGED_SESSION]


class ParsingPipeline:
    """
    Coordinates multiple tool parsers to process C2 framework logs.

    Registered parsers retain their state across calls in either execution mode.
    Use a fresh pipeline for independent collections.
    """

    def __init__(self, platform_filters=None):
        self.tool_parsers: List[ToolParser] = []
        self.platform_filters = platform_filters or []
        self.parser_type = None  # Will be set by factory
        self._used = False

    def register_parser(self, parser: ToolParser):
        """Register a tool parser with the pipeline"""
        self.tool_parsers.append(parser)

    def process_data_source(self, data_source: DataSource, progress_callback=None, num_workers=None) -> ParsingResult:
        """
        Process a data source through all registered parsers.

        Args:
            data_source: The data source to process
            progress_callback: Optional callback for progress updates
            num_workers: Number of parallel workers (None = auto, 1 = single-threaded)

        Returns categorized results.
        """
        # Arbitrary/stateful custom parsers retain their sequential contract.
        already_used = self._used
        self._used = True
        if isinstance(data_source, FileDataSource):
            file_list = list(data_source.get_data_streams())

            # Use parallel processing if multiple files and workers > 1
            if (num_workers != 1 and len(file_list) > 1 and not already_used
                    and all(type(parser) in _PARALLEL_PARSER_TYPES
                            and not parser.has_pending_input and not parser._records
                            for parser in self.tool_parsers)):
                return self._process_files_parallel(
                    file_list,
                    progress_callback=progress_callback,
                    num_workers=num_workers
                )

        # Fall back to sequential processing
        return self._process_sequential(data_source, progress_callback)

    def _process_sequential(self, data_source: DataSource, progress_callback=None) -> ParsingResult:
        """Process data source sequentially (original behavior)."""
        result = ParsingResult()

        for data_stream in data_source.get_data_streams():
            if progress_callback:
                progress_callback(data_stream.identifier)
            for line in data_stream.lines():
                # Apply platform-specific filtering
                filtered_line = line.rstrip('\n\r')

                # Distribute line to all parsers that can handle it
                for parser in self.tool_parsers:
                    parser.process_line(filtered_line)

        # Collect results from all parsers
        for parser in self.tool_parsers:
            result.add_objects(parser.produces_object_type, parser.get_results())

        return result

    def _process_files_parallel(self, file_streams: List[FileDataStream],
                                progress_callback=None, num_workers=None) -> ParsingResult:
        """Process multiple files in parallel using multiprocessing."""
        from concurrent.futures import ProcessPoolExecutor
        from bofhound.logger import logger

        # Determine worker count
        if num_workers is None:
            num_workers = max(1, int((os.cpu_count() or 1) * 0.9))
        from bofhound.parallel import worker_limit
        num_workers = worker_limit(num_workers, len(file_streams))

        if num_workers == 1:
            # Single file or single worker - use sequential
            return self._process_sequential_files(file_streams, progress_callback)

        logger.debug(f"Processing {len(file_streams)} files with {num_workers} workers")

        combined_records = [[] for _ in self.tool_parsers]
        final_parsers = None
        incomplete = False
        ctx = multiprocessing.get_context('spawn')
        with ProcessPoolExecutor(max_workers=num_workers, mp_context=ctx) as executor:
            from functools import partial
            from bofhound.parallel import ordered_parallel_map
            results = ordered_parallel_map(
                executor, partial(_worker_parse_file, configured_parsers=self.tool_parsers),
                file_streams, max_pending=num_workers * 2,
            )
            for stream in file_streams:
                if progress_callback:
                    progress_callback(stream.identifier)
                try:
                    worker_parsers, pending_record = next(results)
                except Exception as exc:
                    raise RuntimeError(f"Unable to process input {stream.identifier}") from exc
                incomplete |= pending_record
                for records, parser in zip(combined_records, worker_parsers):
                    records.extend(parser._records)
                final_parsers = worker_parsers
        if incomplete:
            # Independent file tasks cannot resolve records split across file boundaries.
            logger.debug("Incomplete record at file boundary; parsing streams sequentially")
            return self._process_sequential_files(file_streams, progress_callback)

        # Keep the originally registered parser instances and their accumulated state,
        # so later entry points behave exactly like a fully sequential first call.
        result = ParsingResult()
        for parser, final_parser, records in zip(self.tool_parsers, final_parsers, combined_records):
            final_parser._records = records
            parser.__dict__.clear()
            parser.__dict__.update(final_parser.__dict__)
            result.add_objects(parser.produces_object_type, parser.get_results())
        return result

    def _process_sequential_files(self, file_streams: List[FileDataStream],
                                   progress_callback=None) -> ParsingResult:
        """Process files sequentially (for single file or single worker)."""
        result = ParsingResult()

        for data_stream in file_streams:
            if progress_callback:
                progress_callback(data_stream.identifier)
            for line in data_stream.lines():
                filtered_line = line.rstrip('\n\r')
                for parser in self.tool_parsers:
                    parser.process_line(filtered_line)

        for parser in self.tool_parsers:
            result.add_objects(parser.produces_object_type, parser.get_results())

        return result

    def process_file(self, file_path: str) -> ParsingResult:
        """
        Process a file through all registered parsers.

        Returns categorized results.
        """
        self._used = True
        result = ParsingResult()

        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                # Apply platform-specific filtering
                filtered_line = line.rstrip('\n\r')

                # Distribute line to all parsers that can handle it
                for parser in self.tool_parsers:
                    parser.process_line(filtered_line)

        # Collect results from all parsers
        for parser in self.tool_parsers:
            parsed_objects = parser.get_results()
            result.add_objects(parser.produces_object_type, parsed_objects)

        return result


def _worker_parse_file(data_stream, configured_parsers):
    """Process the configured stream adapter with a private copy of its parsers."""
    from copy import deepcopy
    parsers = deepcopy(configured_parsers)
    for line in data_stream.lines():
        for parser in parsers:
            parser.process_line(line.rstrip('\n\r'))
    pending_record = any(parser.has_pending_input for parser in parsers)
    for parser in parsers:
        parser.get_results()
    return parsers, pending_record


class ParsingPipelineFactory:
    """Factory to create ParsingPipeline instances with registered parsers."""

    @staticmethod
    def create_pipeline(parser_type: ParserType = ParserType.LdapsearchBof) -> ParsingPipeline:
        """Create a ParsingPipeline with all available parsers registered."""
        pipeline = ParsingPipeline()
        pipeline.parser_type = parser_type  # Store for parallel processing

        pipeline.register_parser(NetLoggedOnBofParser())
        pipeline.register_parser(NetSessionBofParser())
        pipeline.register_parser(NetLocalGroupBofParser())
        pipeline.register_parser(RegSessionBofParser())
        if parser_type == ParserType.BRC4:
            pipeline.register_parser(Brc4LdapSentinelParser())
        elif parser_type == ParserType.LDIF:
            pipeline.register_parser(LdifParser())
        else:
            pipeline.register_parser(LdapSearchBofParser())

        return pipeline
