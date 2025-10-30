"""Parsing pipeline to coordinate multiple tool parsers for C2 framework logs."""
from typing import List, Dict, Any
from .types import ObjectType, ToolParser
from .data_sources import DataSource
from . import (
    NetLocalGroupBofParser, NetLoggedOnBofParser, NetSessionBofParser, RegSessionBofParser,
    LdapSearchBofParser, ParserType, Brc4LdapSentinelParser
)

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
    """

    def __init__(self, platform_filters=None):
        self.tool_parsers: List[ToolParser] = []
        self.platform_filters = platform_filters or []

    def register_parser(self, parser: ToolParser):
        """Register a tool parser with the pipeline"""
        self.tool_parsers.append(parser)

    def process_data_source(self, data_source: DataSource, progress_callback=None) -> ParsingResult:
        """
        Process a data source through all registered parsers.

        Returns categorized results.
        """
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

    def process_file(self, file_path: str) -> ParsingResult:
        """
        Process a file through all registered parsers.

        Returns categorized results.
        """
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

class ParsingPipelineFactory:
    """Factory to create ParsingPipeline instances with registered parsers."""

    @staticmethod
    def create_pipeline(parser_type: ParserType = ParserType.LdapsearchBof) -> ParsingPipeline:
        """Create a ParsingPipeline with all available parsers registered."""
        pipeline = ParsingPipeline()

        pipeline.register_parser(NetLoggedOnBofParser())
        pipeline.register_parser(NetSessionBofParser())
        pipeline.register_parser(NetLocalGroupBofParser())
        pipeline.register_parser(RegSessionBofParser())
        if parser_type == ParserType.BRC4:
            pipeline.register_parser(Brc4LdapSentinelParser())
        else:
            pipeline.register_parser(LdapSearchBofParser())

        return pipeline
