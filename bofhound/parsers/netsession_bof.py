"""Parser for net session BOF output."""
from .types import BoundaryBasedParser, ObjectType

class NetSessionBofParser(BoundaryBasedParser):
    """Parser for net session BOF output."""

    def __init__(self):
        super().__init__(
            start_boundary_pattern="---------------Session--------------",
            end_boundary_pattern="-------------End Session------------"
        )

    @property
    def tool_name(self) -> str:
        return "netsession_bof"

    @property
    def produces_object_type(self) -> ObjectType:
        return ObjectType.SESSION
