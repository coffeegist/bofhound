"""Parser for registry session BOF output."""
from .types import BoundaryBasedParser, ObjectType

class RegSessionBofParser(BoundaryBasedParser):
    """Parser for registry session BOF output."""

    def __init__(self):
        super().__init__(
            start_boundary_pattern="-----------Registry Session---------",
            end_boundary_pattern="---------End Registry Session-------"
        )

    @property
    def tool_name(self) -> str:
        return "regsession_bof"

    @property
    def produces_object_type(self) -> ObjectType:
        return ObjectType.REGISTRY_SESSION
