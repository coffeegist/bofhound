"""Parser for net loggedon BOF output."""
from .types import BoundaryBasedParser, ObjectType

class NetLoggedOnBofParser(BoundaryBasedParser):
    """Parser for net loggedon BOF output."""

    def __init__(self):
        super().__init__(
            start_boundary_pattern="-----------Logged on User-----------",
            end_boundary_pattern="---------End Logged on User---------"
        )

    @property
    def tool_name(self) -> str:
        return "netloggedon_bof"

    @property
    def produces_object_type(self) -> ObjectType:
        return ObjectType.PRIVILEGED_SESSION
