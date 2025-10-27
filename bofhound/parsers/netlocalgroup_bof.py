"""Parser for net localgroup BOF output."""
from .types import BoundaryBasedParser, ObjectType

class NetLocalGroupBofParser(BoundaryBasedParser):
    """Parser for net localgroup BOF output."""

    def __init__(self):
        super().__init__(
            start_boundary_pattern="----------Local Group Member----------",
            end_boundary_pattern="--------End Local Group Member--------"
        )

    @property
    def tool_name(self) -> str:
        return "netlocalgroup_bof"

    @property
    def produces_object_type(self) -> ObjectType:
        return ObjectType.LOCAL_GROUP
