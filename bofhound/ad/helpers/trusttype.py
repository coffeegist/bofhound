from enum import Enum

class TrustType(Enum):
    ParentChild = 0
    CrossLink   = 1
    Forest      = 2
    External    = 3
    Unknown     = 4