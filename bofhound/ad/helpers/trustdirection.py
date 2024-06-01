from enum import Enum

class TrustDirection(Enum):
    Disabled        = 0
    Inbound         = 1
    Outbound        = 2
    Bidirectional   = 3