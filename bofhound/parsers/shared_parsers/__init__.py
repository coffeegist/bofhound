from .netloggedon_bof import NetLoggedOnBofParser
from .netsession_bof import NetSessionBofParser
from .netlocalgroup_bof import NetLocalGroupBofParser
from .regsession_bof import RegSessionBofParser

__all_generic_parsers__ = [
    NetLoggedOnBofParser,
    NetSessionBofParser,
    NetLocalGroupBofParser,
    RegSessionBofParser
]