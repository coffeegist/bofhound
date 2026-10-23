from enum import Enum

class ParserType(Enum):
    LdapsearchBof   = 'ldapsearch'
    LDIF            = 'ldif'
    BRC4            = 'BRC4'
    HAVOC           = 'Havoc'
    OUTFLANKC2      = 'OutflankC2'
    MYTHIC          = 'Mythic'