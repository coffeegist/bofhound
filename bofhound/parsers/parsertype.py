from enum import Enum

class ParserType(Enum):
    LdapsearchBof   = 'ldapsearch'
    BRC4            = 'BRC4'
    HAVOC           = 'Havoc'