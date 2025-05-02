import re
import codecs

from bofhound.parsers import LdapSearchBofParser


class HavocParser(LdapSearchBofParser):

    @staticmethod
    def prep_file(file):
        with codecs.open(file, 'r', 'utf-8', errors='ignore') as f:
            contents = f.read()

        return re.sub(r'\[\d{2}\/\d{2}\/\d{4} \d{2}:\d{2}:\d{2}\] \[\+\] Received Output \[\d+ bytes\]:\n', '', contents)