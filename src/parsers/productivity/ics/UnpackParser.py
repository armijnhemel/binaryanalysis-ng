
import os
from UnpackParser import UnpackParser
from bangtext import unpack_ics

class IcsUnpackParser(UnpackParser):
    extensions = ['.ics']
    signatures = [
    ]
    pretty_name = 'ics'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_ics(fileresult, scan_environment, offset, unpack_dir)

