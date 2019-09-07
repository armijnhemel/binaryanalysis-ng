
import os
from UnpackParser import UnpackParser
from bangmedia import unpack_au

class AuUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'.snd')
    ]
    pretty_name = 'au'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_au(fileresult, scan_environment, offset, unpack_dir)

