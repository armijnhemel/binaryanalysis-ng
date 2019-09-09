
import os
from UnpackParser import UnpackParser
from bangtext import unpack_ihex

class IhexUnpackParser(UnpackParser):
    extensions = ['.hex', '.ihex']
    signatures = [
    ]
    pretty_name = 'ihex'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_ihex(fileresult, scan_environment, offset, unpack_dir)

