
import os
from UnpackParser import WrappedUnpackParser
from bangmedia import unpack_au

class AuUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'.snd')
    ]
    pretty_name = 'au'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_au(fileresult, scan_environment, offset, unpack_dir)

