
import os
from UnpackParser import UnpackParser
from bangmedia import unpack_psd

class PsdUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'8BPS')
    ]
    pretty_name = 'psd'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_psd(fileresult, scan_environment, offset, unpack_dir)

