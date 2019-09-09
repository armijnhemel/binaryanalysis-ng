
import os
from UnpackParser import UnpackParser
from bangandroid import unpack_dhtb

class DhtbUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'DHTB\x01\x00\x00')
    ]
    pretty_name = 'dhtb'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_dhtb(fileresult, scan_environment, offset, unpack_dir)

