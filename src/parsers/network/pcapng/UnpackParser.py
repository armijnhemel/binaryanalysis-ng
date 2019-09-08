
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_pcapng

class PcapngUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x0a\x0d\x0d\x0a')
    ]
    pretty_name = 'pcapng'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_pcapng(fileresult, scan_environment, offset, unpack_dir)

