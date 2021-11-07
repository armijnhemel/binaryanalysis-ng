
import os
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_pcapng

class PcapngUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\x0a\x0d\x0d\x0a')
    ]
    pretty_name = 'pcapng'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_pcapng(fileresult, scan_environment, offset, unpack_dir)

