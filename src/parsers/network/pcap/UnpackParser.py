
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_pcap

class PcapUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\xd4\xc3\xb2\xa1'),
        (0, b'\xa1\xb2\xc3\xd4'),
        (0, b'\x4d\x3c\xb2\xa1'),
        (0, b'\xa1\xb2\x3c\x4d')
    ]
    pretty_name = 'pcap'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_pcap(fileresult, scan_environment, offset, unpack_dir)

