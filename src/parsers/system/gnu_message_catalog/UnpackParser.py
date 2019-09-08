
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_gnu_message_catalog

class GnuMessageCatalogUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\xde\x12\x04\x95'),
        (0, b'\x95\x04\x12\xde')
    ]
    pretty_name = 'gnu_message_catalog'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_gnu_message_catalog(fileresult, scan_environment, offset, unpack_dir)

