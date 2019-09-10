
import os
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_gnu_message_catalog

class GnuMessageCatalogUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\xde\x12\x04\x95'),
        (0, b'\x95\x04\x12\xde')
    ]
    pretty_name = 'gnu_message_catalog'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_gnu_message_catalog(fileresult, scan_environment, offset, unpack_dir)

