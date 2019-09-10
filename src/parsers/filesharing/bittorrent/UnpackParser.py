
import os
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_bittorrent

class BittorrentUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'd8:announce')
    ]
    pretty_name = 'bittorrent'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_bittorrent(fileresult, scan_environment, offset, unpack_dir)

