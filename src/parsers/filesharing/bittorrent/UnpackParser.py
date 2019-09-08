
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_bittorrent

class BittorrentUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'd8:announce')
    ]
    pretty_name = 'bittorrent'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_bittorrent(fileresult, scan_environment, offset, unpack_dir)

