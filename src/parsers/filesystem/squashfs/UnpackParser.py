
import os
from UnpackParser import UnpackParser
from bangfilesystems import unpack_squashfs

class SquashfsUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'sqsh'),
        (0, b'hsqs'),
        (0, b'shsq'),
        (0, b'qshs'),
        (0, b'tqsh'),
        (0, b'hsqt'),
        (0, b'sqlz')
    ]
    pretty_name = 'squashfs'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_squashfs(fileresult, scan_environment, offset, unpack_dir)

