
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_sqlite

class SqliteUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'SQLite format 3\x00')
    ]
    pretty_name = 'sqlite3'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_sqlite(fileresult, scan_environment, offset, unpack_dir)

