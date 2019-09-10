
import os
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_sqlite

class SqliteUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'SQLite format 3\x00')
    ]
    pretty_name = 'sqlite3'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_sqlite(fileresult, scan_environment, offset, unpack_dir)

