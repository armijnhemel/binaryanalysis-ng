
import os
from UnpackParser import WrappedUnpackParser
from bangandroid import unpack_android_backup

class AndroidBackupUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'ANDROID BACKUP\n')
    ]
    pretty_name = 'android_backup'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_android_backup(fileresult, scan_environment, offset, unpack_dir)

