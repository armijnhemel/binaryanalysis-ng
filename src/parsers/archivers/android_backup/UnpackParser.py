
import os
from UnpackParser import UnpackParser
from bangandroid import unpack_android_backup

class AndroidBackupUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'ANDROID BACKUP\n')
    ]
    pretty_name = 'android_backup'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_android_backup(fileresult, scan_environment, offset, unpack_dir)

