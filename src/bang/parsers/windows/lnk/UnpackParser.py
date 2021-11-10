import os
from . import windows_shell_items
from . import windows_lnk_file
from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationNotEqualError, ValidationNotAnyOfError

class WindowsLinkUnpackParser(UnpackParser):
    extensions = ['.lnk']
    # https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SHLLINK/[MS-SHLLINK].pdf
    signatures = [
        (0, b'\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46')
    ]
    pretty_name = 'lnk'

    def parse(self):
        try:
            self.data = windows_lnk_file.WindowsLnkFile.from_io(self.infile)
        except (Exception, ValidationNotEqualError, ValidationNotAnyOfError) as e:
            raise UnpackParserException(e.args)

    metadata = {}
    labels = [ 'lnk', 'resource', 'windows' ]

