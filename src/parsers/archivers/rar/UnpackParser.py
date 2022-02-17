import os
import re
import subprocess
from . import rar
from UnpackParser import UnpackParser
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError


class RarUnpackParser(UnpackParser):
    pretty_name = 'rar'
    signatures = [
            (0, b'Rar!\x1a\x07'),
    ]
    def parse(self):
        raise UnpackParserException("Rar not supported")
        try:
            self.data = rar.Rar.from_io(self.infile)
        except (BaseException, ValidationFailedError) as e:
            raise UnpackParserException(e.args)
    def unpack(self):
        return []
        # TODO: (?) for multifile rar only process the .rar file and let it
        # search for .r00, .r01 etc. (these must be written to disk before
        # processing starts, which I assume is the case)
        # skip processing for .r00, etc.
        # To print file names:
        # for b in self.data.blocks:
        #    if b.block_type == self.data.BlockTypes.file_header:
        #        print(b.body.file_name)

    @classmethod
    def is_valid_extension(cls, ext):
        return ext == '.rar' or re.match(r'\.r\d\d', ext)


