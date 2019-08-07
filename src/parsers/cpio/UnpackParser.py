
import os
from . import cpio_new_ascii
from . import cpio_new_crc
from . import cpio_portable_ascii
from UnpackParser import UnpackParser

class CpioBaseUnpackParser(UnpackParser):
    extensions = []
    signatures = [
    ]
    pretty_name = 'cpio'

    def calculate_unpacked_size(self, offset):
        self.unpacked_size = self.infile.tell() - offset
        # the cpio specs (https://www.mankier.com/5/cpio) are unclear about
        # the padding at the end of the file. It looks like the file is padded
        # to make the total file size a multiple of 16, but more research is
        # needed. For now, we ignore the padding and accept a wrong size.
    def unpack(self, fileresult, scan_environment, offset, rel_unpack_dir):
        files_and_labels = []
        pos = 0
        for e in self.data.entries:
            if e.filename != self.data.trailing_filename:
                filedata_start = e.header.hsize + e.header.nsize + e.header.npaddingsize
                # TODO: validate filename
                outfile_rel = rel_unpack_dir / e.filename
                self.extract_to_file(scan_environment, outfile_rel,
                        pos + filedata_start, e.header.fsize)
                outlabels = ['unpacked']
                files_and_labels.append( (str(rel_unpack_dir / e.filename), outlabels) )
            pos += e.header.bsize
        return files_and_labels
    def set_metadata_and_labels(self):
        return

class CpioNewAsciiUnpackParser(CpioBaseUnpackParser):
    extensions = []
    signatures = [
    ]

    def parse(self):
        self.data = cpio_new_ascii.CpioNewAscii.from_io(self.infile)

class CpioNewCrcUnpackParser(CpioBaseUnpackParser):
    extensions = []
    signatures = [
    ]
    pretty_name = 'cpio'

    def parse(self):
        self.data = cpio_new_crc.CpioNewCrc.from_io(self.infile)

class CpioPortableAsciiUnpackParser(CpioBaseUnpackParser):
    extensions = []
    signatures = [
    ]
    pretty_name = 'cpio'

    def parse(self):
        self.data = cpio_portable_ascii.CpioPortableAscii.from_io(self.infile)



