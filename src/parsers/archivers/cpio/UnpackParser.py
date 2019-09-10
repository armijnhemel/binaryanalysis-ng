
import os
import stat
import pathlib
from . import cpio_new_ascii
from . import cpio_new_crc
from . import cpio_portable_ascii
from . import cpio_old_binary
from UnpackParser import UnpackParser
from UnpackParserException import UnpackParserException

def rewrite_symlink(file_path, target_path):
    """rewrites a symlink of target_path, relative to file_path.
    target_path and file_path are both Path objects. Returns a
    Path object, representing a relative symlink.
    We assume that file_path is normalized.
    """
    file_path = pathlib.Path('/') / file_path
    target_res = (file_path.parent / target_path).resolve()
    target_dir_count = len(target_res.parts[1:-1])
    file_dir_count = len(file_path.parts[1:-1])
    if target_path.is_absolute():
        ddots = ['..'] * file_dir_count 
        link_path = pathlib.Path('.').joinpath(*ddots) \
                .joinpath(*target_res.parts[1:])
    else:
        ddots = ['..'] * min(file_dir_count, file_dir_count - target_dir_count)
        link_path = pathlib.Path('.').joinpath(*ddots) / target_path.name
    return link_path

class CpioBaseUnpackParser(UnpackParser):
    extensions = []
    signatures = []
    pretty_name = 'cpio'

    def calculate_unpacked_size(self, offset):
        self.unpacked_size = self.infile.tell() - offset
        # the cpio(5) man page is unclear about the padding at the end of
        # the file. It looks like the file is padded to make the total
        # file size a multiple of 16, but more research is needed. For
        # now, we ignore the padding and accept a wrong size.
    def unpack_directory(self, scan_environment, filename):
        outfile_full = scan_environment.unpack_path(filename)
        os.makedirs(outfile_full, exist_ok=True)

    def unpack_regular(self, scan_environment, filename, start, length):
        self.extract_to_file(scan_environment, filename, start, length)

    def unpack_device(self, scan_environment, filename):
        pass

    def unpack_link(self, scan_environment, rel_unpack_dir, filename, target,
            rewrite=False):
        """we assume filename is normalized. If rewrite is True, symlinks are
        rewritten to point to other extracted files."""
        file_path = pathlib.Path(filename)
        target_path = pathlib.Path(target)
        if rewrite:
            link_path = rewrite_symlink(file_path, target_path)
        else:
            link_path = target_path

        outfile_rel = rel_unpack_dir / file_path
        outfile_full = scan_environment.unpack_path(outfile_rel)
        os.makedirs(outfile_full.parent, exist_ok=True)
        outfile_full.symlink_to(link_path)

    def unpack(self, fileresult, scan_environment, offset, rel_unpack_dir):
        files_and_labels = []
        pos = 0
        for e in self.data.entries:
            out_labels = []
            if e.filename != self.data.trailing_filename:
                file_path = pathlib.Path(e.filename)
                if file_path.is_absolute():
                    file_path = file_path.relative_to('/')
                mode = e.header.cpio_mode
                outfile_rel = rel_unpack_dir / file_path
                if stat.S_ISDIR(mode):
                    self.unpack_directory(scan_environment, outfile_rel)
                elif stat.S_ISLNK(mode):
                    self.unpack_link(scan_environment, rel_unpack_dir,
                            file_path, e.filedata.decode())
                    out_labels.append('symbolic link')
                elif stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
                    self.unpack_device(scan_environment, outfile_rel)
                    continue
                elif stat.S_ISREG(mode):
                    filedata_start = e.header.hsize + e.header.nsize + e.header.npaddingsize
                    self.unpack_regular(scan_environment, outfile_rel,
                            pos + filedata_start, e.header.fsize)

                out_labels.append('unpacked')
                files_and_labels.append( (str(rel_unpack_dir / file_path), out_labels) )
            pos += e.header.bsize
        return files_and_labels
    def set_metadata_and_labels(self):
        return

class CpioNewAsciiUnpackParser(CpioBaseUnpackParser):
    extensions = []
    signatures = [ (0, b'070701') ]

    def parse(self):
        try:
                self.data = cpio_new_ascii.CpioNewAscii.from_io(self.infile)
        except Exception as e:
            raise UnpackParserException(e.args)

class CpioNewCrcUnpackParser(CpioBaseUnpackParser):
    extensions = []
    signatures = [ (0, b'070702') ]
    pretty_name = 'cpio'

    def parse(self):
        try:
            self.data = cpio_new_crc.CpioNewCrc.from_io(self.infile)
        except Exception as e:
            raise UnpackParserException(e.args)

class CpioPortableAsciiUnpackParser(CpioBaseUnpackParser):
    extensions = []
    signatures = [ (0, b'070707') ]
    pretty_name = 'cpio'

    def parse(self):
        try:
            self.data = cpio_portable_ascii.CpioPortableAscii.from_io(self.infile)
        except Exception as e:
            raise UnpackParserException(e.args)

class CpioOldBinaryUnpackParser(CpioBaseUnpackParser):
    extensions = []
    signatures = [ (0, b'\xc7\x71') ]
    pretty_name = 'cpio'

    def parse(self):
        try:
            self.data = cpio_old_binary.CpioOldBinary.from_io(self.infile)
        except Exception as e:
            raise UnpackParserException(e.args)


