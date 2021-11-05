
import os
import pathlib
from UnpackParser import UnpackParser, WrappedUnpackParser
from UnpackParserException import UnpackParserException
from FileResult import FileResult
from bangunpack import unpack_tar
import tarfile

class wTarUnpackParser(WrappedUnpackParser):
    extensions = ['.tar']
    signatures = [
        (0x101, b'ustar\x00'),
        (0x101, b'ustar\x20\x20\x00')
    ]
    pretty_name = 'tar'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_tar(fileresult, scan_environment, offset, unpack_dir)


class TarUnpackParser(UnpackParser):
    #extensions = ['.tar']
    extensions = []
    signatures = [
        (0x101, b'ustar\x00'),
        (0x101, b'ustar\x20\x20\x00')
    ]
    pretty_name = 'tar'

    def tar_unpack_regular(self, meta_directory, path, tarinfo):
        # TODO: absolute paths
        #print(outfile_rel)
        with meta_directory.unpack_regular_file(path) as (unpacked_md, f):
            tar_reader = self.unpacktar.extractfile(tarinfo)
            f.write(tar_reader.read())
            yield unpacked_md

    def unpack(self, meta_directory):
        unpacked_files = []
        for tarinfo in self.tarinfos:
            file_path = pathlib.Path(tarinfo.name)
            if tarinfo.isfile(): # normal file
                for unpacked_md in self.tar_unpack_regular(meta_directory, file_path, tarinfo): yield unpacked_md
            elif tarinfo.issym(): # symlink
                pass
            elif tarinfo.islnk(): # hard link
                pass
            elif tarinfo.isdir(): # directory
                pass

    def parse(self):
        try:
            self.unpacktar = tarfile.open(fileobj=self.infile, mode='r')
        except tarfile.TarError as e:
            raise UnpackParserException(e.args)
        try:
            self.tarinfos = self.unpacktar.getmembers()
        except tarfile.TarError as e:
            raise UnpackParserException(e.args)

    labels = ['tar']
    metadata = {}

