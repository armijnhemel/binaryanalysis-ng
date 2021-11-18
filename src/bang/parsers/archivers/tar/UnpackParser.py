
import os
import pathlib
from bang.UnpackParser import UnpackParser, WrappedUnpackParser
from bang.UnpackParserException import UnpackParserException
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
        for tarinfo in self.tarinfos:
            file_path = pathlib.Path(tarinfo.name)
            if tarinfo.isfile(): # normal file
                yield from self.tar_unpack_regular(meta_directory, file_path, tarinfo)
            elif tarinfo.issym(): # symlink
                # meta_directory.unpack_symlink(tarinfo.name, ...)
                pass
            elif tarinfo.islnk(): # hard link
                pass
            elif tarinfo.isdir(): # directory
                meta_directory.unpack_directory(pathlib.Path(tarinfo.name))

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

