
import os
import pathlib
from UnpackParser import UnpackParser, WrappedUnpackParser
from UnpackParserException import UnpackParserException
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
    extensions = ['.tar']
    signatures = [
        (0x101, b'ustar\x00'),
        (0x101, b'ustar\x20\x20\x00')
    ]
    pretty_name = 'tar'

    def tar_unpack_regular(self, outfile_rel, tarinfo):
        # TODO: absolute paths
        print(outfile_rel)
        if outfile_rel.is_absolute():
            raise UnpackParserException("trying to extract to absolute path")
        else:
            outfile_full = self.scan_environment.unpack_path(outfile_rel)
            os.makedirs(outfile_full.parent, exist_ok=True)
            outfile = open(outfile_full, 'wb')
            tar_reader = self.unpacktar.extractfile(tarinfo)
            outfile.write(tar_reader.read())
            outfile.close()

    def unpack(self):
        files_and_labels = []
        for tarinfo in self.tarinfos:
            file_path = pathlib.Path(tarinfo.name)
            outfile_rel = self.rel_unpack_dir / file_path
            if tarinfo.isfile(): # normal file
                self.tar_unpack_regular(outfile_rel, tarinfo)
                pass
            elif tarinfo.issym(): # symlink
                pass
            elif tarinfo.islnk(): # hard link
                pass
            elif tarinfo.isdir(): # directory
                pass

            out_labels = []
            files_and_labels.append( (str(self.rel_unpack_dir / file_path), out_labels) )
        return files_and_labels

    def parse(self):
        try:
            self.unpacktar = tarfile.open(fileobj=self.infile, mode='r')
        except tarfile.TarError as e:
            raise UnpackParserException(e.args)
        try:
            self.tarinfos = self.unpacktar.getmembers()
        except tarfile.TarError as e:
            raise UnpackParserException(e.args)


