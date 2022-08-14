import os
import pathlib
from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import quake_pak

'''
A Quake PAK file is a file used by the game Quake. It is basically
a concatenation of files with some extra metadata (file name), with
a lookup table.

https://quakewiki.org/wiki/.pak
'''

class QuakePakUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'PACK')
    ]
    pretty_name = 'quakepak'

    def parse(self):
        try:
            self.data = quake_pak.QuakePak.from_io(self.infile)

            # there has to be at least one file.
            check_condition(self.data.len_index > 0, "at least one file needed")

            # size of the file table has to be a multiple of 64.
            check_condition(self.data.len_index%64 == 0, "file table not a multiple of 64")
            check_condition(len(self.data.index.entries) == self.data.len_index//64,
                           "not enough file entries")

            # hack: read the index entries to trigger that instances
            # are read.
            for i in self.data.index.entries:
                pass
        except ValidationFailedError as e:
            raise UnpackParserException(e.args)
        except EOFError as e:
            raise UnpackParserException(e.args)
        except Exception as e:
            raise UnpackParserException(e.args)

    # no need to carve the Quake PAK file itself from the file
    def carve(self):
        pass

    def calculate_unpacked_size(self):
        self.unpacked_size = self.data.ofs_index + self.data.len_index
        for i in self.data.index.entries:
            self.unpacked_size = max(self.unpacked_size, i.ofs + i.size)

    def unpack(self):
        unpacked_files = []
        seen_files = set()
        for quake_entry in self.data.index.entries:
            out_labels = []
            # there can be duplicate names, so rename
            # example: PROGS/OPENCP/CP.PAK in SOUND/OPENCP.ZIP in FD12CD.iso
            entry_name = quake_entry.name
            if entry_name in seen_files:
                counter=1
                while True:
                    entry_name = "%s-renamed-%d" % (quake_entry.name, counter)
                    if entry_name not in seen_files:
                        out_labels.append('renamed')
                        break
                    counter+=1

            file_path = pathlib.Path(entry_name)
            outfile_rel = self.rel_unpack_dir / file_path

            # create subdirectories, if any are defined in the file name
            if '/' in entry_name:
                outfile_rel.parent.mkdir(parents=True, exist_ok=True)

            # write the file
            quake_file = outfile_rel.open(mode='xb')
            os.sendfile(quake_file.fileno(), self.infile.fileno(), self.infile.offset + quake_entry.ofs, quake_entry.size)
            quake_file.close()

            fr = FileResult(self.fileresult, self.rel_unpack_dir / entry_name, set(out_labels))
            unpacked_files.append(fr)

            seen_files.add(entry_name)
        return unpacked_files

    def set_metadata_and_labels(self):
        self.unpack_results.set_labels(['quake', 'resource'])
        self.unpack_results.set_metadata({})
