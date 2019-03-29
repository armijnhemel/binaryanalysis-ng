import re
import os
import shutil
import stat

import bangunpack
import bangsignatures
from bangsignatures import maxsignaturesoffset


class Unpacker:
    def __init__(self):
        # Invariant: lastunpackedoffset ==
        # last known position in file with successfully unpacked data
        # everything before this offset is unpacked and identified.
        self.lastunpackedoffset = -1
        self.unpackedrange = []
        self.needsunpacking = True
        # signature based unpacking?
        self.signaturesfound = []
        self.counterspersignature = {}

    def needs_unpacking(self):
        return self.needsunpacking

    def last_unpacked_offset(self):
        return self.lastunpackedoffset

    def unpacked_range(self):
        return self.unpackedrange

    def set_last_unpacked_offset(self, offset):
        self.lastunpackedoffset = offset

    def set_needs_unpacking(self, needsunpacking):
        self.needsunpacking = needsunpacking

    def append_unpacked_range(self, low, high):
        self.unpackedrange.append((low, high))

    def make_data_unpack_directory(self, filename, filetype, nr=1):
        while True:
            d = "%s-%s-%d" % (filename, filetype, nr)
            try:
                os.mkdir(d)
                self.dataunpackdirectory = d
                break
            # TODO: be more specific in exceptions to prevent infinite loops
            except:
                nr += 1
        return nr

    def remove_data_unpack_directory(self):
        os.rmdir(self.dataunpackdirectory)

    def remove_data_unpack_directory_tree(self):
        # Remove the unpacking directory, including any data that
        # might accidentily be there, so first change the
        # permissions of all the files so they can be safely.
        dirwalk = os.walk(self.dataunpackdirectory)
        for direntries in dirwalk:
            # make sure all subdirectories and files can
            # be accessed and then removed.
            for subdir in direntries[1]:
                subdirname = os.path.join(direntries[0], subdir)
                if not os.path.islink(subdirname):
                    os.chmod(subdirname,
                             stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            for filenameentry in direntries[2]:
                fullfilename = os.path.join(direntries[0], filenameentry)
                if not os.path.islink(fullfilename):
                    os.chmod(fullfilename,
                             stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        shutil.rmtree(self.dataunpackdirectory)

    def get_data_unpack_directory(self):
        return self.dataunpackdirectory

    def try_unpack_file_for_extension(self, fileresult, scanenvironment, filename, extension, temporarydirectory):
        try:
            self.make_data_unpack_directory(filename, bangsignatures.extensionprettyprint[extension])
            return bangsignatures.unpack_file_with_extension(fileresult, scanenvironment, extension, self.dataunpackdirectory)
        except AttributeError as ex:
            print(ex)
            self.remove_data_unpack_directory()
            return None

    def open_scanfile(self, filename):
        self.scanfile = open(filename, 'rb')

    def open_scanfile_with_memoryview(self, filename, maxbytes):
        self.scanfile = open(filename, 'rb')
        self.scanbytesarray = bytearray(maxbytes)
        self.scanbytes = memoryview(self.scanbytesarray)

    def seek_to(self, pos):
        self.scanfile.seek(pos)

    def seek_to_last_unpacked_offset(self):
        self.scanfile.seek(max(self.last_unpacked_offset(), 0))

    def get_current_offset_in_file(self):
        return self.scanfile.tell()

    def read_chunk_from_scanfile(self):
        self.offsetinfile = self.get_current_offset_in_file()
        self.bytesread = self.scanfile.readinto(self.scanbytesarray)

    def close_scanfile(self):
        self.scanfile.close()

    def seek_to_find_next_signature(self):
        if self.scanfile.tell() < self.lastunpackedoffset:
            # skip data that has already been unpacked
            self.scanfile.seek(self.lastunpackedoffset)
        else:
            # use an overlap, i.e. go back
            self.scanfile.seek(-maxsignaturesoffset, 1)

    def find_offsets_for_signature(self, s, filesize):
        offsets = set()
        # TODO: precompile regexp patterns in bangsignatures
        res = re.finditer(re.escape(bangsignatures.signatures[s]), self.scanbytes[:self.bytesread])
        if res is not None:
            for r in res:
                if s in bangsignatures.signaturesoffset:
                    # skip files that aren't big enough if the
                    # signature is not at the start of the data
                    # to be carved (example: ISO9660).
                    if r.start() + self.offsetinfile - bangsignatures.signaturesoffset[s] < 0:
                        continue

                offset = r.start()
                if not bangsignatures.prescan(s, self.scanbytes, self.bytesread, filesize, offset, self.offsetinfile):
                    continue

                # default: store a tuple (offset, signature name)
                if s in bangsignatures.signaturesoffset:
                    offsets.add((offset + self.offsetinfile - bangsignatures.signaturesoffset[s], s))
                else:
                    offsets.add((offset + self.offsetinfile, s))
        return offsets

    def offset_overlaps_with_unpacked_data(self, offset):
        return offset < self.lastunpackedoffset

    def try_unpack_file_for_signatures(self, filename):
        pass

    def file_unpacked(self, unpackresult, filesize):
        # store the location of where the successfully
        # unpacked file ends (the offset is always 0  here).
        self.lastunpackedoffset = unpackresult['length']

        # store the range of the unpacked data
        self.unpackedrange.append((0, unpackresult['length']))

        # if unpackedfilesandlabels is empty, then no files
        # were unpacked likely because the whole file was the
        # result and didn't contain any files (it was not a
        # container or compresed file)
        if unpackresult['filesandlabels'] == []:
            self.remove_data_unpack_directory()

        # whole file has already been unpacked, so no need for
        # further scanning.
        if unpackresult['length'] == filesize:
            self.needsunpacking = False


