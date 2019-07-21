# Binary Analysis Next Generation (BANG!)
#
# This file is part of BANG.
#
# BANG is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License, version 3,
# as published by the Free Software Foundation.
#
# BANG is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public
# License, version 3, along with BANG.  If not, see
# <http://www.gnu.org/licenses/>
#
# Copyright 2018-2019 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License
# version 3
# SPDX-License-Identifier: AGPL-3.0-only

import re
import os
import shutil
import stat

import bangsignatures
from bangsignatures import maxsignaturesoffset


class Unpacker:
    def __init__(self, unpackroot):
        # Invariant: lastunpackedoffset ==
        # last known position in file with successfully unpacked data
        # everything before this offset is unpacked and identified.
        self.lastunpackedoffset = -1
        self.unpackedrange = []
        self.needsunpacking = True
        # signature based unpacking?
        self.signaturesfound = []
        self.counterspersignature = {}
        self.unpackroot = unpackroot

    def needs_unpacking(self):
        ''' Return whether or not a file needs further unpacking'''
        return self.needsunpacking

    def last_unpacked_offset(self):
        '''Return the offset of the last successfully unpacked data'''
        return self.lastunpackedoffset

    def unpacked_range(self):
        '''Return a list of byte ranges of unpacked data'''
        return self.unpackedrange

    def set_last_unpacked_offset(self, offset):
        '''Set the offset of the last successfully unpacked data'''
        self.lastunpackedoffset = offset

    def set_needs_unpacking(self, needsunpacking):
        ''' Set whether or not a file needs further unpacking'''
        self.needsunpacking = needsunpacking

    def append_unpacked_range(self, low, high):
        '''Add a byte range of unpacked data to a list'''
        self.unpackedrange.append((low, high))

    def make_data_unpack_directory(self, relpath, filetype, seqnr=1):
        '''Makes a data unpack directory.'''
        # relpath is the relative path to the file that is unpacked.
        # filetype is the type of the file
        # seqnr is a sequence number that will be increased
        # if the directory with that nr already exists.
        # returns the sequence number of the directory
        while True:
            dirname = "%s-%s-%d" % (relpath, filetype, seqnr)
            try:
                os.mkdir(os.path.join(self.unpackroot, dirname))
                self.dataunpackdirectory = dirname
                break
            except FileExistsError:
                seqnr += 1
        return seqnr

    def remove_data_unpack_directory(self):
        '''Remove the unpacking directory'''
        os.rmdir(os.path.join(self.unpackroot, self.dataunpackdirectory))

    def remove_data_unpack_directory_tree(self):
        '''Remove the unpacking directory, including any
        data that might accidentily have been left behind.'''
        dirwalk = os.walk(os.path.join(self.unpackroot, self.dataunpackdirectory))
        for direntries in dirwalk:
            # make sure all subdirectories and files can
            # be accessed and then removed by first changing the
            # permissions of all the files.
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
        shutil.rmtree(os.path.join(self.unpackroot, self.dataunpackdirectory))

    def get_data_unpack_directory(self):
        '''Return the location of the data unpack directory'''
        return self.dataunpackdirectory

    def try_unpack_file_for_extension(self, fileresult, scanenvironment, relpath, extension):
        try:
            self.make_data_unpack_directory(relpath, bangsignatures.extensionprettyprint[extension])
            return bangsignatures.unpack_file_with_extension(fileresult, scanenvironment, extension, self.dataunpackdirectory)
        except AttributeError:
            self.remove_data_unpack_directory()
            return None

    def open_scanfile(self, filename):
        '''Open the file read-only in raw mode'''
        if filename.stat().st_mode &  stat.S_IRUSR != stat.S_IRUSR:
            filename.chmod(stat.S_IRUSR)
        self.scanfile = open(filename, 'rb')

    def open_scanfile_with_memoryview(self, filename, maxbytes):
        '''Open the file using a memory view to reduce I/O'''
        if filename.stat().st_mode &  stat.S_IRUSR != stat.S_IRUSR:
            filename.chmod(stat.S_IRUSR)
        self.scanfile = open(filename, 'rb')
        self.scanbytesarray = bytearray(maxbytes)
        self.scanbytes = memoryview(self.scanbytesarray)

    def seek_to(self, pos):
        '''Seek to the desired position in the file'''
        self.scanfile.seek(pos)

    def seek_to_last_unpacked_offset(self):
        '''Seek to the position of the data that
        was unpacked successfully last'''
        self.scanfile.seek(max(self.last_unpacked_offset(), 0))

    def get_current_offset_in_file(self):
        '''Return the current position in the file'''
        return self.scanfile.tell()

    def read_chunk_from_scanfile(self):
        self.offsetinfile = self.get_current_offset_in_file()
        self.bytesread = self.scanfile.readinto(self.scanbytesarray)

    def close_scanfile(self):
        '''Close the file'''
        self.scanfile.close()

    def seek_to_find_next_signature(self):
        if self.scanfile.tell() < self.lastunpackedoffset:
            # skip data that has already been unpacked
            self.scanfile.seek(self.lastunpackedoffset)
        else:
            # use an overlap, i.e. go back
            self.scanfile.seek(-maxsignaturesoffset, 1)

    def find_offsets_for_signature(self, sig, filesize):
        offsets = set()
        # TODO: precompile regexp patterns in bangsignatures
        res = re.finditer(re.escape(bangsignatures.signatures[sig]), self.scanbytes[:self.bytesread])
        if res is not None:
            for r in res:
                if sig in bangsignatures.signaturesoffset:
                    # skip files that aren't big enough if the
                    # signature is not at the start of the data
                    # to be carved (example: ISO9660).
                    if r.start() + self.offsetinfile - bangsignatures.signaturesoffset[sig] < 0:
                        continue

                offset = r.start()
                if not bangsignatures.prescan(sig, self.scanbytes, self.bytesread, filesize, offset, self.offsetinfile):
                    continue

                # default: store a tuple (offset, signature name)
                if sig in bangsignatures.signaturesoffset:
                    offsets.add((offset + self.offsetinfile - bangsignatures.signaturesoffset[sig], sig))
                else:
                    offsets.add((offset + self.offsetinfile, sig))
        return offsets

    def offset_overlaps_with_unpacked_data(self, offset):
        return offset < self.lastunpackedoffset

    def try_unpack_file_for_signatures(self, fileresult, scanenvironment, signature, offset):
        try:
            return bangsignatures.signaturetofunction[signature](fileresult, scanenvironment, offset, self.dataunpackdirectory)
        except AttributeError as ex:
            print(ex)
            self.remove_data_unpack_directory()
            return None

    def try_textonlyfunctions(self, fileresult, scanenvironment, filetype, offset):
        try:
            return bangsignatures.textonlyfunctions[filetype](fileresult, scanenvironment, 0, self.dataunpackdirectory)
        except Exception as ex:
            # TODO: make exception more specific, it is too general
            print(ex)
            self.remove_data_unpack_directory()
            return None


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
