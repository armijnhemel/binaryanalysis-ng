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

import stat
import os
import logging
import mimetypes
import pathlib
import shutil
import sys
import traceback
from operator import itemgetter

import bangsignatures
from banglogging import log
import banglogging
from FileResult import FileResult
from FileContentsComputer import *
from UnpackManager import *
from UnpackParserException import UnpackParserException

class ScanJobError(Exception):
    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)

    def __init__(self, scanjob, e):
        super().__init__(self, scanjob, e)
        self.scanjob = scanjob
        self.e = e

    def __str__(self):
        exc = traceback.format_exception(type(self.e), self.e, self.e.__traceback__, chain=False)
        if self.scanjob is not None:
            return """Exception for scanjob:
file:
    %s
labels:
    %s
""" % (str(self.scanjob.fileresult.filename), ",".join(self.scanjob.fileresult.labels)) + "".join(exc)
        else:
            return "Exception (no scanjob):\n\n" + "".join(exc)


class ScanJob:
    """Performs scanning and unpacking related checks and stores the
    results in the given FileResult object."""
    def __init__(self, fileresult):
        self.fileresult = fileresult
        self.type = None

    def set_scanenvironment(self, scanenvironment):
        self.scanenvironment = scanenvironment

    def initialize(self):
        self.abs_filename = self.scanenvironment.unpack_path(self.fileresult.filename)
        self._stat_file()

    def _stat_file(self):
        try:
            self.stat = os.stat(self.abs_filename)
        except FileNotFoundError as e:
            #raise
            self.stat = None
        except:
            self.stat = None

    def _is_symlink(self):
        r = self.abs_filename.is_symlink()
        if r: self.type = 'symbolic link'
        return r

    def _is_socket(self):
        r = stat.S_ISSOCK(self.stat.st_mode)
        if r: self.type = 'socket'
        return r

    def _is_fifo(self):
        r = stat.S_ISFIFO(self.stat.st_mode)
        if r: self.type = 'fifo'
        return r

    def _is_block_device(self):
        r = stat.S_ISBLK(self.stat.st_mode)
        if r: self.type = 'block device'
        return r

    def _is_character_device(self):
        r = stat.S_ISCHR(self.stat.st_mode)
        if r: self.type = 'character device'
        return r

    def _is_directory(self):
        r = self.abs_filename.is_dir()
        if r: self.type = 'directory'
        return r

    def _is_empty(self):
        r = self.stat.st_size == 0
        if r: self.type = 'empty'
        return r

    def not_scannable(self):
        return self._is_symlink() or \
                self._is_socket() or \
                self._is_fifo() or \
                self._is_block_device() or \
                self._is_character_device() or \
                self._is_directory() or \
                self._is_empty()

    def check_unscannable_file(self):
        if self.not_scannable():
            self.fileresult.labels.add(self.type)
            if self.type == 'empty':
                self.fileresult.set_filesize(0)
                for hash_algorithm, hash_value in emptyhashresults.items():
                    self.fileresult.set_hashresult(hash_algorithm, hash_value)
            elif self.type == 'symbolic link':
                self.fileresult.set_target(self.fileresult.filename.readlink())
            return True
        self.fileresult.set_filesize(self.stat.st_size)
        return False

    def prepare_for_unpacking(self):
        self.fileresult.init_unpacked_files()

    def check_for_padding_file(self, unpacker):
        # padding files don't need to be scanned
        if 'padding' in self.fileresult.labels:
            unpacker.set_needs_unpacking(False)
            report = {
                'offset': 0,
                'size': self.fileresult.filesize,
                'files': [],
                'relative_files': [],
            }
            self.fileresult.add_unpackedfile(report)
        else:
            unpacker.set_needs_unpacking(True)

    def check_for_unpacked_file(self, unpacker):
        # check for a dummy value to see if the file has already been
        # unpacked and if so, simply report and skip the unpacking, and
        # move on to just running the per file scans.
        if 'unpacked' in self.fileresult.labels:
            self.fileresult.labels.remove('unpacked')
            unpacker.set_needs_unpacking(False)
            unpacker.set_last_unpacked_offset(self.fileresult.filesize)
            unpacker.append_unpacked_range(0, self.fileresult.filesize)

            # store lot of information about the unpacked files
            # TODO: add more information, such as signature
            report = {
                'offset': 0,
                'size': self.fileresult.filesize,
                'files': [],
                'relative_files': [],
            }
            self.fileresult.add_unpackedfile(report)

    def check_mime_types(self):
        # Search the extension of the file in a list of known extensions.
        # https://www.iana.org/assignments/media-types/media-types.xhtml
        mimeres = mimetypes.guess_type(self.fileresult.filename.name)
        self.fileresult.set_mimetype(mimeres)

    def check_for_valid_extension(self, unpacker):
        # TODO: this method will try to unpack multiple extensions
        # if they match. Is this the intention?
        for extension, unpackparsers in \
                self.scanenvironment.get_unpackparsers_for_extensions().items():
            for unpackparser in unpackparsers:
                if bangsignatures.matches_file_pattern(self.fileresult.filename, extension):
                    log(logging.INFO, "TRYING extension match %s %s" % (self.fileresult.filename, extension))
                    try:
                        unpackresult = unpacker.try_unpack_file_for_extension(
                            self.fileresult, self.scanenvironment,
                            extension, unpackparser)
                    except UnpackParserException as e:
                        # No data could be unpacked for some reason
                        log(logging.DEBUG, "FAIL %s known extension %s: %s" %
                            (self.fileresult.filename, extension,
                             e.args))
                        # Fatal errors should lead to the program stopping
                        # execution. Ignored for now.
                        # if unpackresult['error']['fatal']:
                        #    pass
                        unpacker.remove_data_unpack_directory_tree()
                        continue

                    # the file could be unpacked successfully,
                    # so log it as such.
                    log(logging.INFO, "SUCCESS %s %s at offset: 0, length: %d" %
                        (self.fileresult.filename, extension,
                         unpackresult.get_length()))

                    unpacker.file_unpacked(unpackresult, self.fileresult.filesize)

                    # store any labels that were passed as a result and
                    # add them to the current list of labels
                    self.fileresult.labels.update(unpackresult.get_labels())

                    # store lot of information about the unpacked files
                    report = {
                        'offset': 0,
                        'extension': extension,
                        'type': unpackparser.pretty_name,
                        'size': unpackresult.get_length(),
                        'files': [],
                        'relative_files': [],
                    }

                    if unpackresult.get_metadata != {}:
                        self.fileresult.set_metadata(unpackresult.get_metadata())

                    for unpackedfile in unpackresult.get_unpacked_files():
                        j = ScanJob(unpackedfile)
                        self.scanenvironment.scanfilequeue.put(j)
                        report['files'].append(unpackedfile.filename)
                        report['relative_files'].append(unpackedfile.filename.relative_to(unpacker.get_data_unpack_directory()))
                    self.fileresult.add_unpackedfile(report)

    def check_for_signatures(self, unpacker):
            signaturesfound = []
            counterspersignature = {}

            filename_full = self.scanenvironment.unpack_path(self.fileresult.filename)
            unpacker.open_scanfile_with_memoryview(filename_full, self.scanenvironment.get_maxbytes())
            unpacker.seek_to_last_unpacked_offset()
            unpacker.read_chunk_from_scanfile()

            # search the data for known signatures in the data that was read
            # TODO: check why this is a while true loop
            # instead of:
            # while unpacker.get_current_offset_in_file() != self.fileresult.filesize:
            sigs_and_unpackers = self.scanenvironment.get_unpackparsers_for_signatures().items()
            while True:
                candidateoffsetsfound = set()
                for s, unpackparsers in sigs_and_unpackers:
                    offsets = unpacker.find_offsets_for_signature(s,
                            unpackparsers, self.fileresult.filesize)
                    candidateoffsetsfound.update(offsets)

                # For each of the found candidates see if any
                # data can be unpacked. Process these in the order
                # in which the signatures were found in the file.
                for offset_with_unpackparser in sorted(candidateoffsetsfound,
                        key=itemgetter(0)):
                    # skip offsets which are not useful to look at
                    # for example because the data has already been
                    # unpacked.
                    (offset, unpackparser) = offset_with_unpackparser
                    if unpacker.offset_overlaps_with_unpacked_data(offset):
                        continue

                    signaturesfound.append(offset_with_unpackparser)

                    # TODO: this chdir can probably go away
                    # always change to the declared unpacking directory
                    os.chdir(self.scanenvironment.unpackdirectory)
                    # then create an unpacking directory specifically
                    # for the signature including the pretty printed signature
                    # name and a counter for the signature.
                    namecounter = counterspersignature.get(unpackparser.pretty_name, 0) + 1
                    namecounter = unpacker.make_data_unpack_directory(
                            self.fileresult.get_unpack_directory_parent(),
                            unpackparser.pretty_name, offset, namecounter)

                    # run the scan for the offset that was found
                    # First log which identifier was found and
                    # at which offset for possible later analysis.
                    log(logging.DEBUG, "TRYING %s %s at offset: %d" %
                        (self.fileresult.filename, unpackparser.pretty_name, offset))

                    try:
                        unpackresult = unpacker.try_unpack_file_for_signatures(
                            self.fileresult, self.scanenvironment,
                            unpackparser, offset)
                    except UnpackParserException as e:
                        # No data could be unpacked for some reason,
                        # so log the status and error message
                        log(logging.DEBUG, "FAIL %s %s at offset: %d: %s" %
                            (self.fileresult.filename, unpackparser.pretty_name, offset,
                             e.args))

                        # Fatal errors should lead to the program
                        # stopping execution. Ignored for now.
                        # if unpackresult['error']['fatal']:
                        #    pass

                        unpacker.remove_data_unpack_directory_tree()

                        # unfortunately it is not correct to store
                        # the last inspected offset, as it could be
                        # that later some signatures are found that
                        # for that format only occur later in the file
                        # such as ISO9660 or ext2. It would be possible
                        # that these signatures are then missed. This
                        # could lead to some overlap and redundant
                        # scanning. TODO: find an elegant solution for this.
                        continue

                    # first rewrite the offset, if needed
                    # (example: coreboot file system)
                    offset = unpackresult.get_offset(default=offset)

                    # the file could be unpacked successfully,
                    # so log it as such.
                    log(logging.INFO, "SUCCESS %s %s at offset: %d, length: %d" %
                        (self.fileresult.filename, unpackparser.pretty_name,
                            offset, unpackresult.get_length()))

                    # store the name counter
                    counterspersignature[unpackparser.pretty_name] = namecounter

                    # store the labels for files that could be
                    # unpacked/verified completely.
                    if offset == 0 and unpackresult.get_length() == self.fileresult.filesize:
                        self.fileresult.labels.update(unpackresult.get_labels())
                        # self.labels = list(set(self.labels))
                        # if unpackedfilesandlabels is empty, then no
                        # files were unpacked, likely because the whole
                        # file was the result and didn't contain any
                        # files (i.e. it was not a container file or
                        # compressed file).
                        if unpackresult.get_unpacked_files() == []:
                            unpacker.remove_data_unpack_directory_tree()

                    # store the range of the unpacked data
                    unpacker.append_unpacked_range(offset, offset +
                        unpackresult.get_length())

                    # store lot of information about the unpacked files
                    report = {
                        'offset': offset,
                        # TODO: signature text or index?
                        'signature': unpackparser.pretty_name,
                        'type': unpackparser.pretty_name,
                        'size': unpackresult.get_length(),
                        'files': [],
                        'relative_files': [],
                    }

                    if unpackresult.get_metadata != {}:
                        self.fileresult.set_metadata(unpackresult.get_metadata())

                    # set unpackdirectory, but only if needed: if the entire
                    # file is a file that was verified (example: GIF or PNG)
                    # then there will not be an unpacking directory.
                    if unpackresult.get_unpacked_files() != []:
                        report['unpackdirectory'] = unpacker.get_data_unpack_directory()

                    for unpackedfile in unpackresult.get_unpacked_files():
                        report['files'].append(unpackedfile.filename)
                        report['relative_files'].append(unpackedfile.filename.relative_to(unpacker.get_data_unpack_directory()))
                        j = ScanJob(unpackedfile)
                        self.scanenvironment.scanfilequeue.put(j)

                    self.fileresult.add_unpackedfile(report)

                    # skip over all of the indexes that are now known
                    # to be false positives
                    unpacker.set_last_unpacked_offset(offset + \
                            unpackresult.get_length())

                    # something was unpacked, so record it as such
                    unpacker.set_needs_unpacking(False)

                # check if the end of file has been reached, if so exit
                if unpacker.get_current_offset_in_file() == self.fileresult.filesize:
                    break

                # this should not happen, but in case a scan reports the wrong
                # size (outside of the file) then the method should also exit.
                # TODO: add proper warning.
                if unpacker.get_current_offset_in_file() > self.fileresult.filesize:
                    break

                unpacker.seek_to_find_next_signature()
                unpacker.read_chunk_from_scanfile()

            unpacker.close_scanfile()

    def is_padding(self, filename):
        # try to see if the file contains NUL byte padding
        # or 0xFF padding and if so tag it as such
        validpadding = [b'\x00', b'\xff']
        ispadding = True
        outfile = open(filename, 'rb')
        c = outfile.read(1)
        if c in validpadding:
            padding_char = c
            while c == padding_char:
                c = outfile.read(1)
            ispadding = c == b''
        else:
            ispadding = False
        outfile.close()
        return ispadding

        checkbytes = outfile.read(1)
        if checkbytes in validpadding:
            paddingchar = checkbytes
            # now read more bytes
            while True:
                scanbytes = outfile.read(self.scanenvironment.get_maxbytes())
                if scanbytes == b'':
                    break
                if scanbytes != len(scanbytes) * paddingchar:
                    ispadding = False
                    break
        else:
            ispadding = False
        outfile.close()

    def synthesize_file(self, unpacker, scanfile, index_from, index_to):
        self.synthesizedcounter = \
                unpacker.make_data_unpack_directory(
                self.fileresult.get_unpack_directory_parent(),
                "synthesized", index_from, self.synthesizedcounter)

        outfile_rel = unpacker.get_data_unpack_directory() / \
                ("unpacked-0x%x-0x%x" % (index_from, index_to-1))
        outfile_full = self.scanenvironment.unpack_path(outfile_rel)

        # create the unpacking directory and write the file
        os.makedirs(outfile_full.parent, exist_ok=True)

        # write the file
        outfile = open(outfile_full, 'wb')
        os.sendfile(outfile.fileno(), scanfile.fileno(), index_from, index_to -
                index_from)
        outfile.close()

        unpackedlabel = ['synthesized']

        if self.is_padding(outfile_full):
            unpackedlabel.append('padding')
            if self.scanenvironment.get_paddingname() is not None:
                newoutfile_rel = unpacker.get_data_unpack_directory() / \
                    ( "%s-%s-%s" % (self.scanenvironment.get_paddingname(),
                            hex(index_from), hex(index_to-1)))
                newoutfile_full = self.scanenvironment.unpack_path(newoutfile_rel)
                shutil.move(outfile_full, newoutfile_full)

                outfile_rel = newoutfile_rel
        return outfile_rel, unpackedlabel


    def carve_file_data(self, unpacker):
        # Now carve any data that was not unpacked from the file and
        # put it back into the scanning queue to see if something
        # could be unpacked after all, or to more quickly recognize
        # padding data.
        #
        # This also makes it easier for doing a "post mortem".
        #
        unpacked_range = unpacker.unpacked_range()
        if unpacked_range == []:
            return



        # Invariant: everything up to carve_index has been inspected
        # unpack ranges are [u_low:u_high)
        self.synthesizedcounter = 1
        carve_index = 0
        filename_full = self.scanenvironment.unpack_path(self.fileresult.filename)
        scanfile = open(filename_full, 'rb')
        scanfile.seek(carve_index)
        for u_low, u_high in unpacked_range + [(self.fileresult.filesize, self.fileresult.filesize)]:
            if carve_index < u_low:
                outfile_rel, unpackedlabel = self.synthesize_file(unpacker,
                        scanfile, carve_index, u_low)

                report = {
                    'offset': carve_index,
                    'type': 'carved',
                    'size': u_low - carve_index,
                    'files': [ outfile_rel ],
                    'relative_files': [ outfile_rel.relative_to(unpacker.get_data_unpack_directory()) ],
                }
                self.fileresult.add_unpackedfile(report)

                # add the data, plus labels, to the queue
                fr = FileResult(self.fileresult,
                    outfile_rel,
                    set(unpackedlabel))
                j = ScanJob(fr)
                self.scanenvironment.scanfilequeue.put(j)
                self.synthesizedcounter += 1
            carve_index = u_high
        scanfile.close()

    def do_content_computations(self):
        fc = FileContentsComputer(self.scanenvironment.get_readsize())
        hasher = Hasher(hash_algorithms)
        fc.subscribe(hasher)

        if self.scanenvironment.get_createbytecounter() and 'padding' not in self.fileresult.labels:
            byte_counter = ByteCounter()
            fc.subscribe(byte_counter)

        is_text = IsTextComputer()
        fc.subscribe(is_text)

        if self.scanenvironment.use_tlsh(self.fileresult.filesize, self.fileresult.labels):
            tlshc = TLSHComputerMemoryView()
            fc.subscribe(tlshc)

        filename_full = self.scanenvironment.unpack_path(self.fileresult.filename)
        fc.read(filename_full)

        hashresults = dict(hasher.get())
        if self.scanenvironment.use_tlsh(self.fileresult.filesize, self.fileresult.labels):
            # there might not be a valid hex digest for files
            # with little or no entropy, for example files with
            # all NUL bytes
            try:
                hashresults['tlsh'] = tlshc.get()
            except ValueError:
                pass
        for hash_algorithm, hash_value in hashresults.items():
            self.fileresult.set_hashresult(hash_algorithm, hash_value)

        if self.scanenvironment.get_createbytecounter() and 'padding' not in self.fileresult.labels:
            self.fileresult.byte_counter = byte_counter

        # store if files are text or binary
        if is_text.get():
            self.fileresult.labels.add('text')
        else:
            self.fileresult.labels.add('binary')

    def check_entire_file(self, unpacker):
        # TODO: this is making an assumption that all featureless files are
        # text based.
        # TODO: this is assuming that only one featureless file can be extracted
        # and not more
        if 'text' in self.fileresult.labels and unpacker.unpacked_range() == []:
            for unpack_parser in \
                    self.scanenvironment.get_unpackparsers_for_featureless_files():
                namecounter = unpacker.make_data_unpack_directory(
                        self.fileresult.get_unpack_directory_parent(),
                        unpack_parser.pretty_name, 0, 1)

                log(logging.DEBUG, "TRYING %s %s at offset: 0" %
                        (self.fileresult.filename, unpack_parser.pretty_name))
                try:
                    unpackresult = unpacker.try_unpack_without_features(
                        self.fileresult, self.scanenvironment, unpack_parser, 0)
                except UnpackParserException as e:
                    log(logging.DEBUG, "FAIL %s %s at offset: %d: %s" %
                        (self.fileresult.filename, unpack_parser.pretty_name, 0,
                            e.args))
                    unpacker.remove_data_unpack_directory_tree()
                    continue

                log(logging.INFO, "SUCCESS %s %s at offset: %d, length: %d" %
                    (self.fileresult.filename, unpack_parser.pretty_name, 0,
                    unpackresult.get_length()))

                # store the labels for files that could be
                # unpacked/verified completely.
                # TODO: what about files that we could not unpack completely?
                if unpackresult.get_length() == self.fileresult.filesize:
                    self.fileresult.labels.update(unpackresult.get_labels())


                # store lot of information about the unpacked files
                report = {
                    'offset': 0,
                    'signature': unpack_parser.pretty_name,
                    'type': unpack_parser.pretty_name,
                    'size': unpackresult.get_length(),
                    'files': [],
                    'relative_files': [],
                }

                if unpackresult.get_metadata != {}:
                    self.fileresult.set_metadata(unpackresult.get_metadata())

                unpacker.set_last_unpacked_offset(unpackresult.get_length())
                unpacker.append_unpacked_range(0, unpackresult.get_length())

                for unpackedfile in unpackresult.get_unpacked_files():
                    report['files'].append(unpackedfile.filename)
                    report['relative_files'].append(unpackedfile.filename.relative_to(unpacker.get_data_unpack_directory()))
                    j = ScanJob(unpackedfile)
                    self.scanenvironment.scanfilequeue.put(j)

                self.fileresult.add_unpackedfile(report)

                if unpackresult.get_unpacked_files() == []:
                    unpacker.remove_data_unpack_directory()

                break

# Process a single file.
# This method has the following parameters:
#
# * scanenvironment :: a ScanEnvironment object, describing
#   the environment for the scan
#
# The scan queue contains ScanJob objects
#
# For every file a set of labels describing the file (such as 'binary' or
# 'graphics') will be stored. These labels can be used to feed extra
# information to the unpacking process, such as preventing scans from
# running.
def processfile(scanenvironment):

    scanfilequeue = scanenvironment.scanfilequeue
    resultqueue = scanenvironment.resultqueue
    processlock = scanenvironment.processlock
    checksumdict = scanenvironment.checksumdict

    carveunpacked = True

    os.chdir(scanenvironment.unpackdirectory)

    while True:
        try:
            scanjob = scanfilequeue.get(timeout=86400)
            if not scanjob: continue
            scanjob.set_scanenvironment(scanenvironment)
            scanjob.initialize()
            fileresult = scanjob.fileresult

            unscannable = scanjob.check_unscannable_file()
            if unscannable:
                resultqueue.put(scanjob.fileresult)
                scanfilequeue.task_done()
                continue

            unpacker = UnpackManager(scanenvironment.unpackdirectory)
            scanjob.prepare_for_unpacking()
            scanjob.check_for_padding_file(unpacker)
            scanjob.check_for_unpacked_file(unpacker)
            scanjob.check_mime_types()

            if unpacker.needs_unpacking():
                scanjob.check_for_valid_extension(unpacker)

            if unpacker.needs_unpacking():
                if 'synthesized' not in fileresult.labels:
                    scanjob.check_for_signatures(unpacker)

            if carveunpacked:
                scanjob.carve_file_data(unpacker)

            scanjob.do_content_computations()

            if unpacker.needs_unpacking():
                scanjob.check_entire_file(unpacker)

            processlock.acquire()

            if scanjob.fileresult.get_hash() in checksumdict:
                scanjob.fileresult.set_duplicate(True)
            else:
                scanjob.fileresult.set_duplicate(False)
                checksumdict[scanjob.fileresult.get_hash()] = scanjob.fileresult.filename
            processlock.release()

            if not scanjob.fileresult.is_duplicate():
                for rclass in scanenvironment.reporters:
                    r = rclass(scanenvironment)
                    r.report(scanjob.fileresult)

            # scanjob.fileresult.set_filesize(scanjob.filesize)

            resultqueue.put(scanjob.fileresult)
            scanfilequeue.task_done()
        except Exception as e:
            tb = sys.exc_info()[2]
            if scanjob:
                raise ScanJobError(scanjob, e)
                # raise ScanJobError(scanjob, e).with_traceback(tb)
            else:
                raise ScanJobError(None, e).with_traceback(tb)

