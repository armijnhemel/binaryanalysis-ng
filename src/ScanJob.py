import stat
import os
import logging
import mimetypes
import pathlib
import shutil
import pickle
import sys

import bangsignatures
from banglogging import log
from FileResult import FileResult
from FileContentsComputer import *
from Unpacker import *

class ScanJob:
    """Performs scanning and unpacking related checks and stores the
    results in the given FileResult object."""
    def __init__(self, scancontext, fileresult):
        self.fileresult = fileresult
        self.scancontext = scancontext
        self.type = None
        self._stat_file()

    def set_scanenvironment(self, scanenvironment):
        self.scanenvironment = scanenvironment

    def _stat_file(self):
        try:
            self.stat = os.stat(self.fileresult.filepath)
        except:
            self.stat = None

    def _is_symlink(self):
        r = self.fileresult.filepath.is_symlink()
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
        r = self.fileresult.filepath.is_dir()
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
            }
            self.fileresult.add_unpackedfile(report)

    def check_mime_types(self):
        # Search the extension of the file in a list of known extensions.
        # https://www.iana.org/assignments/media-types/media-types.xhtml
        mimeres = mimetypes.guess_type(self.fileresult.filepath.name)
        self.fileresult.set_mimetype(mimeres)

    def check_for_valid_extension(self, unpacker, scanfilequeue):
        # TODO: this method will try to unpack multiple extensions
        # if they match. Is this the intention?
        for extension in bangsignatures.extensiontofunction:
            if bangsignatures.matches_file_pattern(self.fileresult.filepath, extension):
                log(logging.INFO, "TRY extension match %s %s" % (self.fileresult.filepath, extension))
                unpackresult = unpacker.try_unpack_file_for_extension(
                        self.fileresult.filepath, extension, self.scancontext.temporarydirectory)
                if unpackresult is None:
                    continue
                if not unpackresult['status']:
                    # No data could be unpacked for some reason
                    log(logging.DEBUG, "FAIL %s known extension %s: %s" %
                            (self.fileresult.get_filename(), extension,
                            unpackresult['error']['reason']))
                    # Fatal errors should lead to the program stopping
                    # execution. Ignored for now.
                    if unpackresult['error']['fatal']:
                        pass
                    unpacker.remove_data_unpack_directory_tree()
                    continue

                # the file could be unpacked successfully,
                # so log it as such.
                log(logging.INFO, "SUCCESS %s %s at offset: 0, length: %d" %
                        (self.fileresult.get_filename(), extension,
                        unpackresult['length']))

                unpacker.file_unpacked(unpackresult, self.fileresult.filesize)

                # store any labels that were passed as a result and
                # add them to the current list of labels
                self.fileresult.labels.update(unpackresult['labels'])

                # store lot of information about the unpacked files
                report = {
                    'offset': 0,
                    'extension': extension,
                    'type': bangsignatures.extensionprettyprint[extension],
                    'size': unpackresult['length'],
                    'files': [],
                }

                for unpackedfile, unpackedlabel in unpackresult['filesandlabels']:
                    fr = FileResult(
                            pathlib.Path(unpackedfile),
                            self.scancontext.get_relative_path(unpackedfile),
                            self.fileresult.filepath,
                            self.fileresult.filename,
                            set(unpackedlabel))
                    j = ScanJob(self.scancontext, fr)
                    scanfilequeue.put(j)
                    report['files'].append(unpackedfile[len(unpacker.get_data_unpack_directory())+1:])
                self.fileresult.add_unpackedfile(report)

    def check_for_signatures(self, unpacker, scanfilequeue):
            signaturesfound = []
            counterspersignature = {}

            unpacker.open_scanfile_with_memoryview(self.fileresult.filepath, self.scanenvironment.get_maxbytes())
            unpacker.seek_to_last_unpacked_offset()
            unpacker.read_chunk_from_scanfile()

            # search the data for known signatures in the data that was read
            # TODO: check why this is a while true loop
            # instead of:
            # while unpacker.get_current_offset_in_file() != self.fileresult.filesize:
            while True:
                candidateoffsetsfound = set()
                for s in bangsignatures.signatures:
                    offsets = unpacker.find_offsets_for_signature(s, self.fileresult.filesize)
                    candidateoffsetsfound.update(offsets)

                # For each of the found candidates see if any
                # data can be unpacked. Process these in the order
                # in which the signatures were found in the file.
                for offset_with_signature in sorted(candidateoffsetsfound):
                    # skip offsets which are not useful to look at
                    # for example because the data has already been
                    # unpacked.
                    (offset, signature) = offset_with_signature
                    if unpacker.offset_overlaps_with_unpacked_data(offset):
                        continue

                    # first see if there actually is a method to unpack
                    # this type of file
                    if signature not in bangsignatures.signaturetofunction:
                        continue

                    signaturesfound.append(offset_with_signature)

                    # always change to the declared unpacking directory
                    os.chdir(self.scancontext.unpackdirectory)
                    # then create an unpacking directory specifically
                    # for the signature including the signature name
                    # and a counter for the signature.
                    namecounter = counterspersignature.get(signature, 0) + 1
                    namecounter = unpacker.make_data_unpack_directory(self.fileresult.filepath,
                            bangsignatures.signatureprettyprint.get(signature, signature),
                            namecounter)

                    # run the scan for the offset that was found
                    # First log which identifier was found and
                    # at which offset for possible later analysis.
                    log(logging.DEBUG, "TRYING %s %s at offset: %d" %
                            (self.fileresult.get_filename(), signature, offset))

                    try:
                        unpackresult = bangsignatures.signaturetofunction[signature](self.fileresult.filepath, offset, unpacker.get_data_unpack_directory(), self.scancontext.temporarydirectory)
                    except AttributeError as e:
                        unpacker.remove_data_unpack_directory()
                        continue

                    if not unpackresult['status']:
                        # No data could be unpacked for some reason,
                        # so log the status and error message
                        log(logging.DEBUG, "FAIL %s %s at offset: %d: %s" %
                                (self.fileresult.get_filename(), signature, offset,
                                    unpackresult['error']['reason']))

                        # Fatal errors should lead to the program
                        # stopping execution. Ignored for now.
                        if unpackresult['error']['fatal']:
                            pass

                        unpacker.remove_data_unpack_directory_tree()
                        continue

                    # first rewrite the offset, if needed
                    offset = unpackresult.get('offset', offset)

                    # the file could be unpacked successfully,
                    # so log it as such.
                    log(logging.INFO, "SUCCESS %s %s at offset: %d, length: %d" %
                            (self.fileresult.get_filename(), signature, offset, unpackresult['length']))

                    # store the name counter
                    counterspersignature[signature] = namecounter

                    # store the labels for files that could be
                    # unpacked/verified completely.
                    if offset == 0 and unpackresult['length'] == self.fileresult.filesize:
                        self.fileresult.labels.update(unpackresult['labels'])
                        # self.labels = list(set(self.labels))
                        # if unpackedfilesandlabels is empty, then no
                        # files were unpacked, likely because the whole
                        # file was the result and didn't contain any
                        # files (i.e. it was not a container file or
                        # compressed file).
                        if unpackresult['filesandlabels'] == []:
                            unpacker.remove_data_unpack_directory()

                    # store the range of the unpacked data
                    unpacker.append_unpacked_range(offset, offset + unpackresult['length'])

                    # store lot of information about the unpacked files
                    report = {
                        'offset': offset,
                        'signature': signature,
                        'type': bangsignatures.signatureprettyprint.get(signature, signature),
                        'size': unpackresult['length'],
                        'files': [],
                    }

                    # set unpackdirectory, but only if needed: if the entire
                    # file is a file that was verified (example: GIF or PNG)
                    # then there will not be an unpacking directory.
                    if unpackresult['filesandlabels'] != []:
                        # report['unpackdirectory'] = unpacker.get_data_unpack_directory()[len(str(self.scancontext.unpackdirectory))+1:]
                        report['unpackdirectory'] = self.scancontext.get_relative_path(unpacker.get_data_unpack_directory())

                    for unpackedfile, unpackedlabel in unpackresult['filesandlabels']:
                        # TODO: make relative wrt unpackdir
                        report['files'].append(unpackedfile[len(unpacker.get_data_unpack_directory())+1:])
                        # add the data, plus possibly any label
                        fr = FileResult(
                                pathlib.Path(unpackedfile),
                                self.scancontext.get_relative_path(unpackedfile),
                                self.fileresult.filepath,
                                self.fileresult.filename,
                                set(unpackedlabel))
                        j = ScanJob(self.scancontext,fr)
                        scanfilequeue.put(j)

                    self.fileresult.add_unpackedfile(report)

                    # skip over all of the indexes that are now known
                    # to be false positives
                    unpacker.set_last_unpacked_offset(offset + unpackresult['length'])

                    # something was unpacked, so record it as such
                    unpacker.set_needs_unpacking(False)

                # check if the end of file has been reached, if so exit
                if unpacker.get_current_offset_in_file() == self.fileresult.filesize:
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

    def carve_file_data(self, unpacker, scanfilequeue):
        # Now carve any data that was not unpacked from the file and
        # put it back into the scanning queue to see if something
        # could be unpacked after all, or to more quickly recognize
        # padding data.
        #
        # This also makes it easier for doing a "post mortem".
        unpacked_range = unpacker.unpacked_range()
        if unpacked_range != []:
            # first check if the first entry covers the entire file
            # because if so there is nothing to do
            if unpacked_range[0] != (0, self.fileresult.filesize):
                synthesizedcounter = 1

                # Invariant: everything up to carve_index has been inspected
                carve_index = 0

                scanfile = open(self.fileresult.filepath, 'rb')
                scanfile.seek(carve_index)

                # then try to see if the any useful data can be uncarved.
                # Add an artifical entry for the end of the file
                # TODO: this algorithm assumes that ranges in unpacked_range
                # are disjoint. Is this always the case?
                # TODO: why self.fileresult.filesize + 1 ?
                # unpack ranges are [u_low:u_high)
                for u_low, u_high in unpacked_range + [(self.fileresult.filesize+1, self.fileresult.filesize+1)]:
                    if carve_index == self.fileresult.filesize:
                        break
                    # get the bytes from range [carve_index:u_low)
                    if u_low > carve_index:
                        #if u_low - carve_index < scanenvironment.get_synthesizedminimum():
                        #        carve_index = u_high
                        #        continue
                        dataunpackdirectory = "%s-%s-%d" % (self.fileresult.filepath, "synthesized", synthesizedcounter)
                        try:
                            os.mkdir(dataunpackdirectory)
                        except:
                            # could not make unpack dir, forget about this carve part
                            break
                        synthesizedcounter += 1

                        outfilename = os.path.join(dataunpackdirectory, "unpacked-%s-%s" % (hex(carve_index), hex(u_low-1)))
                        outfile = open(outfilename, 'wb')
                        os.sendfile(outfile.fileno(), scanfile.fileno(), carve_index, u_low - carve_index)
                        outfile.close()

                        unpackedlabel = ['synthesized']

                        if self.is_padding(outfilename):
                            unpackedlabel.append('padding')
                            # TODO: what if paddingname is None?
                            if self.scanenvironment.get_paddingname() is not None:
                                newoutfilename = os.path.join(dataunpackdirectory, "%s-%s-%s" % (self.scanenvironment.get_paddingname(), hex(carve_index), hex(u_low-1)))
                                shutil.move(outfilename, newoutfilename)
                                outfilename = newoutfilename

                        # add the data, plus labels, to the queue
                        fr = FileResult(
                                pathlib.Path(outfilename),
                                self.scancontext.get_relative_path(outfilename),
                                self.fileresult.filepath,
                                self.fileresult.filename,
                                set(unpackedlabel))
                        j = ScanJob(self.scancontext,fr)
                        scanfilequeue.put(j)
                    carve_index = u_high

                scanfile.close()

    def do_content_computations(self, createbytecounter):
        fc = FileContentsComputer(self.scanenvironment.get_readsize())
        hasher = Hasher(hash_algorithms)
        fc.subscribe(hasher)

        if createbytecounter and 'padding' not in self.fileresult.labels:
            byte_counter = ByteCounter()
            fc.subscribe(byte_counter)

        is_text = IsTextComputer()
        fc.subscribe(is_text)

        if self.scanenvironment.use_tlsh(self.fileresult.filesize, self.fileresult.labels):
            tlshc = TLSHComputerMemoryView()
            fc.subscribe(tlshc)

        fc.read(self.fileresult.filepath)

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

        # store if files are text or binary
        if is_text.get():
            self.fileresult.labels.add('text')
        else:
            self.fileresult.labels.add('binary')

    def check_entire_file(self, unpacker, scanfilequeue):
        if 'text' in self.fileresult.labels and unpacker.unpacked_range() == []:
            for f in bangsignatures.textonlyfunctions:
                namecounter = unpacker.make_data_unpack_directory(self.fileresult.filepath, f, 1)

                log(logging.DEBUG, "TRYING %s %s at offset: 0" % (self.fileresult.get_filename(), f))
                try:
                    unpackresult = bangsignatures.textonlyfunctions[f](self.fileresult.filepath, 0, unpacker.get_data_unpack_directory(), self.scancontext.temporarydirectory)
                except Exception as e:
                    unpacker.remove_data_unpack_directory()
                    continue

                if not unpackresult['status']:
                    # No data could be unpacked for some reason,
                    # so check the status first
                    log(logging.DEBUG, "FAIL %s %s at offset: %d: %s" %
                            (self.fileresult.get_filename(), f, 0, unpackresult['error']['reason']))
                    #print(s[1], unpackresult['error'])
                    #sys.stdout.flush()
                    # unpackerror contains:
                    # * offset in the file where the error occured
                    #   (integer)
                    # * reason of the error (human readable)
                    # * flag to indicate if it is a fatal error
                    #   (boolean)
                    #
                    # Fatal errors should stop execution of the
                    # program and remove the unpacking directory,
                    # so first change the permissions of
                    # all the files so they can be safely removed.
                    if unpackresult['error']['fatal']:
                        pass

                    unpacker.remove_data_unpack_directory_tree()
                    continue

                log(logging.INFO, "SUCCESS %s %s at offset: %d, length: %d" %
                        (self.fileresult.get_filename(), f, 0, unpackresult['length']))

                # store the labels for files that could be
                # unpacked/verified completely.
                if unpackresult['length'] == self.fileresult.filesize:
                    self.fileresult.labels.update(unpackresult['labels'])
                    # if unpackedfilesandlabels is empty, then no
                    # files were unpacked, likely because the whole
                    # file was the result and didn't contain any
                    # files (i.e. it was not a container file or
                    # compresed file).
                    #if len(unpackresult['filesandlabels']) == 0:
                    if unpackresult['filesandlabels'] == []:
                        unpacker.remove_data_unpack_directory()

                # store lot of information about the unpacked files
                report = {
                    'offset': 0,
                    'signature': f,
                    'type': f,
                    'size': unpackresult['length'],
                    'files': [],
                }

                unpacker.set_last_unpacked_offset(unpackresult['length'])
                unpacker.append_unpacked_range(0, unpackresult['length'])

                for unpackedfile, unpackedlabel in unpackresult['filesandlabels']:
                    # TODO: make relative wrt unpackdir
                    report['files'].append(unpackedfile[len(unpacker.get_data_unpack_directory())+1:])

                    # add the data, plus possibly any label
                    fr = FileResult(
                            pathlib.Path(unpackedfile),
                            self.scancontext.get_relative_path(unpackedfile),
                            self.fileresult.filepath,
                            self.fileresult.filename,
                            set(unpackedlabel))
                    j = ScanJob(self.scancontext,fr)
                    scanfilequeue.put(j)

                self.fileresult.add_unpackedfile(report)
                break

    def run_scans_on_file(self, bangfilefunctions, dbconn, dbcursor):
        for filefunc in bangfilefunctions:
            if self.fileresult.labels.isdisjoint(set(filefunc.ignore)):
                res = filefunc(self.fileresult.filepath, self.fileresult.get_hashresult(), dbconn, dbcursor, self.scanenvironment)

# Process a single file.
# This method has the following parameters:
#
# * scancontext :: the scan context
# * scanfilequeue :: a queue where files to scan will be fetched from
# * resultqueue :: a queue where results will be written to
# * processlock :: a lock object that guards access to shared objects
# * checksumdict :: a shared dictionary to store hashes of files so
#   unnecessary scans of duplicate files can be prevented.
# * resultsdirectory :: the absolute path of the directory where results
#   will be written to
# * dbconn :: a PostgreSQL database connection
# * dbcursor :: a PostgreSQL database cursor
# * bangfilefunctions :: a list of functions for individual files
# * scanenvironment :: a dict that describes the environment in
#   which the scans run
#
# Each file will be in the scan queue and have the following data
# associated with it:
#
# * file name :: absolute path to the file to be scanned
# * set of labels :: either empty or containing hints from unpacking
# * parent :: name of parent file)
# * extradata :: empty, reserved for future use
#
# For every file a set of labels describing the file (such as 'binary' or
# 'graphics') will be stored. These labels can be used to feed extra
# information to the unpacking process, such as preventing scans from
# running.
def processfile(scancontext, scanfilequeue, resultqueue, processlock, checksumdict,
                resultsdirectory,
                dbconn, dbcursor, bangfilefunctions, scanenvironment):

    createbytecounter = scanenvironment.get_createbytecounter()

    carveunpacked = True

    while True:
        scanjob = scanfilequeue.get(timeout=86400)
        if not scanjob: continue
        scanjob.set_scanenvironment(scanenvironment)
        fileresult = scanjob.fileresult

        unscannable = scanjob.check_unscannable_file()
        if unscannable:
            resultqueue.put(scanjob.fileresult)
            scanfilequeue.task_done()
            continue

        unpacker = Unpacker()
        scanjob.prepare_for_unpacking()
        scanjob.check_for_padding_file(unpacker)
        scanjob.check_for_unpacked_file(unpacker)
        scanjob.check_mime_types()

        if unpacker.needs_unpacking():
            scanjob.check_for_valid_extension(unpacker, scanfilequeue)

        if unpacker.needs_unpacking():
            scanjob.check_for_signatures(unpacker, scanfilequeue)

        if carveunpacked:
            scanjob.carve_file_data(unpacker, scanfilequeue)

        scanjob.do_content_computations(createbytecounter)

        if unpacker.needs_unpacking():
            scanjob.check_entire_file(unpacker, scanfilequeue)

        duplicate = False
        processlock.acquire()
        # TODO: make checksumdict an object
        # TODO: does this need to be a dictionary, or can it be a set?
        # if hashresults['sha256'] in checksumdict:
        if scanjob.fileresult.get_hash() in checksumdict:
            duplicate = True
        else:
            checksumdict[scanjob.fileresult.get_hash()] = scanjob.fileresult.filepath
        processlock.release()

        if not duplicate:
            scanjob.run_scans_on_file(bangfilefunctions, dbconn, dbcursor)

            # write a pickle with output data
            # The pickle contains:
            # * all available hashes
            # * labels
            # * byte count
            # * any extra data that might have been passed around
            resultout = {}
            if createbytecounter and 'padding' not in scanjob.fileresult.labels:
                resultout['bytecount'] = sorted(byte_counter.get().items())
                # write a file with the distribution of bytes in the scanned file
                bytescountfilename = resultsdirectory / ("%s.bytes" % scanjob.fileresult.get_hash())
                if not bytescountfilename.exists():
                    bytesout = bytescountfilename.open('w')
                    for by in resultout['bytecount']:
                        bytesout.write("%d\t%d\n" % by)
                    bytesout.close()

            for a, h in scanjob.fileresult.get_hashresult().items():
                resultout[a] = h

            resultout['labels'] = list(scanjob.fileresult.labels)
            picklefilename = resultsdirectory / ("%s.pickle" % scanjob.fileresult.get_hash('sha256'))
            # TODO: this is vulnerable to a race condition, replace with EAFP pattern
            if not picklefilename.exists():
                pickleout = picklefilename.open('wb')
                pickle.dump(resultout, pickleout)
                pickleout.close()

        else:
            scanjob.fileresult.labels.add('duplicate')

        # scanjob.fileresult.set_filesize(scanjob.filesize)
        # log(logging.INFO, json.dumps(fileresult.get()))
        sys.stdout.flush()

        resultqueue.put(scanjob.fileresult)
        scanfilequeue.task_done()


