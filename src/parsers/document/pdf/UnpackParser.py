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
# Copyright Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License
# version 3
# SPDX-License-Identifier: AGPL-3.0-only

# The specifications for PDF 1.7 are an ISO standard and can be found
# on the Adobe website:
#
# https://opensource.adobe.com/dc-acrobat-sdk-docs/standards/pdfstandards/pdf/PDF32000_2008.pdf
#
# with additional information at:
#
# https://www.adobe.com/devnet/pdf/pdf_reference.html
#
# The file structure is described in section 7.5.
#
# Test files for PDF 2.0 can be found at:
#
# https://github.com/pdf-association/pdf20examples


import os
import re

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException


class PdfUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'%PDF-')
    ]
    pretty_name = 'pdf'

    def parse(self):
        pdfinfo = {}

        # open the file and skip the offset
        self.infile.seek(5)

        # read the major version number and '.'
        buf = self.infile.read(2)
        check_condition(len(buf) == 2, "not enough bytes for version number")

        check_condition(buf in [b'1.', b'2.'], "invalid version number")

        # read the minor version number
        buf = self.infile.read(1)
        check_condition(len(buf) == 1, "not enough bytes for version number")

        # section 7.5.2
        try:
            version_number = int(buf)
        except ValueError as e:
            raise UnpackParserException(e.args)

        check_condition(version_number <= 7, "invalid minor version number")

        # then either LF, CR, or CRLF (section 7.5.1)
        # exception: ImageMagick 6.5.8-10 2010-12-17 Q16 (and possibly others)
        # sometimes included an extra space directly after the PDF version.
        buf = self.infile.read(1)
        check_condition(len(buf) == 1, "not enough bytes for line ending")
        if buf == b'\x20':
            buf = self.infile.read(1)
            check_condition(len(buf) == 1, "not enough bytes for line ending")

        check_condition(buf in [b'\x0a', b'\x0d'], "wrong line ending")

        # check if the line ending is CRLF
        if buf == b'\x0d':
            buf = self.infile.read(1)
            if buf != b'\x0a':
                self.infile.seek(-1, os.SEEK_CUR)

        valid_pdf = False
        valid_pdf_size = -1

        # keep a list of referencs for the entire document
        document_object_references = {}

        # store the current position (just after the header)
        current_position = self.infile.tell()
        max_unpacked_size = current_position

        # The difficulty with PDF is that the body has no fixed structure.
        # Instead, there is a trailer at the end of the file that contains
        # references back into the file. There could be multiple trailers,
        # because PDF allows incremental updates (section 7.5.6).
        #
        # As files might have been concatenated or a PDF might need to be
        # carved simply jumping to the end of the file is not an option
        # (although it would certainly work for most files). Therefore
        # the file needs to be read until the start of the trailer is found.
        # As an extra complication sometimes the updates are not appended
        # to the file, but prepended using forward references instead of
        # back references and then other parts of the PDF file having back
        # references, making the PDF file more of a random access file.
        while True:
            # continuously look for trailers until there is no valid trailer
            # anymore. This will (likely) be the correct end of the file.
            start_xref_pos = -1
            cross_offset = -1

            # keep track of the object references in a single
            # part of the document (either the original document
            # or an update to the document)
            object_references = {}

            # first seek to where data had already been read
            self.infile.seek(current_position)
            is_valid_trailer = True

            # Sometimes the value for the reference table in startxref is 0.
            # This typically only happens for some updates, and there should
            # be a Prev entry in the trailer dictionary.
            needs_prev = False

            while True:
                # first store the current pointer in the file
                cur = self.infile.tell()

                # create a new buffer for every read, as buffers are
                # not flushed and old data might linger.
                pdfbuffer = bytearray(10240)
                bytesread = self.infile.readinto(pdfbuffer)
                if bytesread == 0:
                    # no bytes could be read, so exit the loop
                    break

                pdfpos = pdfbuffer.find(b'startxref')
                if pdfpos != -1:
                    start_xref_pos = cur + pdfpos
                    # extra sanity checks to check if it is really EOF
                    # (defined in section 7.5.5):
                    # * whitespace
                    # * valid byte offset to last cross reference
                    # * EOF marker

                    # skip 'startxref'
                    self.infile.seek(start_xref_pos + 9)

                    # then either LF, CR, or CRLF (section 7.5.1)
                    buf = self.infile.read(1)
                    if buf not in [b'\x0a', b'\x0d']:
                        start_xref_pos = -1
                    if buf == b'\x0d':
                        buf = self.infile.read(1)
                        if buf != b'\x0a':
                            self.infile.seek(-1, os.SEEK_CUR)
                    crossbuf = b''
                    seeneol = False

                    while True:
                        buf = self.infile.read(1)
                        if buf in [b'\x0a', b'\x0d']:
                            seeneol = True
                            break
                        if self.infile.tell() == self.fileresult.filesize:
                            break
                        crossbuf += buf
                    if not seeneol:
                        is_valid_trailer = False
                        break

                    # the value should be an integer followed by
                    # LF, CR or CRLF.
                    if crossbuf != b'':
                        try:
                            crossoffset = int(crossbuf)
                        except ValueError:
                            break
                    if crossoffset != 0:
                        # the offset for the cross reference cannot
                        # be outside of the file.
                        if crossoffset > self.infile.tell():
                            is_valid_trailer = False
                            break
                    else:
                        needs_prev = True
                    if buf == b'\x0d':
                        buf = self.infile.read(1)
                    if buf != b'\x0a':
                        self.infile.seek(-1, os.SEEK_CUR)

                    # now finally check EOF
                    buf = self.infile.read(5)
                    seen_eof = False
                    if buf != b'%%EOF':
                        is_valid_trailer = False
                        break

                    seen_eof = True

                    # Most likely there are EOL markers, although the PDF
                    # specification is not 100% clear about this:
                    # section 7.5.1 indicates that EOL markers are part of
                    # line by convention.
                    # Section 7.2.3 says that comments should *not*
                    # include "end of line" (but these two do not contradict)
                    # which likely confused people.
                    buf = self.infile.read(1)
                    if buf in [b'\x0a', b'\x0d']:
                        if buf == b'\x0d':
                            if self.infile.tell() != self.fileresult.filesize:
                                buf = self.infile.read(1)
                                if buf != b'\x0a':
                                    self.infile.seek(-1, os.SEEK_CUR)

                    max_unpacked_size = max(max_unpacked_size, self.infile.tell())
                    if self.infile.tell() == self.fileresult.filesize:
                        break
                    if seen_eof:
                        break

                # check if the end of file was reached, without having
                # read a valid trailer.
                if self.infile.tell() == self.fileresult.filesize:
                    is_valid_trailer = False
                    break

                # continue searching, with some overlap
                self.infile.seek(-10, os.SEEK_CUR)
                cur = self.infile.tell()

            if not is_valid_trailer:
                break
            if start_xref_pos == -1 or crossoffset == -1 or not seen_eof:
                break

            current_position = self.infile.tell()

            # extra sanity check: look at the contents of the trailer dictionary
            self.infile.seek(start_xref_pos-5)
            buf = self.infile.read(5)
            if b'>>' not in buf:
                # possibly a cross reference stream (section 7.5.8),
                # a comment line (iText seems to do this a lot)
                # or whitespace
                # TODO
                break

            end_of_trailer_pos = buf.find(b'>>') + start_xref_pos - 4

            trailerpos = -1

            # search the data backwards for the word "trailer"
            self.infile.seek(-50, os.SEEK_CUR)
            isstart = False
            while True:
                curpos = self.infile.tell()
                if curpos <= 0:
                    isstart = True
                buf = self.infile.read(50)
                trailerpos = buf.find(b'trailer')
                if trailerpos != -1:
                    trailerpos = curpos + trailerpos
                    break
                if isstart:
                    break
                self.infile.seek(-60, os.SEEK_CUR)

            # read the xref entries (section 7.5.4) as those
            # might be referenced in the trailer.
            self.infile.seek(crossoffset+4)
            validxref = True
            if trailerpos - crossoffset > 0:
                buf = self.infile.read(trailerpos - crossoffset - 4).strip()
                if b'\r\n' in buf:
                    objectdefs = buf.split(b'\r\n')
                elif b'\r' in buf:
                    objectdefs = buf.split(b'\r')
                else:
                    objectdefs = buf.split(b'\n')
                firstlineseen = False
                xrefseen = 0
                xrefcount = 0
                # the cross reference section might have
                # subsections. The first line is always
                # two integers
                for obj in objectdefs:
                    if not firstlineseen:
                        # first line has to be two integers
                        linesplits = obj.split()
                        if len(linesplits) != 2:
                            validxref = False
                            break
                        try:
                            startxref = int(linesplits[0])
                            xrefcount = int(linesplits[1])
                            xrefcounter = int(linesplits[0])
                        except ValueError:
                            validxref = False
                            break
                        firstlineseen = True
                        xrefseen = 0
                        continue
                    linesplits = obj.split()
                    if len(linesplits) != 2 and len(linesplits) != 3:
                        validxref = False
                        break
                    if len(linesplits) == 2:
                        # start of a new subsection, so first
                        # check if the previous subsection was
                        # actually valid.
                        if xrefcount != xrefseen:
                            validxref = False
                            break
                        linesplits = obj.split()
                        if len(linesplits) != 2:
                            validxref = False
                            break
                        try:
                            startxref = int(linesplits[0])
                            xrefcount = int(linesplits[1])
                            xrefcounter = int(linesplits[0])
                        except ValueError:
                            validxref = False
                            break
                        xrefseen = 0
                        continue
                    elif len(linesplits) == 3:
                        # each of the lines consists of:
                        # * offset
                        # * generation number
                        # * keyword to indicate in use/free
                        if len(linesplits[0]) != 10:
                            validxref = False
                            break
                        if len(linesplits[1]) != 5:
                            validxref = False
                            break
                        if len(linesplits[2]) != 1:
                            validxref = False
                            break
                        try:
                            objectoffset = int(linesplits[0])
                        except ValueError:
                            validxref = False
                            break
                        try:
                            generation = int(linesplits[1])
                        except ValueError:
                            validxref = False
                            break
                        if linesplits[2] == b'n':
                            object_references[xrefcounter] = {}
                            object_references[xrefcounter]['offset'] = objectoffset
                            object_references[xrefcounter]['generation'] = generation
                            object_references[xrefcounter]['keyword'] = 'new'
                        elif linesplits[2] == b'f':
                            object_references[xrefcounter] = {}
                            object_references[xrefcounter]['offset'] = objectoffset
                            object_references[xrefcounter]['generation'] = generation
                            object_references[xrefcounter]['keyword'] = 'free'
                        else:
                            validxref = False
                            break
                        xrefcounter += 1
                        xrefseen += 1

                if xrefcount != xrefseen:
                    validxref = False

                if not validxref:
                    break

            # jump to the position where the trailer starts
            self.infile.seek(trailerpos)

            # and read the trailer, minus '>>'
            buf = self.infile.read(end_of_trailer_pos - trailerpos)

            # extra sanity check: see if '<<' is present
            if b'<<' not in buf:
                break

            # then split the entries
            trailersplit = buf.split(b'\x0d\x0a')
            if len(trailersplit) == 1:
                trailersplit = buf.split(b'\x0d')
                if len(trailersplit) == 1:
                    trailersplit = buf.split(b'\x0a')

            seen_root = False
            correct_reference = True
            seen_prev = False
            for i in trailersplit:
                if b'/' not in i:
                    continue
                if b'/Root' in i:
                    seen_root = True
                if b'/Info' in i:
                    # indirect reference, section 7.3.10
                    # Don't treat errors as fatal right now.
                    infores = re.search(rb'/Info\s+(\d+)\s+(\d+)\s+R', i)
                    if infores is None:
                        continue
                    (objectref, generation) = infores.groups()
                    objectref = int(objectref)
                    generation = int(generation)
                    if objectref in object_references:
                        # seek to the position of the object in the
                        # file and read the data
                        self.infile.seek(object_references[objectref]['offset'])

                        # first read a few bytes to check if it is
                        # actually the right object
                        buf = self.infile.read(len(str(objectref)))
                        try:
                            cb = int(buf)
                        except ValueError:
                            continue
                        if cb != objectref:
                            continue

                        # read a space
                        buf = self.infile.read(1)
                        if buf != b' ':
                            continue

                        # read the generation
                        buf = self.infile.read(len(str(generation)))
                        try:
                            gen = int(buf)
                        except ValueError:
                            continue
                        if gen != generation:
                            continue

                        # read a space
                        buf = self.infile.read(1)
                        if buf != b' ':
                            continue

                        # then read 'obj'
                        buf = self.infile.read(3)
                        if buf != b'obj':
                            continue

                        # now read until 'endobj' is reached
                        infobytes = b''
                        validinfobytes = True
                        while True:
                            buf = self.infile.read(20)
                            infobytes += buf
                            if infobytes == b'':
                                validinfobytes = False
                                break
                            if b'endobj' in infobytes:
                                break
                        if not validinfobytes:
                            continue
                        infobytes = infobytes.split(b'endobj', 1)[0].strip()
                        if b'<<' not in infobytes:
                            continue
                        if b'>>' not in infobytes:
                            continue
                        if infobytes[0] == b'<<' and infobytes[-1] == b'>>':
                            infobytes = infobytes[1:-1]
                        else:
                            infobytes = infobytes.split(b'>>', 1)[0]
                            infobytes = infobytes.split(b'<<', 1)[1]
                        # process according to section 14.3.3
                        # TODO
                if b'/Prev' in i:
                    prevres = re.search(rb'/Prev\s(\d+)', i)
                    if prevres is not None:
                        prevxref = int(prevres.groups()[0])
                        seen_prev = True
                        if prevxref > self.fileresult.filesize:
                            correct_reference = False
                            break
                        self.infile.seek(prevxref)
                        buf = self.infile.read(4)
                        if buf != b'xref':
                            correct_reference = False
                            break
                        pdfinfo['updates'] = True

            # /Root element is mandatory
            if not seen_root:
                break

            if needs_prev and not seen_prev:
                break

            # references should be correct
            if not correct_reference:
                break

            # so far the PDF file is valid (possibly including updates)
            # so record it as such and record until where the PDF is
            # considered valid.
            valid_pdf = True
            max_unpacked_size = max(max_unpacked_size, self.infile.tell())
            valid_pdf_size = max_unpacked_size

        check_condition(valid_pdf, "not a valid PDF")
        self.infile.seek(valid_pdf_size)

    def extract_metadata_and_labels(self):
        '''Extract metadata from the PDF file and set labels'''
        labels = ['pdf']
        metadata = {}

        return(labels, metadata)

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        metadata = {}

        (labels, metadata) = self.extract_metadata_and_labels()
        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
