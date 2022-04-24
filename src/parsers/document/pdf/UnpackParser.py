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


import io
import os
import re
import tempfile

import pdfminer

from pdfminer.pdfparser import PDFParser
from pdfminer.pdfdocument import PDFDocument
from pdfminer.pdfpage import PDFPage

from pdfminer.converter import TextConverter
from pdfminer.layout import LAParams
from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter

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

        # store the current position (just after the header)
        current_position = self.infile.tell()

        # The difficulty with PDF is that the body has no fixed structure.
        # Instead, there is a trailer at the end of the file that contains
        # references back into the file. There could be multiple trailers,
        # because PDF allows incremental updates (section 7.5.6).
        #
        # As files might have been concatenated or a PDF might need to be
        # carved simply jumping to the end of the file is not an option
        # (although it would certainly work for most files). Therefore
        # the file needs to be read until %%EOF is found.
        #
        # As an extra complication sometimes the updates are not appended
        # to the file, but prepended using forward references instead of
        # back references and then other parts of the PDF file having back
        # references, making the PDF file more of a random access file.

        best_eof = -1
        buffersize = 1000000
        while True:
            # continuously look for %%EOF and then parse with pdfminer
            # until there is a parse error or the end of file has been
            # reached.
            end_of_eof = -1
            valid_eof = True

            while True:
                # first store the current pointer in the file
                cur = self.infile.tell()

                # create a new buffer for every read, as buffers are
                # not flushed and old data might linger.
                pdfbuffer = bytearray(buffersize)
                bytesread = self.infile.readinto(pdfbuffer)
                if bytesread == 0:
                    # no bytes could be read, so exit this loop
                    break

                pdfpos = pdfbuffer.find(b'%%EOF')
                if pdfpos != -1:
                    # Most likely there are EOL markers, although the PDF
                    # specification is not 100% clear about this:
                    # section 7.5.1 indicates that EOL markers are part of
                    # line by convention.
                    # Section 7.2.3 says that comments should *not*
                    # include "end of line" (but these two do not contradict)
                    # which likely confused people.
                    self.infile.seek(cur + pdfpos + 5)
                    buf = self.infile.read(1)
                    if buf in [b'\x0a', b'\x0d']:
                        if buf == b'\x0d':
                            if self.offset + self.infile.tell() != self.fileresult.filesize:
                                buf = self.infile.read(1)
                                if buf != b'\x0a':
                                    self.infile.seek(-1, os.SEEK_CUR)

                    end_of_eof = self.infile.tell()
                    havetmpfile = False

                    # carve the file if necessary. This is necessary as pdfminer
                    # first does a seek() to the end of the file. By carving
                    # it is ensured that there actually is an %%EOF at the
                    # end of the file.
                    if self.offset != 0 or self.infile.tell() != self.fileresult.filesize:
                        temporary_file = tempfile.mkstemp(dir=self.scan_environment.temporarydirectory)
                        os.sendfile(temporary_file[0], self.infile.fileno(), self.offset, self.infile.tell())
                        os.fdopen(temporary_file[0]).close()
                        pdffile = open(temporary_file[1], 'rb')
                        havetmpfile = True
                    else:
                        pdffile = self.infile

                    # parse the file with pdfminer
                    try:
                        # first create a parser object
                        self.parser = PDFParser(pdffile)

                        # create a document with the parser. By default
                        # pdfminer tries to be smart: if an error in the xref
                        # section is found it will seek() to the start of the
                        # file and parse from there as a fallback. This is
                        # specifically *NOT* what is needed here, so disable
                        # the fallback option.
                        self.doc = PDFDocument(self.parser, fallback=False)

                        # create a temporary string where the text
                        # converter can write data to
                        out = io.StringIO()

                        # extract text from the PDF here. This cannot be
                        # done later because the temporary file that is used
                        # will be removed after parsing.
                        rsrcmgr = PDFResourceManager()
                        device = TextConverter(rsrcmgr, out, laparams=LAParams())
                        interpreter = PDFPageInterpreter(rsrcmgr, device)
                        for page in PDFPage.create_pages(self.doc):
                            interpreter.process_page(page)
                        self.contents = out.getvalue()

                        best_eof = end_of_eof
                    except (pdfminer.psparser.PSEOF, pdfminer.pdfparser.PDFSyntaxError) as e:
                        # in case there is an error then this %%EOF is not
                        # a valid %%EOF for the file, so there is no need
                        # to continue parsing.
                        valid_eof = False
                        break
                    finally:
                        if havetmpfile:
                            pdffile.close()
                            os.unlink(temporary_file[1])

                    self.infile.seek(end_of_eof)
                    if self.offset + end_of_eof == self.fileresult.filesize:
                        break
                else:
                    # continue searching, with some overlap
                    # unless EOF has been reached
                    if self.offset + self.infile.tell() == self.fileresult.filesize:
                        break

                    self.infile.seek(-10, os.SEEK_CUR)

            if not valid_eof:
                break

            # stop if EOF has been reached
            if self.offset + self.infile.tell() == self.fileresult.filesize:
                break

        check_condition(best_eof != -1, "not a valid PDF")
        self.infile.seek(best_eof)

    def extract_metadata_and_labels(self):
        '''Extract metadata from the PDF file and set labels'''
        labels = ['pdf']
        metadata = {}
        metadata['contents'] = self.contents

        return(labels, metadata)

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        metadata = {}

        (labels, metadata) = self.extract_metadata_and_labels()
        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
