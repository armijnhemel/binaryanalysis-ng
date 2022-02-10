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

import os
import shutil
import subprocess
import tempfile

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException

class Pack200UnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\xca\xfe\xd0\x0d')
    ]
    pretty_name = 'pack200'

    def parse(self):
        check_condition(False, "unsupported")
        check_condition(shutil.which('unpack200') is not None,
                        "pack200 program not found")

        # create a temporary directory
        temp_dir = tempfile.mkdtemp(dir=self.scan_environment.temporarydirectory)

        # the unpack200 tool only works on whole files. Finding out
        # where the file ends is TODO, but if there is data in front
        # of a valid pack200 file it is not a problem.
        havetmpfile = False
        if self.offset != 0:
            pass

        if havetmpfile:
            p = subprocess.Popen(['unpack200', temporaryfile[1], outfile_full],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 cwd=temp_dir)
        else:
            p = subprocess.Popen(['unpack200', self.fileresult.filename, outfile_full],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 cwd=temp_dir)

        (outputmsg, errormsg) = p.communicate()

        if havetmpfile:
            os.unlink(temporary_file[1])

## old code here
'''
# Transform a pack200 file to a JAR file using the unpack200 tool.
# This will not restore the original JAR file, as pack200 performs all kinds
# of optimizations, such as removing redundant classes, and so on.
#
# https://docs.oracle.com/javase/7/docs/technotes/guides/pack200/pack-spec.html
#
# The header format is described in section 5.2
def unpack_pack200(fileresult, scanenvironment, offset, unpackdir):
    filesize = fileresult.filesize
    filename_full = scanenvironment.unpack_path(fileresult.filename)
    unpackdir_full = scanenvironment.unpack_path(unpackdir)
    unpackedfilesandlabels = []
    labels = []
    unpackingerror = {}
    unpackedsize = 0
    unpackdir_full = scanenvironment.unpack_path(unpackdir)

    # first check if the unpack200 program is actually there
    if shutil.which('unpack200') is None:
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'unpack200 program not found'}
        return {'status': False, 'error': unpackingerror}

    # the unpack200 tool only works on whole files. Finding out
    # where the file ends is TODO, but if there is data in front
    # of a valid pack200 file it is not a problem.
    if offset != 0:
        # create a temporary file and copy the data into the
        # temporary file if offset != 0
        checkfile = open(filename_full, 'rb')
        temporaryfile = tempfile.mkstemp(dir=scanenvironment.temporarydirectory)
        os.sendfile(temporaryfile[0], checkfile.fileno(), offset, filesize - offset)
        os.fdopen(temporaryfile[0]).close()
        checkfile.close()

    # write unpacked data to a JAR file
    outfile_rel = os.path.join(unpackdir, "unpacked.jar")
    outfile_full = scanenvironment.unpack_path(outfile_rel)

    # create the unpacking directory
    os.makedirs(unpackdir_full, exist_ok=True)

    # then extract the file
    if offset != 0:
        p = subprocess.Popen(['unpack200', temporaryfile[1], outfile_full],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             cwd=unpackdir_full)
    else:
        p = subprocess.Popen(['unpack200', filename_full, outfile_full],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             cwd=unpackdir_full)
    (outputmsg, errormsg) = p.communicate()

    if offset != 0:
        os.unlink(temporaryfile[1])

    if p.returncode != 0:
        # try to remove any files that were possibly left behind
        try:
            os.unlink(outfile_full)
        except:
            pass
        unpackingerror = {'offset': offset+unpackedsize, 'fatal': False,
                          'reason': 'Not a valid pack200 file'}
        return {'status': False, 'error': unpackingerror}

    unpackedsize = filesize - offset

    if offset == 0 and unpackedsize == filesize:
        labels.append('pack200')

    unpackedfilesandlabels.append((outfile_rel, []))

    return {'status': True, 'length': unpackedsize, 'labels': labels,
            'filesandlabels': unpackedfilesandlabels}
'''
