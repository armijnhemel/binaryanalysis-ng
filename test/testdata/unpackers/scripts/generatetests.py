#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# This file is part of BANG.
#
# Copyright 2018-2019 - Armijn Hemel
# Licensed under the terms of the GNU General Public License
# version 3
# SPDX-License-Identifier: GPL-3.0-only
#
# Program to generate test files from a base file using a few
# common patterns: cutting data, adding data, replacing data

import os
import sys
import stat
import argparse
import pathlib


# first use case: add random data to a file
def generate_add_random_data(filepath, randombytes):
    """Adds random data to a file"""
    extension = filepath.suffix
    filestem = filepath.stem

    outfilename = filepath.with_name("%s-%s%s" % (filestem, "add-random-data", extension))
    filesize = filepath.stat().st_size

    # open the original file for reading
    sourcefile = open(filepath, 'rb')
    offset = 0
    sourcefile.seek(offset)

    # open the target file for writing
    outfile = open(outfilename, 'wb')

    # add original data
    os.sendfile(outfile.fileno(), sourcefile.fileno(), offset, filesize)
    outfile.flush()

    # add random data
    outfile.write(randombytes)
    outfile.close()

    # close the original file
    sourcefile.close()


# second use case: prepend random data to a file
def generate_prepend_random_data(filepath, randombytes):
    """Prepends random data to a file"""
    extension = filepath.suffix
    filestem = filepath.stem

    outfilename = filepath.with_name("%s-%s%s" % (filestem, "prepend-random-data", extension))
    filesize = filepath.stat().st_size

    # open the original file for reading
    sourcefile = open(filepath, 'rb')
    offset = 0
    sourcefile.seek(offset)

    # open the target file for writing
    outfile = open(outfilename, 'wb')

    # add random data
    outfile.write(randombytes)
    outfile.flush()

    # add original data
    os.sendfile(outfile.fileno(), sourcefile.fileno(), offset, filesize)
    outfile.flush()
    outfile.close()

    # close the original file
    sourcefile.close()


# third use case: cut data from the end
def generate_cut_bytes_end(filepath, cutlength):
    """Cuts data from the end of a file"""
    extension = filepath.suffix
    filestem = filepath.stem

    outfilename = filepath.with_name("%s-%s%s" % (filestem, "cut-data-from-end", extension))
    filesize = filepath.stat().st_size

    # open the original file for reading
    sourcefile = open(filepath, 'rb')
    offset = 0
    sourcefile.seek(offset)

    # open the target file for writing
    outfile = open(outfilename, 'wb')

    # add original data, minus cutlength bytes
    os.sendfile(outfile.fileno(), sourcefile.fileno(),
                offset, filesize-cutlength)
    outfile.flush()
    outfile.close()

    # close the original file
    sourcefile.close()


# fourth use case: cut data from the end, add random data
def generate_cut_bytes_add_random_data(filepath, randombytes, cutlength):
    """Cuts data from the end of a file and adds random data to a file"""
    extension = filepath.suffix
    filestem = filepath.stem

    outfilename = filepath.with_name("%s-%s%s" % (filestem, "cut-data-from-end-add-random", extension))
    filesize = filepath.stat().st_size

    # open the original file for reading
    sourcefile = open(filepath, 'rb')
    offset = 0
    sourcefile.seek(offset)

    # open the target file for writing
    outfile = open(outfilename, 'wb')

    # add original data, minus cutlength bytes
    os.sendfile(outfile.fileno(), sourcefile.fileno(),
                offset, filesize-cutlength)
    outfile.flush()

    # add random data
    outfile.write(randombytes)
    outfile.flush()
    outfile.close()

    # close the original file
    sourcefile.close()


# fifth use case: cut data from middle
def generate_cut_bytes_from_middle(filepath, cutlength):
    """Cuts data from the middle of a file"""
    extension = filepath.suffix
    filestem = filepath.stem

    outfilename = filepath.with_name("%s-%s%s" % (filestem, "cut-data-from-middle", extension))
    filesize = filepath.stat().st_size

    # open the original file for reading
    sourcefile = open(filepath, 'rb')
    offset = 0
    sourcefile.seek(offset)

    middle = filesize//2

    # open the target file for writing
    outfile = open(outfilename, 'wb')

    # add half of original data
    os.sendfile(outfile.fileno(), sourcefile.fileno(), offset, middle)
    outfile.flush()

    # add rest of data, minus cutlength bytes
    os.sendfile(outfile.fileno(), sourcefile.fileno(),
                offset + middle + cutlength, filesize - middle - cutlength)
    outfile.flush()
    outfile.close()

    # close the original file
    sourcefile.close()


# sixth use case: data added to middle
def generate_add_bytes_to_middle(filepath, randombytes):
    """Adds data in the middle of a file"""
    extension = filepath.suffix
    filestem = filepath.stem

    outfilename = filepath.with_name("%s-%s%s" % (filestem, "data-added-to-middle", extension))
    filesize = filepath.stat().st_size

    # open the original file for reading
    sourcefile = open(filepath, 'rb')
    offset = 0
    sourcefile.seek(offset)

    middle = filesize//2

    # open the target file for writing
    outfile = open(outfilename, 'wb')

    # add half of original data
    os.sendfile(outfile.fileno(), sourcefile.fileno(), offset, middle)
    outfile.flush()

    # add random data
    outfile.write(randombytes)
    outfile.flush()

    # add rest of data
    os.sendfile(outfile.fileno(), sourcefile.fileno(), offset + middle, filesize - middle)
    outfile.flush()
    outfile.close()

    # close the original file
    sourcefile.close()


# seventh use case: data replaced in middle
def generate_replace_bytes_in_middle(filepath, randombytes):
    """Replaces data in the middle of a file"""
    extension = filepath.suffix
    filestem = filepath.stem

    outfilename = filepath.with_name("%s-%s%s" % (filestem, "data-replaced-in-middle", extension))
    filesize = filepath.stat().st_size

    # open the original file for reading
    sourcefile = open(filepath, 'rb')
    offset = 0
    sourcefile.seek(offset)

    middle = filesize//2

    # open the target file for writing
    outfile = open(outfilename, 'wb')

    # add half of original data
    os.sendfile(outfile.fileno(), sourcefile.fileno(), offset, middle)
    outfile.flush()

    # add random data
    outfile.write(randombytes)
    outfile.flush()

    # add rest of data
    os.sendfile(outfile.fileno(), sourcefile.fileno(),
                offset + middle + len(randombytes),
                filesize - middle - len(randombytes))
    outfile.flush()
    outfile.close()

    # close the original file
    sourcefile.close()


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", action="store", dest="checkfile",
                        help="path to original file", metavar="FILE")
    args = parser.parse_args()

    # sanity checks for the file to scan
    if args.checkfile is None:
        parser.error("No file to scan provided, exiting")

    # the file to scan should exist ...
    if not os.path.exists(args.checkfile):
        parser.error("File %s does not exist, exiting." % args.checkfile)

    # ... and should be a real file
    if not stat.S_ISREG(os.stat(args.checkfile).st_mode):
        parser.error("%s is not a regular file, exiting." % args.checkfile)

    # get a few random bytes of junk
    #randombytes = os.urandom(1024)
    randombytes = os.urandom(128)

    filepath = pathlib.PosixPath(args.checkfile).resolve()
    cutlength = 100

    generate_add_random_data(filepath, randombytes)
    generate_prepend_random_data(filepath, randombytes)
    generate_cut_bytes_end(filepath, cutlength)
    generate_cut_bytes_add_random_data(filepath, randombytes, cutlength)
    generate_cut_bytes_from_middle(filepath, cutlength)
    generate_add_bytes_to_middle(filepath, randombytes)
    generate_replace_bytes_in_middle(filepath, randombytes)

if __name__ == "__main__":
    main(sys.argv)
