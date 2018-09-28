#!/usr/bin/python3

# Binary Analysis Next Generation (BANG!)
#
# This file is part of BANG.
#
# BANG is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License,
# version 3, as published by the Free Software Foundation.
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
# Copyright 2018 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License
# version 3
# SPDX-License-Identifier: AGPL-3.0-only
#
# Processes a BANG log file to see which errors were triggered the
# most, as this is useful to find which checks to tighten and see
# which checks possibly need to be inlined into the main program.

import os
import sys
import stat
import pathlib
import collections
import re
import argparse

# import own modules
import bangsignatures


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", action="store", dest="checkfile",
                        help="path to file to check", metavar="FILE")
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

    filesize = os.stat(args.checkfile).st_size

    # Don't scan an empty file
    if filesize == 0:
        print("File to scan is empty, exiting", file=sys.stderr)
        sys.exit(1)

    bangerrors = collections.Counter()
    bangerrormessages = {}

    # open the file, assume for now that everything is in UTF-8
    # (famous last words).
    logfile = open(args.checkfile, 'r')
    for i in logfile:
        if 'FAIL' not in i:
            continue
        # ignore the 'known extension' entries
        if ' known extension ' in i:
            continue
        bangfail = i.strip().rsplit(':', 1)[1].strip()
        for s in bangsignatures.signatures:
            if " %s at offset" % s in i.strip():
                bangerrors.update([s])
                if s not in bangerrormessages:
                    bangerrormessages[s] = collections.Counter()
                bangerrormessages[s].update([bangfail])
                break
    logfile.close()

    # print the error messages in descending order
    for e in bangerrors.most_common():
        print("Signature %s: %d" % e)
        for s in bangerrormessages[e[0]].most_common():
            print("%s: %d" % s)
        print()

if __name__ == "__main__":
    main(sys.argv)
