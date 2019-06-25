#!/usr/bin/python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright 2018 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License version 3
# SPDX-License-Identifier: AGPL-3.0-only
#
# Crawls the release ls-lR.gz from Debian and stores files and metadata

import sys
import os
import argparse
import configparser
import datetime
import stat
import hashlib
import tempfile
import multiprocessing
import queue
import gzip
import pathlib
import logging
import re

# import the requests module for downloading the XML
import requests


# use several threads to download the Debian data. This is of no
# use if you are on a slow line with a bandwidth cap and it might
# actually be beneficial to use just a single thread.
def downloadfile(downloadqueue, failqueue, debianmirror):
    while True:
        (debiandir, debianfile, debiansize, basestoredirectory) = downloadqueue.get()

        storeparts = debiandir.parts
        resultfilename = pathlib.Path(basestoredirectory, storeparts[1], debianfile)
        downloadurl = '%s/%s/%s' % (debianmirror, debiandir, debianfile)

        # first check if the file already exists and is the right size
        if resultfilename.exists():
            if resultfilename.stat().st_size == debiansize:
                logging.info('ALREADY DOWNLOADED: %s' % downloadurl)
                downloadqueue.task_done()
                continue
            # else remove the file as it is likely a failed download
            os.unlink(resultfilename)

        try:
            r = requests.get(downloadurl)
        except:
            failqueue.put(debianfile)
            downloadqueue.task_done()
            continue

        if r.status_code != 200:
            failqueue.put(debianfile)
            downloadqueue.task_done()
            logging.info('FAIL: %s' % downloadurl)
            continue

        # write the data to the output file
        resultfile = open(resultfilename, 'wb')
        resultfile.write(r.content)
        resultfile.close()

        logging.info('SUCCESS: %s' % downloadurl)

        downloadqueue.task_done()


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", action="store", dest="cfg",
                        help="path to configuration file", metavar="FILE")
    args = parser.parse_args()

    # sanity checks for the configuration file
    if args.cfg is None:
        parser.error("No configuration file provided, exiting")

    # the configuration file should exist ...
    if not os.path.exists(args.cfg):
        parser.error("File %s does not exist, exiting." % args.cfg)

    # ... and should be a real file
    if not stat.S_ISREG(os.stat(args.cfg).st_mode):
        parser.error("%s is not a regular file, exiting." % args.cfg)

    # read the configuration file. This is in Windows INI format.
    config = configparser.ConfigParser()

    try:
        configfile = open(args.cfg, 'r')
        config.readfp(configfile)
    except:
        print("Cannot open configuration file, exiting", file=sys.stderr)
        sys.exit(1)

    # set a few default values)
    storedirectory = ''
    debianmirror = ''
    verbose = False

    # then process each individual section and extract configuration options
    for section in config.sections():
        if section == 'debian':
            try:
                storedirectory = pathlib.Path(config.get(section, 'storedirectory'))
            except Exception:
                break
            try:
                debianmirror = config.get(section, 'debianmirror')
            except Exception:
                break

        elif section == 'general':
            # The number of threads to be created to download the files,
            # next to the main thread. Defaults to "all availabe threads".
            # WARNING: this might not always be faster!
            try:
                threads = min(int(config.get(section, 'threads')), multiprocessing.cpu_count())
                # if 0 or a negative number was configured,
                # then use all available threads
                if threads < 1:
                    threads = multiprocessing.cpu_count()
            except Exception:
                # use all available threads by default
                threads = multiprocessing.cpu_count()
    configfile.close()

    # Check if the Debian mirror was declared.
    if debianmirror == '':
        print("Debian mirror not declared in configuration file, exiting", file=sys.stderr)
        sys.exit(1)

    # Check if the base unpack directory was declared.
    if storedirectory == '':
        print("Store directory not declared in configuration file, exiting", file=sys.stderr)
        sys.exit(1)

    # Check if the base unpack directory exists
    if not storedirectory.exists():
        print("Store directory %s does not exist, exiting" % storedirectory, file=sys.stderr)
        sys.exit(1)

    if not storedirectory.is_dir():
        print("Store directory %s is not a directory, exiting" % storedirectory, file=sys.stderr)
        sys.exit(1)

    # Check if the base unpack directory can be written to
    try:
        testfile = tempfile.mkstemp(dir=storedirectory)
        os.unlink(testfile[1])
    except Exception as e:
        print("Base unpack directory %s cannot be written to, exiting" % storedirectory, file=sys.stderr)
        sys.exit(1)

    # now create a directory structure inside the scandirectory:
    # binary/ -- this is where all the binary data will be stored
    # source/ -- this is where all source files will be stored
    # meta/ -- this is where the ls-lR.gz file will be stored
    # dsc/  -- this is where the Debian package file descriptions
    #          will be stored
    # patches/ -- this is where the Debian specific patches (diff.gz)
    #          files will be stored
    # logs/ -- download logs will be stored here
    binarydirectory = pathlib.Path(storedirectory, "binary")
    if not binarydirectory.exists():
        binarydirectory.mkdir()

    sourcedirectory = pathlib.Path(storedirectory, "source")
    if not sourcedirectory.exists():
        sourcedirectory.mkdir()

    metadatadirectory = pathlib.Path(storedirectory, "meta")
    if not metadatadirectory.exists():
        metadatadirectory.mkdir()

    dscdirectory = pathlib.Path(storedirectory, "dsc")
    if not dscdirectory.exists():
        dscdirectory.mkdir()

    patchesdirectory = pathlib.Path(storedirectory, "patches")
    if not patchesdirectory.exists():
        patchesdirectory.mkdir()

    logdirectory = pathlib.Path(storedirectory, "logs")
    if not logdirectory.exists():
        logdirectory.mkdir()

    # recreate the Debian contrib/main/non-free data structure
    for i in ['contrib', 'main', 'non-free']:
        if not pathlib.Path(binarydirectory, i).exists():
            pathlib.Path(binarydirectory, i).mkdir()
        if not pathlib.Path(sourcedirectory, i).exists():
            pathlib.Path(sourcedirectory, i).mkdir()
        if not pathlib.Path(dscdirectory, i).exists():
            pathlib.Path(dscdirectory, i).mkdir()
        if not pathlib.Path(patchesdirectory, i).exists():
            pathlib.Path(patchesdirectory, i).mkdir()

    downloaddate = datetime.datetime.utcnow()
    metadataoutname = pathlib.Path(metadatadirectory, "ls-lR.gz-%s" % downloaddate.strftime("%Y%m%d-%H%M%S"))

    if metadataoutname.exists():
        print("metadata file %s already exists, please retry later. Exiting." % xmloutname, file=sys.stderr)
        sys.exit(1)

    # first download the ls-lR.gz file and see if it needs to be
    # processed by comparing it to the hash of the previously
    # downloaded file.
    try:
        r = requests.get('%s/ls-lR.gz' % debianmirror)
    except:
        print("Could not connect to Debian mirror, exiting.", file=sys.stderr)
        sys.exit(1)

    if r.status_code != 200:
        print("Could not get Debian ls-lR.gz file, got code %d, exiting." % r.status_code, file=sys.stderr)
        sys.exit(1)

    # now store the ls-lR.gz file for future reference
    metadataoutname = pathlib.Path(metadatadirectory, "ls-lR.gz-%s" % downloaddate.strftime("%Y%m%d-%H%M%S"))
    metadata = metadataoutname.open(mode='wb')
    metadata.write(r.content)
    metadata.close()

    # compute the SHA256 of the file to see if it is already known
    h = hashlib.new('sha256')
    h.update(r.content)
    filehash = h.hexdigest()

    # the hash of the latest file should always be stored in a file called HASH
    hashfilename = os.path.join(storedirectory, "HASH")
    if os.path.exists(hashfilename):
        hashfile = open(hashfilename, 'r')
        oldhashdata = hashfile.read()
        hashfile.close()
        if oldhashdata == filehash:
            print("Metadata has not changed, exiting.")
            os.unlink(metadataoutname)
            sys.exit(0)

    # write the hash of the current data to the hash file
    hashfile = open(hashfilename, 'w')
    hashfile.write(filehash)
    hashfile.close()

    logging.basicConfig(filename=pathlib.Path(logdirectory, 'download.log'),
                        level=logging.INFO, format='%(asctime)s %(message)s')

    # now walk the ls-lR file and grab all the files in parallel
    processmanager = multiprocessing.Manager()

    # create a queue for scanning files
    downloadqueue = processmanager.JoinableQueue(maxsize=0)
    failqueue = processmanager.JoinableQueue(maxsize=0)
    processes = []

    debianarchitectures = ['all', 'i386', 'amd64', 'arm64', 'armhf']

    # Process the ls-lR.gz and put all the tasks into a queue for downloading.
    lslr = gzip.open(metadataoutname)
    inpool = False
    curdir = ''
    for i in lslr:
        if i.decode().startswith('./pool'):
            inpool = True
            curdir = pathlib.Path(i.decode().rsplit(':', 1)[0][2:])
        if not inpool:
            continue
        # end of the pool reached
        if i.decode().startswith('./project'):
            break
        if i.decode().startswith('-'):
            downloadpath = i.decode().strip().rsplit(' ', 1)[1]
            filesize = int(re.sub(r'  +', ' ', i.decode().strip()).split(' ')[4])
            if downloadpath.endswith('.dsc'):
                downloadqueue.put((curdir, downloadpath, filesize, dscdirectory))
            if downloadpath.endswith('.deb'):
                for d in debianarchitectures:
                    if downloadpath.endswith('_%s.deb' % d):
                        downloadqueue.put((curdir, downloadpath, filesize, binarydirectory))
                        break
            if downloadpath.endswith('.diff.gz'):
                downloadqueue.put((curdir, downloadpath, filesize, patchesdirectory))
            if downloadpath.endswith('.orig.tar.bz2'):
                downloadqueue.put((curdir, downloadpath, filesize, sourcedirectory))
            if downloadpath.endswith('.orig.tar.gz'):
                downloadqueue.put((curdir, downloadpath, filesize, sourcedirectory))
            if downloadpath.endswith('.orig.tar.xz'):
                downloadqueue.put((curdir, downloadpath, filesize, sourcedirectory))
    lslr.close()

    # create processes for unpacking archives
    for i in range(0, threads):
        p = multiprocessing.Process(target=downloadfile, args=(downloadqueue, failqueue, debianmirror))
        processes.append(p)

    # start all the processes
    for p in processes:
        p.start()

    downloadqueue.join()

    failedfiles = []

    while True:
        try:
            failedfiles.append(failqueue.get_nowait())
            failqueue.task_done()
        except queue.Empty as e:
            # Queue is empty
            break

    # block here until the failqueue is empty
    failqueue.join()

    # Done processing, terminate processes
    for p in processes:
        p.terminate()

    if verbose:
        print("Successfully downloaded: %d files" % ((apkcounter + srccounter) - len(failedfiles)))
        print("Failed to download: %d files" % len(failedfiles))

if __name__ == "__main__":
    main(sys.argv)
