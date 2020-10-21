#!/usr/bin/python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright 2018 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License version 3
# SPDX-License-Identifier: AGPL-3.0-only
#

'''
Script to crawl the release ls-lR.gz from Debian (or derivates) and store
files and metadata.

Run manually, or from a cronjob.
'''

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
def downloadfile(download_queue, fail_queue, debian_mirror):
    '''Download files from a Debian mirror'''
    while True:
        (debiandir, debianfile, debiansize, basestoredirectory) = download_queue.get()

        storeparts = debiandir.parts
        resultfilename = pathlib.Path(basestoredirectory, storeparts[1], debianfile)
        downloadurl = '%s/%s/%s' % (debian_mirror, debiandir, debianfile)

        # first check if the file already exists and is the right size
        if resultfilename.exists():
            if resultfilename.stat().st_size == debiansize:
                logging.info('ALREADY DOWNLOADED: %s' % downloadurl)
                download_queue.task_done()
                continue
            # else remove the file as it is likely a failed download
            os.unlink(resultfilename)

        try:
            req = requests.get(downloadurl)
        except requests.exceptions.RequestException:
            fail_queue.put(debianfile)
            download_queue.task_done()
            continue

        if req.status_code != 200:
            fail_queue.put(debianfile)
            download_queue.task_done()
            logging.info('FAIL: %s' % downloadurl)
            continue

        # write the data to the output file
        resultfile = open(resultfilename, 'wb')
        resultfile.write(req.content)
        resultfile.close()

        logging.info('SUCCESS: %s' % downloadurl)

        download_queue.task_done()


def main():
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
        config.read_file(configfile)
    except:
        print("Cannot open configuration file, exiting", file=sys.stderr)
        sys.exit(1)

    # set a few default values)
    storedirectory = ''
    debian_mirror = ''
    verbose = False
    debian_architectures = ['all', 'i386', 'amd64', 'arm64', 'armhf']
    debian_categories = ['dsc', 'source', 'patch', 'binary']
    debian_directories = ['contrib', 'main', 'non-free']

    # then process each individual section, extract configuration options
    # and change the default values if needed
    for section in config.sections():
        if section == 'debian':
            try:
                storedirectory = pathlib.Path(config.get(section, 'storedirectory'))
            except configparser.Error:
                break
            try:
                debian_mirror = config.get(section, 'mirror')
            except configparser.Error:
                break
            try:
                debian_architectures = config.get(section, 'architectures').split(',')
            except configparser.Error:
                break
            try:
                debian_categories = config.get(section, 'categories').split(',')
            except configparser.Error:
                break
            try:
                debian_directories = []
                debian_directories_tmp = config.get(section, 'directories').split(',')

                # simple sanity check to remove spaces
                for debian_directory in debian_directories_tmp:
                    debian_directories.append(debian_directory.strip())
            except configparser.Error:
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
            except configparser.Error:
                # use all available threads by default
                threads = multiprocessing.cpu_count()
    configfile.close()

    # Check if the Debian mirror was declared.
    if debian_mirror == '':
        print("Debian mirror not declared in configuration file, exiting",
              file=sys.stderr)
        sys.exit(1)

    # Check if the base unpack directory was declared.
    if storedirectory == '':
        print("Store directory not declared in configuration file, exiting",
              file=sys.stderr)
        sys.exit(1)

    # Check if the base unpack directory exists
    if not storedirectory.exists():
        print("Store directory %s does not exist, exiting" % storedirectory,
              file=sys.stderr)
        sys.exit(1)

    if not storedirectory.is_dir():
        print("Store directory %s is not a directory, exiting" % storedirectory,
              file=sys.stderr)
        sys.exit(1)

    # Check if the base unpack directory can be written to
    try:
        testfile = tempfile.mkstemp(dir=storedirectory)
        os.unlink(testfile[1])
    except Exception:
        print("Base unpack directory %s cannot be written to, exiting" % storedirectory,
              file=sys.stderr)
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
    binary_directory = pathlib.Path(storedirectory, "binary")
    if not binary_directory.exists():
        binary_directory.mkdir()

    source_directory = pathlib.Path(storedirectory, "source")
    if not source_directory.exists():
        source_directory.mkdir()

    meta_data_dir = pathlib.Path(storedirectory, "meta")
    if not meta_data_dir.exists():
        meta_data_dir.mkdir()

    dsc_directory = pathlib.Path(storedirectory, "dsc")
    if not dsc_directory.exists():
        dsc_directory.mkdir()

    patches_directory = pathlib.Path(storedirectory, "patches")
    if not patches_directory.exists():
        patches_directory.mkdir()

    log_directory = pathlib.Path(storedirectory, "logs")
    if not log_directory.exists():
        log_directory.mkdir()

    # recreate the download site data structure
    for i in debian_directories:
        if not pathlib.Path(binary_directory, i).exists():
            pathlib.Path(binary_directory, i).mkdir()
        if not pathlib.Path(source_directory, i).exists():
            pathlib.Path(source_directory, i).mkdir()
        if not pathlib.Path(dsc_directory, i).exists():
            pathlib.Path(dsc_directory, i).mkdir()
        if not pathlib.Path(patches_directory, i).exists():
            pathlib.Path(patches_directory, i).mkdir()

    download_date = datetime.datetime.utcnow()
    meta_outname = pathlib.Path(meta_data_dir,
                                "ls-lR.gz-%s" % download_date.strftime("%Y%m%d-%H%M%S"))

    if meta_outname.exists():
        print("metadata file %s already exists, please retry later. Exiting." % meta_outname,
              file=sys.stderr)
        sys.exit(1)

    # first download the ls-lR.gz file and see if it needs to be
    # processed by comparing it to the hash of the previously
    # downloaded file.
    try:
        req = requests.get('%s/ls-lR.gz' % debian_mirror)
    except requests.exceptions.RequestException:
        print("Could not connect to Debian mirror, exiting.", file=sys.stderr)
        sys.exit(1)

    if req.status_code != 200:
        print("Could not get Debian ls-lR.gz file, got code %d, exiting." % req.status_code,
              file=sys.stderr)
        sys.exit(1)

    # now store the ls-lR.gz file for future reference
    meta_outname = pathlib.Path(meta_data_dir,
                                "ls-lR.gz-%s" % download_date.strftime("%Y%m%d-%H%M%S"))
    metadata = meta_outname.open(mode='wb')
    metadata.write(req.content)
    metadata.close()

    # compute the SHA256 of the file to see if it is already known
    debian_hash = hashlib.new('sha256')
    debian_hash.update(req.content)
    filehash = debian_hash.hexdigest()

    # the hash of the latest file should always be stored in a file called HASH
    hashfilename = os.path.join(storedirectory, "HASH")
    if os.path.exists(hashfilename):
        hashfile = open(hashfilename, 'r')
        oldhashdata = hashfile.read()
        hashfile.close()
        if oldhashdata == filehash:
            print("Metadata has not changed, exiting.")
            os.unlink(meta_outname)
            sys.exit(0)

    # write the hash of the current data to the hash file
    hashfile = open(hashfilename, 'w')
    hashfile.write(filehash)
    hashfile.close()

    logging.basicConfig(filename=pathlib.Path(log_directory, 'download.log'),
                        level=logging.INFO, format='%(asctime)s %(message)s')

    # now walk the ls-lR file and grab all the files in parallel
    processmanager = multiprocessing.Manager()

    # create a queue for scanning files
    download_queue = processmanager.JoinableQueue(maxsize=0)
    fail_queue = processmanager.JoinableQueue(maxsize=0)
    processes = []

    # Process the ls-lR.gz and put all the tasks into a queue for downloading.
    lslr = gzip.open(meta_outname)
    inpool = False
    curdir = ''

    download_dsc = False
    if 'dsc' in debian_categories:
        download_dsc = True

    download_binary = False
    if 'binary' in debian_categories:
        download_binary = True

    download_patch = False
    if 'patch' in debian_categories:
        download_patch = True

    download_source = False
    if 'source' in debian_categories:
        download_source = True

    # add some counters for statistics
    deb_counter = 0
    src_counter = 0
    diff_counter = 0
    dsc_counter = 0

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
            if download_dsc and downloadpath.endswith('.dsc'):
                download_queue.put((curdir, downloadpath, filesize, dsc_directory))
                dsc_counter += 1
            if download_binary and downloadpath.endswith('.deb'):
                for arch in debian_architectures:
                    if downloadpath.endswith('_%s.deb' % arch):
                        download_queue.put((curdir, downloadpath, filesize, binary_directory))
                        deb_counter += 1
                        break
            if download_patch and downloadpath.endswith('.diff.gz'):
                download_queue.put((curdir, downloadpath, filesize, patches_directory))
                diff_counter += 1
            if download_source:
                for ext in ['.orig.tar.bz2', '.orig.tar.gz', '.orig.tar.xz']:
                    if downloadpath.endswith(ext):
                        download_queue.put((curdir, downloadpath, filesize, source_directory))
                        src_counter += 1
                        break
    lslr.close()

    # create processes for unpacking archives
    for i in range(0, threads):
        process = multiprocessing.Process(target=downloadfile,
                                          args=(download_queue, fail_queue, debian_mirror))
        processes.append(process)

    # start all the processes
    for process in processes:
        process.start()

    download_queue.join()

    failed_files = []

    while True:
        try:
            failed_files.append(fail_queue.get_nowait())
            fail_queue.task_done()
        except queue.Empty:
            # Queue is empty
            break

    # block here until the fail_queue is empty
    fail_queue.join()

    # Done processing, terminate processes
    for process in processes:
        process.terminate()

    if verbose:
        len_failed = len(failed_files)
        downloaded_files = (deb_counter + src_counter + dsc_counter + diff_counter) - len_failed
        print("Successfully downloaded: %d files" % downloaded_files)
        print("Failed to download: %d files" % len_failed)

if __name__ == "__main__":
    main()
