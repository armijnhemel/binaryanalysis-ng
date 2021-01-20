#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright 2018-2020 - Armijn Hemel
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
import urllib

# import the requests module for downloading the XML
import requests

# import YAML module
from yaml import load
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader


# use several threads to download the Debian data. This is of no
# use if you are on a slow line with a bandwidth cap and it might
# actually be beneficial to use just a single thread.
def downloadfile(download_queue, fail_queue, debian_mirror, verbose):
    '''Download files from a Debian mirror'''
    while True:
        (debiandir, debianfile, debiansize, basestoredirectory) = download_queue.get()

        storeparts = debiandir.parts
        resultfilename = pathlib.Path(basestoredirectory, storeparts[1], debianfile)
        downloadurl = '%s/%s/%s' % (debian_mirror, debiandir, debianfile)

        # first check if the file already exists and is the right size
        if resultfilename.exists():
            if resultfilename.stat().st_size == debiansize and debiansize != 0:
                logging.info('ALREADY DOWNLOADED: %s', downloadurl)
                download_queue.task_done()
                continue
            # else remove the file as it is likely a failed download
            os.unlink(resultfilename)

        if verbose:
            logging.info('DOWNLOADING: %s', downloadurl)
        try:
            req = requests.get(downloadurl)
        except requests.exceptions.RequestException:
            fail_queue.put(debianfile)
            download_queue.task_done()
            continue

        if req.status_code != 200:
            fail_queue.put(debianfile)
            download_queue.task_done()
            logging.info('FAIL: %s', downloadurl)
            continue

        # write the data to the output file
        resultfile = open(resultfilename, 'wb')
        resultfile.write(req.content)
        resultfile.close()

        logging.info('SUCCESS: %s', downloadurl)

        download_queue.task_done()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", action="store", dest="cfg",
                        help="path to configuration file", metavar="FILE")
    parser.add_argument("-f", "--force", action="store_true", dest="force",
                        help="run if metadata hasn't changed")
    #parser.add_argument("-p", "--packagelist", action="store", dest="packagelist",
    #                    help="file with packages", metavar="FILE")
    args = parser.parse_args()

    '''
    packagelist = []

    # check if there is a file with packages to download. This overrides
    # the option of downloading packages in the ls-lR.gz file
    if args.packagelist is not None:
        if not os.path.exists(args.packagelist):
            parser.error("No configuration file provided, exiting")
        if not stat.S_ISREG(os.stat(args.packagelist).st_mode):
            parser.error("%s is not a regular file, exiting." % args.packagelist)
        try:
            packages = open(args.packagelist, 'r').readlines()
            for pkg in packages:
                if not pkg.startswith('Filename: '):
                    continue
                packagelist.append(pkg.strip().split(': ', 1)[1])
        except:
            pass
    '''

    # sanity checks for the configuration file
    if args.cfg is None:
        parser.error("No configuration file provided, exiting")

    # the configuration file should exist ...
    if not os.path.exists(args.cfg):
        parser.error("File %s does not exist, exiting." % args.cfg)

    # ... and should be a real file
    if not stat.S_ISREG(os.stat(args.cfg).st_mode):
        parser.error("%s is not a regular file, exiting." % args.cfg)

    # read the configuration file. This is in YAML format
    try:
        configfile = open(args.cfg, 'r')
        config = load(configfile, Loader=Loader)
    except:
        print("Cannot open configuration file, exiting", file=sys.stderr)
        sys.exit(1)

    # some sanity checks:
    if not 'config' in config:
        print("Invalid configuration file, exiting", file=sys.stderr)
        sys.exit(1)

    if not 'general' in config['config']:
        print("Invalid configuration file, exiting", file=sys.stderr)
        sys.exit(1)

    if not 'repositories' in config['config']:
        print("Invalid configuration file (no repositories defined), exiting", file=sys.stderr)
        sys.exit(1)

    # Set a few default values for general configuration options.
    # These can be overridden in the configuration file.
    storedirectory = ''
    verbose = False
    threads = multiprocessing.cpu_count()

    # check configuration options and change the default values if needed
    if 'verbose' in config['config']['general']:
        if isinstance(config['config']['general']['verbose'], bool):
            verbose = config['config']['general']['verbose']

    if 'storedirectory' not in config['config']['general']:
        print("no store directory defined in configuration file", file=sys.stderr)
        sys.exit(1)

    storedirectory = pathlib.Path(config['config']['general']['storedirectory'])

    # The number of threads to be created to download the files,
    # next to the main thread. Defaults to "all availabe threads".
    # WARNING: this might not always be faster!
    if 'threads' in config['config']['general']:
        if isinstance(config['config']['general']['threads'], int):
            threads = config['config']['general']['threads']
            # if 0 or a negative number was configured,
            # then use all available threads
            if threads < 1:
                threads = multiprocessing.cpu_count()

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

    repositories = []

    # create the repository configuration information based on
    # the configuration file and default values
    for repo in config['config']['repositories']:
        repo_entry = config['config']['repositories'][repo]

        # check to see if the repository is disabled
        if 'enabled' in repo_entry:
            if isinstance(repo_entry['enabled'], bool):
                if not repo_entry['enabled']:
                    continue

        # set a few default values
        debian_architectures = ['all', 'i386', 'amd64', 'arm64', 'armhf']
        debian_categories = ['dsc', 'source', 'patch', 'binary', 'dev']

        # this is a default value for Debian, not for Ubuntu. For Ubuntu
        # crawling this should be configured properly in the configuration file
        debian_directories = ['contrib', 'main', 'non-free']

        if not 'mirror' in repo_entry:
            continue

        repository = {'name': repo}
        repository['mirror'] = repo_entry['mirror']

        # extract architectures from configuration file
        if 'architectures' in repo_entry:
            if isinstance(repo_entry['architectures'], list):
                if repo_entry['architectures'] != []:
                    repository['architectures'] = repo_entry['architectures']
                else:
                    repository['architectures'] = debian_architectures
            else:
                repository['architectures'] = debian_architectures
        else:
            repository['architectures'] = debian_architectures

        # extract categories from configuration file
        if 'categories' in repo_entry:
            if isinstance(repo_entry['categories'], list):
                if repo_entry['categories'] != []:
                    repository['categories'] = repo_entry['categories']
                else:
                    repository['categories'] = debian_categories
            else:
                repository['categories'] = debian_categories
        else:
            repository['categories'] = debian_categories

        # extract directories from configuration file
        if 'directories' in repo_entry:
            if isinstance(repo_entry['directories'], list):
                if repo_entry['directories'] != []:
                    repository['directories'] = repo_entry['directories']
                else:
                    repository['directories'] = debian_directories
            else:
                repository['directories'] = debian_directories
        else:
            repository['directories'] = debian_directories
        repositories.append(repository)

    # download data for every repository that has been declared
    for repository in repositories:
        # create directory for the repository (by name)
        repo_directory = pathlib.Path(storedirectory, repository['name'])
        if not repo_directory.exists():
            repo_directory.mkdir()

        # now create a directory structure inside the scandirectory:
        # binary/ -- this is where all the binary data will be stored
        # source/ -- this is where all source files will be stored
        # meta/ -- this is where the ls-lR.gz file will be stored
        # dsc/  -- this is where the Debian package file descriptions
        #          will be stored
        # patches/ -- this is where the Debian specific patches (diff.gz)
        #          files will be stored
        # logs/ -- download logs will be stored here
        binary_directory = pathlib.Path(repo_directory, "binary")
        if not binary_directory.exists():
            binary_directory.mkdir()

        source_directory = pathlib.Path(repo_directory, "source")
        if not source_directory.exists():
            source_directory.mkdir()

        meta_data_dir = pathlib.Path(repo_directory, "meta")
        if not meta_data_dir.exists():
            meta_data_dir.mkdir()

        dsc_directory = pathlib.Path(repo_directory, "dsc")
        if not dsc_directory.exists():
            dsc_directory.mkdir()

        patches_directory = pathlib.Path(repo_directory, "patches")
        if not patches_directory.exists():
            patches_directory.mkdir()

        log_directory = pathlib.Path(repo_directory, "logs")
        if not log_directory.exists():
            log_directory.mkdir()

        download_date = datetime.datetime.utcnow()
        meta_outname = pathlib.Path(meta_data_dir,
                                    "ls-lR.gz-%s" % download_date.strftime("%Y%m%d-%H%M%S"))

        if meta_outname.exists():
            print("metadata file %s already exists. Skipping entry." % meta_outname,
                  file=sys.stderr)
            continue

        # recreate the download site data structure
        for i in repository['directories']:
            if not pathlib.Path(binary_directory, i).exists():
                pathlib.Path(binary_directory, i).mkdir()
            if not pathlib.Path(source_directory, i).exists():
                pathlib.Path(source_directory, i).mkdir()
            if not pathlib.Path(dsc_directory, i).exists():
                pathlib.Path(dsc_directory, i).mkdir()
            if not pathlib.Path(patches_directory, i).exists():
                pathlib.Path(patches_directory, i).mkdir()

        # Check if the Debian mirror was declared.
        if repository['mirror'] == '':
            print("Debian mirror not declared in configuration file, skipping entry",
                  file=sys.stderr)
            continue
        try:
            mirror_parts = urllib.parse.urlparse(repository['mirror'])
            if mirror_parts.scheme not in ['http', 'https', 'ftp', 'ftps']:
                print("Invalid URL '%s' for '%s', skipping entry" % (repository['mirror'], repository['name']),
                      file=sys.stderr)
                continue
            if mirror_parts.netloc == '':
                print("Invalid URL '%s' for '%s', skipping entry" % (repository['mirror'], repository['name']),
                      file=sys.stderr)
                continue
        except Exception:
            print("Debian mirror not a valid URL, skipping entry",
                  file=sys.stderr)
            continue

        # first download the ls-lR.gz file and see if it needs to be
        # processed by comparing it to the hash of the previously
        # downloaded file.
        try:
            req = requests.get('%s/ls-lR.gz' % repository['mirror'])
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
        hashfilename = os.path.join(repo_directory, "HASH")
        if os.path.exists(hashfilename):
            hashfile = open(hashfilename, 'r')
            oldhashdata = hashfile.read()
            hashfile.close()
            if oldhashdata == filehash and not args.force:
                print("Metadata for '%s' has not changed, skipping entry." % repository['name'])
                os.unlink(meta_outname)
                continue

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

        download_dsc = False
        if 'dsc' in repository['categories']:
            download_dsc = True

        download_binary = False
        if 'binary' in repository['categories']:
            download_binary = True

        download_patch = False
        if 'patch' in repository['categories']:
            download_patch = True

        download_source = False
        if 'source' in repository['categories']:
            download_source = True

        download_dev = False
        if 'dev' in repository['categories']:
            download_dev = True

        # add some counters for statistics
        deb_counter = 0
        src_counter = 0
        diff_counter = 0
        dsc_counter = 0

        # Process the ls-lR.gz and put all the tasks into a queue for downloading.
        lslr = gzip.open(meta_outname)
        inpool = False
        curdir = ''

        for i in lslr:
            if i.decode().startswith('./pool'):
                inpool = True
                curdir = pathlib.Path(i.decode().rsplit(':', 1)[0][2:])
            if not inpool:
                continue

            download_file = False
            for debian_dir in repository['directories']:
                if debian_dir in curdir.parts:
                    download_file = True
                    break
            if not download_file:
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
                if download_binary:
                    for ext in ['.deb', '.udeb']:
                        if downloadpath.endswith(ext):
                            if '-dev_' in downloadpath and not download_dev:
                                continue
                            for arch in repository['architectures']:
                                arch_ext = '_%s%s' % (arch, ext)
                                if downloadpath.endswith(arch_ext):
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
                                              args=(download_queue, fail_queue, repository['mirror'], verbose))
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

        '''
        for pkg in packagelist:
            curdir = pathlib.Path(pkg).parent
            downloadpath = pathlib.Path(pkg).name
            if downloadpath.endswith('.deb'):
                if '-dev_' in downloadpath and not download_dev:
                    continue
                for arch in debian_architectures:
                    if downloadpath.endswith('_%s.deb' % arch):
                        download_queue.put((curdir, downloadpath, 0, binary_directory))
                        deb_counter += 1
                        break
            download_queue.put((curdir, downloadpath, 0, binary_directory))
        '''

if __name__ == "__main__":
    main()
