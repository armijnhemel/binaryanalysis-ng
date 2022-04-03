#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright 2018-2022 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License version 3
# SPDX-License-Identifier: AGPL-3.0-only

'''
Crawls the release XML from F-Droid and stores files and metadata
from the XML on disk.

The XML release format is described at:

https://f-droid.org/en/docs/Build_Metadata_Reference/

and in the XML file itself:

https://f-droid.org/repo/index.xml

Note: this script only crawls the "repo/" part of F-Droid, not the
older "archive/" part!
'''

import datetime
import hashlib
import multiprocessing
import os
import pathlib
import queue
import sys
import tempfile
import urllib

# import defusedxml module to guard against XML attacks
import defusedxml.minidom

# import the requests module for downloading data
import requests

import click

# import YAML module
from yaml import load
try:
    from yaml import CSafeLoader as Loader
except ImportError:
    from yaml import Loader


# use several threads to download the F-Droid data. This is of no
# use if you are on a slow line with a bandwidth cap and it might
# actually be beneficial to use just a single thread.
def downloadfile(downloadqueue, failqueue, mirror, verbose):
    '''Download a single file from the F-Droid repository'''
    mirror_url = "%s/repo" % mirror
    while True:
        (fdroidfile, store_directory, filehash) = downloadqueue.get()

        resultfilename = os.path.join(store_directory, fdroidfile)

        # don't redownload if the file has already been
        # downloaded and has the correct file hash
        if os.path.exists(resultfilename):
            apk_hash = hashlib.new('sha256')
            resultfile = open(resultfilename, 'rb')
            apk_hash.update(resultfile.read())
            resultfile.close()
            apk_hash = apk_hash.hexdigest()
            if apk_hash == filehash:
                downloadqueue.task_done()
                continue

        try:
            if verbose:
                print("Attempting to download %s" % fdroidfile)
            req = requests.get('%s/%s' % (mirror_url, fdroidfile))
        except requests.exceptions.RequestException:
            if verbose:
                print("Failed to download %s" % fdroidfile)
            failqueue.put(fdroidfile)
            downloadqueue.task_done()
            continue

        if req.status_code != 200:
            # HTTP status code is not 'OK',
            # so continue with the next file
            if verbose:
                print("Failed to download %s" % fdroidfile)
            failqueue.put(fdroidfile)
            downloadqueue.task_done()
            continue

        # write the downloaded data to a file
        resultfile = open(resultfilename, 'wb')
        resultfile.write(req.content)
        resultfile.close()

        if filehash is not None:
            fdroid_hash = hashlib.new('sha256')
            fdroid_hash.update(req.content)
            if filehash != fdroid_hash.hexdigest():
                if verbose:
                    print("Failed to download %s" % fdroidfile)
                os.unlink(resultfilename)
                failqueue.put(fdroidfile)
                downloadqueue.task_done()
                continue
        downloadqueue.task_done()


@click.command(short_help='crawl F-Droid repositories')
@click.option('--config-file', '-c', required=True, help='configuration file', type=click.File('r'))
@click.option('--force', '-f', help='run if metadata hasn\'t changed', is_flag=True)
def main(config_file, force):
    # read the configuration file. This is in YAML format
    try:
        config = load(config_file, Loader=Loader)
    except:
        print("Cannot open configuration file, exiting", file=sys.stderr)
        sys.exit(1)

    # some sanity checks:
    if 'config' not in config:
        print("Invalid configuration file, exiting", file=sys.stderr)
        sys.exit(1)

    # Set a few default values for general configuration options.
    # These can be overridden in the configuration file.
    store_directory = ''
    verbose = False
    threads = multiprocessing.cpu_count()
    fdroid_categories = ['binary', 'source']
    mirror = 'https://f-droid.org/'

    # check configuration options and change the default values if needed
    if 'verbose' in config['config']:
        if isinstance(config['config']['verbose'], bool):
            verbose = config['config']['verbose']

    # The number of threads to be created to download the files,
    # next to the main thread. Defaults to "all availabe threads".
    # WARNING: this might not always be faster!
    if 'threads' in config['config']:
        if isinstance(config['config']['threads'], int):
            threads = config['config']['threads']
            # if 0 or a negative number was configured,
            # then use all available threads
            if threads < 1:
                threads = multiprocessing.cpu_count()

    if 'storedirectory' not in config['config']:
        print("no store directory defined in configuration file", file=sys.stderr)
        sys.exit(1)

    store_directory = pathlib.Path(config['config']['storedirectory'])

    # Check if the base unpack directory exists
    if not store_directory.exists():
        print("Store directory %s does not exist, exiting" % store_directory,
              file=sys.stderr)
        sys.exit(1)

    if not store_directory.is_dir():
        print("Store directory %s is not a directory, exiting" % store_directory,
              file=sys.stderr)
        sys.exit(1)

    # Check if the base unpack directory can be written to
    try:
        testfile = tempfile.mkstemp(dir=store_directory)
        os.unlink(testfile[1])
    except Exception:
        print("Base unpack directory %s cannot be written to, exiting" % store_directory,
              file=sys.stderr)
        sys.exit(1)

    if 'categories' in config['config']:
        if isinstance(config['config']['categories'], list):
            if config['config']['categories'] != []:
                fdroid_categories = config['config']['categories']

    if 'mirror' in config['config']:
        try:
            mirror_parts = urllib.parse.urlparse(config['config']['mirror'])
            if mirror_parts.scheme in ['http', 'https']:
                mirror = config['config']['mirror']
        except:
            pass

    # now create a directory structure inside the scandirectory:
    # binary/ -- this is where all the binary data will be stored
    # source/ -- this is where all source files will be stored
    # xml/ -- this is where the XML file from F-Droid will be stored
    binary_directory = os.path.join(store_directory, "binary")
    if not os.path.exists(binary_directory):
        os.mkdir(binary_directory)

    source_directory = os.path.join(store_directory, "source")
    if not os.path.exists(source_directory):
        os.mkdir(source_directory)

    xmldirectory = os.path.join(store_directory, "xml")
    if not os.path.exists(xmldirectory):
        os.mkdir(xmldirectory)

    downloaddate = datetime.datetime.utcnow()
    xmloutname = os.path.join(xmldirectory, "index.xml-%s" % downloaddate.strftime("%Y%m%d-%H%M%S"))

    if os.path.exists(xmloutname):
        print("XML file %s already exists, please retry later. Exiting." % xmloutname,
              file=sys.stderr)
        sys.exit(1)

    # first download the XML and see if it needs to be processed by
    # comparing it to the hash of the previous downloaded XML.
    try:
        req = requests.get('https://f-droid.org/repo/index.xml')
    except requests.exceptions.RequestException:
        print("Could not connect to F-Droid, exiting.", file=sys.stderr)
        sys.exit(1)

    if req.status_code != 200:
        print("Could not get F-Droid XML file, got code %d, exiting." % req.status_code,
              file=sys.stderr)
        sys.exit(1)

    # now store the XML file for future reference
    xmloutname = os.path.join(xmldirectory, "index.xml-%s" % downloaddate.strftime("%Y%m%d-%H%M%S"))
    xmlfile = open(xmloutname, 'wb')
    xmlfile.write(req.content)
    xmlfile.close()

    # first parse the XML data to see if it is valid XML data, else
    # remove the XML file and exit.
    try:
        fdroidxml = defusedxml.minidom.parseString(req.content)
    except:
        os.unlink(xmloutname)
        print("Could not parse F-Droid XML, exiting.", file=sys.stderr)
        sys.exit(1)

    # compute the SHA256 of the file to see if it is already known
    fdroid_hash = hashlib.new('sha256')
    fdroid_hash.update(req.content)
    filehash = fdroid_hash.hexdigest()

    # the hash of the latest file should always be stored in a file called HASH
    hashfilename = os.path.join(store_directory, "HASH")
    if os.path.exists(hashfilename):
        hashfile = open(hashfilename, 'r')
        oldhashdata = hashfile.read()
        hashfile.close()
        if oldhashdata == filehash and not force:
            print("Metadata has not changed, exiting.")
            os.unlink(xmloutname)
            sys.exit(0)

    # write the hash of the current data to the hash file
    hashfile = open(hashfilename, 'w')
    hashfile.write(filehash)
    hashfile.close()

    # now walk the XML and grab all the files in parallel
    processmanager = multiprocessing.Manager()

    # create a queue for scanning files
    downloadqueue = processmanager.JoinableQueue(maxsize=0)
    failqueue = processmanager.JoinableQueue(maxsize=0)
    processes = []

    download_binary = False
    if 'binary' in fdroid_categories:
        download_binary = True

    download_source = False
    if 'source' in fdroid_categories:
        download_source = True

    # Process the XML and put all the tasks into a queue for downloading.
    # If there is a SHA256 hash in the XML, then it is for the APK.
    apkcounter = 0
    srccounter = 0
    for i in fdroidxml.getElementsByTagName('package'):
        apkname = ''
        apkhash = ''
        for childnode in i.childNodes:
            if download_source and childnode.nodeName == 'srcname':
                fdroidfile = childnode.childNodes[0].data
                if os.path.exists(os.path.join(source_directory, fdroidfile)):
                    continue

                downloadqueue.put((fdroidfile, source_directory, None))
                srccounter += 1
            elif childnode.nodeName == 'hash':
                apkhash = childnode.childNodes[0].data
            elif childnode.nodeName == 'apkname':
                apkname = childnode.childNodes[0].data
                if os.path.exists(os.path.join(binary_directory, apkname)):
                    continue

        if download_binary and apkname != '':
            if apkhash != '':
                downloadqueue.put((apkname, binary_directory, apkhash))
            else:
                downloadqueue.put((apkname, binary_directory, apkhash))
            apkcounter += 1

    # create processes for unpacking archives
    for i in range(0, threads):
        process = multiprocessing.Process(target=downloadfile,
                                          args=(downloadqueue, failqueue, mirror, verbose))
        processes.append(process)

    # start all the processes
    for process in processes:
        process.start()

    downloadqueue.join()

    failedfiles = []

    while True:
        try:
            failedfiles.append(failqueue.get_nowait())
            failqueue.task_done()
        except queue.Empty:
            # Queue is empty
            break

    # block here until the failqueue is empty
    failqueue.join()

    # Done processing, terminate processes
    for process in processes:
        process.terminate()

    if verbose:
        print("Successfully downloaded: %d files" % ((apkcounter + srccounter) - len(failedfiles)))
        print("Failed to download: %d files" % len(failedfiles))


if __name__ == "__main__":
    main()
