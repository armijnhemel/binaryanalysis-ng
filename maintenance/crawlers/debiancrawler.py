#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright 2018-2021 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License version 3
# SPDX-License-Identifier: AGPL-3.0-only

'''
Script to crawl the release ls-lR.gz from Debian (or derivates) and store
files and metadata.

Run manually, or from a cronjob.
'''

import sys
import os
import datetime
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

import click

# import YAML module
from yaml import load
try:
    from yaml import CSafeLoader as Loader
except ImportError:
    from yaml import Loader


class ConfigError(Exception):
    pass


class Config:
    '''Crawler configuration class'''
    def __init__(self, configfile):
        # read the configuration file. This is in YAML format
        config = load(configfile, Loader=Loader)

        # some sanity checks:
        if 'config' not in config:
            raise ConfigError("'config' not in configuration")

        if 'general' not in config['config']:
            raise ConfigError("'general' not in configuration")

        if 'repositories' not in config['config']:
            raise ConfigError("'repositories' not in configuration")

        if 'storedirectory' not in config['config']['general']:
            raise ConfigError("'storedirectory' not in configuration")

        # Set a few default values for general configuration options.
        # These can be overridden in the configuration file.
        self.storedirectory = ''
        self.verbose = False
        self.threads = multiprocessing.cpu_count()

        # check configuration options and change the default values if needed
        if 'verbose' in config['config']['general']:
            if isinstance(config['config']['general']['verbose'], bool):
                self.verbose = config['config']['general']['verbose']

        # The number of threads to be created to download the files,
        # next to the main thread. Defaults to "all availabe threads".
        # WARNING: this might not always be faster!
        if 'threads' in config['config']['general']:
            if isinstance(config['config']['general']['threads'], int):
                threads = config['config']['general']['threads']
                # if 0 or a negative number was configured,
                # then use the default value, otherwise use
                # the value from the configuration file
                if threads > 0:
                    self.threads = threads

        self.storedirectory = pathlib.Path(config['config']['general']['storedirectory'])

        # Check if the base unpack directory exists
        if not self.storedirectory.exists():
            raise ConfigError("Store directory %s does not exist" % self.storedirectory)

        if not self.storedirectory.is_dir():
            raise ConfigError("Store directory %s is not a directory" % self.storedirectory)

        # Check if the base unpack directory can be written to
        try:
            testfile = tempfile.mkstemp(dir=self.storedirectory)
            os.unlink(testfile[1])
        except Exception as e:
            raise ConfigError("Base unpack directory %s: %s" % (self.storedirectory, e))

        self.repositories = config['config']['repositories']

class Packages:
    '''Packages.gz object'''
    def __init__(self, packages_file, arch):
        self.packages_file = packages_file
        self.packages = []
        self.arch = arch
        self.parse()

    def parse(self):
        packages = gzip.open(self.packages_file)

        cur_package = None
        for i in packages:
            line = i.decode().strip()
            if line.startswith('Package'):
                if cur_package is not None:
                    self.packages.append(cur_package)
                cur_package = {}
            if cur_package is None:
                continue
            if line.startswith('Size'):
                cur_package['size'] = int(line.split(':')[1].strip())
            elif line.startswith('Filename'):
                cur_package['filename'] = line.split(':')[1].strip()
            elif line.startswith('Architecture'):
                arch = line.split(':')[1].strip()
                if self.arch != arch:
                    cur_package = None
        packages.close()
        if cur_package is not None:
            self.packages.append(cur_package)


class Lslr:
    '''ls-lr.gz object'''
    def __init__(self, lslrfile, repository):
        self.lslrfile = lslrfile
        self.repository = repository

        # add some counters for statistics
        self.deb_counter = 0
        self.src_counter = 0
        self.diff_counter = 0
        self.dsc_counter = 0

        self.dscs = []
        self.debs = []
        self.srcs = []
        self.diffs = []

        self.parse()

    def parse(self):
        lslr = gzip.open(self.lslrfile)
        inpool = False
        curdir = ''

        for i in lslr:
            if i.decode().startswith('./pool'):
                inpool = True
                curdir = pathlib.Path(i.decode().rsplit(':', 1)[0][2:])
            if not inpool:
                continue

            download_file = False
            for debian_dir in self.repository.directories:
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
                if self.repository.download_dsc and downloadpath.endswith('.dsc'):
                    self.dscs.append((curdir, downloadpath, filesize))
                    self.dsc_counter += 1
                if self.repository.download_binary:
                    for ext in ['.deb', '.udeb']:
                        if downloadpath.endswith(ext):
                            if '-dev_' in downloadpath and not self.repository.download_dev:
                                continue
                            for arch in self.repository.architectures:
                                arch_ext = '_%s%s' % (arch, ext)
                                if downloadpath.endswith(arch_ext):
                                    self.debs.append((curdir, downloadpath, filesize))
                                    self.deb_counter += 1
                                    break
                if self.repository.download_patch and downloadpath.endswith('.diff.gz'):
                    self.diffs.append((curdir, downloadpath, filesize))
                    self.diff_counter += 1
                if self.repository.download_source:
                    for ext in ['.orig.tar.bz2', '.orig.tar.gz', '.orig.tar.xz']:
                        if downloadpath.endswith(ext):
                            self.srcs.append((curdir, downloadpath, filesize))
                            self.src_counter += 1
                            break
        lslr.close()


class Repository:
    '''Represents a Debian(-derived) repository'''
    def __init__(self, name, mirror):
        self.name = name
        self.mirror = mirror

        # set a few default values
        self._architectures = ['all', 'i386', 'amd64', 'arm64', 'armhf']
        self._categories = ['dsc', 'source', 'patch', 'binary', 'dev']
        self._directories = []

        self.download_dsc = False
        self.download_binary = False
        self.download_patch = False
        self.download_source = False
        self.download_dev = False

    @property
    def architectures(self):
        return self._architectures

    @architectures.setter
    def architectures(self, architectures):
        self._architectures = architectures

    @property
    def categories(self):
        return self._categories

    @categories.setter
    def categories(self, categories):
        self._categories = categories
        if 'dsc' in categories:
            self.download_dsc = True
        if 'binary' in categories:
            self.download_binary = True
        if 'patch' in categories:
            self.download_patch = True
        if 'source' in categories:
            self.download_source = True
        if 'dev' in categories:
            self.download_dev = True

    @property
    def directories(self):
        return self._directories

    @directories.setter
    def directories(self, directories):
        self._directories = directories


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
            if resultfilename.stat().st_size == debiansize and debiansize != 0:
                logging.info('ALREADY DOWNLOADED: %s', downloadurl)
                download_queue.task_done()
                continue
            # else remove the file as it is likely a failed download
            os.unlink(resultfilename)

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


def create_debian_directories(repo_directory, repository):
    # create directory for the repository (by name)
    if not repo_directory.exists():
        repo_directory.mkdir(parents=True)

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

    meta_data_directory = pathlib.Path(repo_directory, "meta")
    if not meta_data_directory.exists():
        meta_data_directory.mkdir()

    dsc_directory = pathlib.Path(repo_directory, "dsc")
    if not dsc_directory.exists():
        dsc_directory.mkdir()

    patches_directory = pathlib.Path(repo_directory, "patches")
    if not patches_directory.exists():
        patches_directory.mkdir()

    log_directory = pathlib.Path(repo_directory, "logs")
    if not log_directory.exists():
        log_directory.mkdir()

    # recreate the download site data structure
    for i in repository.directories:
        if not pathlib.Path(binary_directory, i).exists():
            pathlib.Path(binary_directory, i).mkdir()
        if not pathlib.Path(source_directory, i).exists():
            pathlib.Path(source_directory, i).mkdir()
        if not pathlib.Path(dsc_directory, i).exists():
            pathlib.Path(dsc_directory, i).mkdir()
        if not pathlib.Path(patches_directory, i).exists():
            pathlib.Path(patches_directory, i).mkdir()
    return {'binary_directory': binary_directory,
            'source_directory': source_directory,
            'meta_data_directory': meta_data_directory,
            'dsc_directory': dsc_directory,
            'patches_directory': patches_directory,
            'repo_directory': repo_directory,
            'log_directory': log_directory}


def create_repositories(config):
    repositories = []

    # create the repository configuration information based on
    # the configuration file and default values
    for repo in config.repositories:
        repo_entry = config.repositories[repo]

        # check to see if the repository is disabled
        if 'enabled' in repo_entry:
            if isinstance(repo_entry['enabled'], bool):
                if not repo_entry['enabled']:
                    continue

        if 'mirror' not in repo_entry:
            continue
        mirror = repo_entry['mirror']

        # Check if the Debian mirror was declared.
        if mirror == '':
            print("Debian mirror not declared in configuration file, skipping entry",
                  file=sys.stderr)
            continue

        # Sanity checks for the Debian mirrors, only support certain protocols
        try:
            mirror_parts = urllib.parse.urlparse(mirror)
            if mirror_parts.scheme not in ['http', 'https', 'ftp', 'ftps']:
                print("Invalid URL '%s' for '%s', skipping entry" % (mirror, repo_entry),
                      file=sys.stderr)
                continue
            if mirror_parts.netloc == '':
                print("Invalid URL '%s' for '%s', skipping entry" % (mirror, repo_entry),
                      file=sys.stderr)
                continue
        except Exception:
            print("Debian mirror not a valid URL, skipping entry",
                  file=sys.stderr)
            continue

        # create a repository object for this repository
        repository = Repository(repo, mirror)

        # extract architectures from configuration file and store
        if 'architectures' in repo_entry:
            if isinstance(repo_entry['architectures'], list):
                if repo_entry['architectures'] != []:
                    repository.architectures = repo_entry['architectures']

        # extract categories from configuration file and store
        if 'categories' in repo_entry:
            if isinstance(repo_entry['categories'], list):
                if repo_entry['categories'] != []:
                    repository.categories = repo_entry['categories']

        # this is a default value for Debian, not for Ubuntu. For Ubuntu
        # crawling this should be configured properly in the configuration file
        debian_directories = ['contrib', 'main', 'non-free']
        repository.directories = debian_directories

        # extract directories from configuration file and store
        if 'directories' in repo_entry:
            if isinstance(repo_entry['directories'], list):
                if repo_entry['directories'] != []:
                    repository.directories = repo_entry['directories']
        repositories.append(repository)

    return repositories


@click.group()
def main():
   pass

@main.command(short_help='download Debian files')
@click.option('--config', '-c', required=True, help='path to configuration file', type=click.File('r'))
@click.option('--force', '-f', help='run if metadata hasn\'t changed', is_flag=True)
def download(config, force):
    try:
        crawler_config = Config(config)
    except Exception as e:
        print("Cannot open or process configuration file: %s. Exiting." % e, file=sys.stderr)
        sys.exit(1)

    repositories = create_repositories(crawler_config)

    # download data for every repository that has been declared
    for repository in repositories:
        repo_directory = crawler_config.storedirectory / repository.name
        debian_dirs = create_debian_directories(repo_directory, repository)

        # write logging output to a separate log file. This file can
        # get large, so it might be useful periodically truncate with
        # for example logrotate
        logging.basicConfig(filename=pathlib.Path(debian_dirs['log_directory'], 'download.log'),
                            level=logging.INFO, format='%(asctime)s %(message)s')

        download_date = datetime.datetime.utcnow()
        meta_outname = pathlib.Path(debian_dirs['meta_data_directory'],
                                    "ls-lR.gz-%s" % download_date.strftime("%Y%m%d-%H%M%S"))

        if meta_outname.exists():
            print("metadata file %s already exists. Skipping entry." % meta_outname,
                  file=sys.stderr)

        # first download the ls-lR.gz file and see if it needs to be
        # processed by comparing it to the hash of the previously
        # downloaded file.
        try:
            req = requests.get('%s/ls-lR.gz' % repository.mirror)
        except requests.exceptions.RequestException:
            print("Could not connect to Debian mirror, continuing.", file=sys.stderr)
            continue

        if req.status_code != 200:
            print("Could not get Debian ls-lR.gz file, got code %d, continuing." % req.status_code,
                  file=sys.stderr)
            continue

        # now store the ls-lR.gz file for future reference
        metadata = meta_outname.open(mode='wb')
        metadata.write(req.content)
        metadata.close()

        # compute the SHA256 of the file to see if it is already known
        debian_hash = hashlib.new('sha256')
        debian_hash.update(req.content)
        filehash = debian_hash.hexdigest()

        # the hash of the latest file should always be stored in a file called HASH
        hashfilename = os.path.join(debian_dirs['repo_directory'], "HASH")
        if os.path.exists(hashfilename):
            hashfile = open(hashfilename, 'r')
            oldhashdata = hashfile.read()
            hashfile.close()
            if oldhashdata == filehash and not force:
                print("Metadata for '%s' has not changed, skipping entry." % repository.name)
                os.unlink(meta_outname)
                continue

        # write the hash of the current data to the hash file
        hashfile = open(hashfilename, 'w')
        hashfile.write(filehash)
        hashfile.close()

        # Parse the ls-lR.gz file
        lslr = Lslr(meta_outname, repository)

        # now walk the ls-lR file and grab all the files in parallel
        processmanager = multiprocessing.Manager()

        # create a queue for scanning files
        download_queue = processmanager.JoinableQueue(maxsize=0)
        fail_queue = processmanager.JoinableQueue(maxsize=0)
        processes = []

        # put all the tasks into the download queue for downloading.
        for d in lslr.dscs:
            download_queue.put(d + (debian_dirs['dsc_directory'],))
        for d in lslr.debs:
            download_queue.put(d + (debian_dirs['binary_directory'],))
        for d in lslr.diffs:
            download_queue.put(d + (debian_dirs['patches_directory'],))
        for d in lslr.srcs:
            download_queue.put(d + (debian_dirs['source_directory'],))

        # create processes for unpacking archives
        for i in range(0, crawler_config.threads):
            process = multiprocessing.Process(target=downloadfile,
                                              args=(download_queue, fail_queue, repository.mirror))
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

        if crawler_config.verbose:
            len_failed = len(failed_files)
            downloaded_files = (lslr.deb_counter + lslr.src_counter + lslr.dsc_counter + lslr.diff_counter) - len_failed
            print("Successfully downloaded: %d files" % downloaded_files)
            print("Failed to download: %d files" % len_failed)


@main.command(short_help='download binaries from a single Debian repository')
@click.option('--config', '-c', required=True, help='path to configuration file', type=click.File('r'))
@click.option('--repository', '-r', required=True, help='repository to download from')
@click.option('--distribution', '-d', required=True, help='specific distribution to download')
@click.option('--force', '-f', help='run if metadata hasn\'t changed', is_flag=True)
def download_single_version(config, force, repository, distribution):
    try:
        crawler_config = Config(config)
    except Exception as e:
        print("Cannot open or process configuration file: %s. Exiting." % e, file=sys.stderr)
        sys.exit(1)

    repositories = create_repositories(crawler_config)

    for repo in repositories:
        if repo.name != repository:
            continue
        # check if the distribution exists on the mirror
        download_url = '%s/dists/%s' % (repo.mirror, distribution)

        try:
            req = requests.get(download_url)
        except requests.exceptions.RequestException:
            continue

        if req.status_code != 200:
            continue

        repo_directory = crawler_config.storedirectory / repo.name / 'dists' / distribution

        debian_dirs = create_debian_directories(repo_directory, repo)

        processmanager = multiprocessing.Manager()

        # create a queue for scanning files
        download_queue = processmanager.JoinableQueue(maxsize=0)
        fail_queue = processmanager.JoinableQueue(maxsize=0)

        # grab the Packages files for the defined architectures per directory
        for d in repo.directories:
            for arch in repo.architectures:
                download_url = '%s/dists/%s/%s/binary-%s/Packages.gz' % (repo.mirror, distribution, d, arch)

                try:
                    req = requests.get(download_url)
                except requests.exceptions.RequestException:
                    continue

                if req.status_code != 200:
                    continue

                download_date = datetime.datetime.utcnow()
                meta_directory = debian_dirs['meta_data_directory'] / d
                if not meta_directory.exists():
                    meta_directory.mkdir()

                meta_outname = meta_directory / ("Packages.gz-%s" % download_date.strftime("%Y%m%d-%H%M%S"))

                if meta_outname.exists():
                    print("metadata file %s already exists. Skipping entry." % meta_outname,
                          file=sys.stderr)

                # now store the Packages.gz file for future reference
                metadata = meta_outname.open(mode='wb')
                metadata.write(req.content)
                metadata.close()
                packages = Packages(meta_outname, arch)
                for p in packages.packages:
                    curdir, filename = p['filename'].rsplit('/', maxsplit=1)
                    download_queue.put((pathlib.Path(curdir), filename, p['size'], debian_dirs['binary_directory']))

        processes = []

        # create processes for unpacking archives
        for i in range(0, crawler_config.threads):
            process = multiprocessing.Process(target=downloadfile,
                                              args=(download_queue, fail_queue, repo.mirror))
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

if __name__ == "__main__":
    main()
