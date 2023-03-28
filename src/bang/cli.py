#!/usr/bin/env python3

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
# Licensed under the terms of the GNU Affero General Public License
# version 3
# SPDX-License-Identifier: AGPL-3.0-only

import datetime
import logging
import multiprocessing
import pathlib
import pprint
import sys
import time

import click

from .scan_environment import *
from .scan_job import ScanJob, process_jobs, make_scan_pipeline
from .meta_directory import MetaDirectory, MetaDirectoryException
from . import signatures
from .log import log

BANG_VERSION = "0.0.1"

def create_scan_environment_from_config(config):
    e = ScanEnvironment(
            unpack_directory = '',
            scan_queue = None,
            )
    return e


@click.group()
def app():
    pass


# bang scan <input file>
@app.command(short_help='Scan a file')
@click.option('-c', '--config')
@click.option('-v', '--verbose', is_flag=True, help='Enable debug logging')
@click.option('-u', '--unpack-directory', type=click.Path(path_type=pathlib.Path), default=pathlib.Path('/tmp'), help='Directory to unpack to')
@click.option('-t', '--temporary-directory', type=click.Path(path_type=pathlib.Path, exists=True), default=pathlib.Path('/tmp'), help='Temporary directory')
@click.option('-j', '--jobs', default=1, type=int, help='Number of jobs running simultaneously')
@click.option('--job-wait-time', default=10, type=int, help='Time to wait for a new job')
@click.argument('path', type=click.Path(exists=True))
def scan(config, verbose, unpack_directory, temporary_directory, jobs, job_wait_time, path):
    '''Scans PATH and unpacks its files to UNPACK_DIRECTORY.
    '''

    # record the starting time of the scan
    start_time = datetime.datetime.utcnow()

    # set up the environment
    scan_environment = create_scan_environment_from_config(config)
    scan_environment.job_wait_time = job_wait_time
    scan_environment.configuration.temporary_directory = temporary_directory.absolute()
    scan_environment.unpack_directory = unpack_directory.absolute()

    if verbose:
        log.setLevel(logging.DEBUG)

    log.info(f'cli:scan: BANG version {BANG_VERSION}')
    log.info(f'cli:scan: start [{time.time_ns()}]')

    # set the unpack_parsers
    # TODO: use config to enable/disable parsers
    #log.debug(f' finding unpack_parsers ')
    unpack_parsers = signatures.get_unpackers()
    scan_environment.parsers.unpackparsers = unpack_parsers
    #log.debug(f'{unpack_parsers =}')
    scan_environment.parsers.build_automaton()

    # set up the process manager and initialize the semaphore
    # with the value of the amount of jobs: this is the maximum
    # amount of jobs that will be able to run concurrently.
    process_manager = multiprocessing.Manager()
    scan_environment.scan_semaphore = process_manager.Semaphore(jobs)

    # create a queue
    scan_queue = process_manager.Queue(maxsize=0)
    scan_environment.scan_queue = scan_queue

    # create a scan pipeline for parsing and unpacking files
    scan_pipeline = make_scan_pipeline()

    # create $jobs processes
    processes = [ multiprocessing.Process(target = process_jobs, args = (scan_pipeline, scan_environment,)) for i in range(jobs)]

    # first create a meta directory for the file
    md = MetaDirectory(scan_environment.unpack_directory, None, True)
    md.file_path = pathlib.Path(path).absolute()
    log.debug(f'cli:scan[{md.md_path}]: queued job [{time.time_ns()}]')

    # create a scanjob using the created meta directory
    j = ScanJob(md.md_path)

    # queue the scanjob
    scan_queue.put(j)

    # start processes
    log.debug(f'cli:scan: starting processes...')
    for p in processes: p.start()

    log.debug(f'cli:scan: waiting for all processes to finish...')
    for p in processes: p.join()
    log.debug(f'cli:scan: all processes in queue finished')

    log.debug(f'cli:scan: terminating processes...')
    for p in processes:
        p.terminate()
    log.debug(f'cli:scan: done.')

    stop_time = datetime.datetime.utcnow()


@app.command(short_help='Show bang scan results')
@click.option('-a', '--all', is_flag=True, help='Show all information, including extracted/unpacked files')
@click.argument('metadir', type=click.Path(path_type=pathlib.Path))
def show(all, metadir):
    '''Shows bang scan results stored in METADIR.
    '''
    md = MetaDirectory.from_md_path(metadir.parent, metadir.name)
    try:
        print(f'{md.md_path} ({md.file_path}):')
    except MetaDirectoryException:
        print(f'directory {metadir} not found, exiting')
        sys.exit(1)

    with md.open(open_file=False, info_write=False):
        print(f'Parser: {md.info.get("unpack_parser")}')
        print(f'Labels: {", ".join(md.info.get("labels",[]))}')
        print(f'Size: {md.size}')
        print(f'Metadata:')
        pprint.pprint(md.info.get('metadata'))
        if all:
            for k,v in sorted(md.info.get('extracted_files', {}).items()):
                child_md = MetaDirectory.from_md_path(metadir.parent, v)
                with child_md.open(open_file=False, info_write=False):
                    labels = ", ".join(child_md.info.get("labels", []))
                    print(f'{k}\t{v}\t{labels}')
            for k,v in sorted(md.info.get('unpacked_absolute_files', {}).items()):
                child_md = MetaDirectory.from_md_path(metadir.parent, v)
                with child_md.open(open_file=False, info_write=False):
                    labels = ", ".join(child_md.info.get("labels", []))
                    print(f'{k}\t{v}\t{labels}')
            for k,v in sorted(md.info.get('unpacked_relative_files', {}).items()):
                child_md = MetaDirectory.from_md_path(metadir.parent, v)
                with child_md.open(open_file=False, info_write=False):
                    labels = ", ".join(child_md.info.get("labels", []))
                    print(f'{k}\t{v}\t{labels}')
            for k,v in sorted(md.info.get('unpacked_symlinks', {}).items()):
                print(f'{k}\t{v}\t(symlink)')
            for k,v in sorted(md.info.get('unpacked_hardlinks', {}).items()):
                print(f'{k}\t{v}\t(hardlink)')


@app.command(short_help='Lists extracted and unpacked files')
@click.argument('metadir', type=click.Path(path_type=pathlib.Path))
def ls(metadir):
    '''Lists extracted and unpacked files stored in METADIR.
    '''
    md = MetaDirectory.from_md_path(metadir.parent, metadir.name)
    with md.open(open_file=False, info_write=False):
        for k,v in sorted(md.info.get('extracted_files', {}).items()):
            child_md = md = MetaDirectory.from_md_path(metadir.parent, v)
            with child_md.open(open_file=False, info_write=False):
                labels = ", ".join(child_md.info.get("labels", []))
                print(f'{k}\t{v}\t{labels}')
        for k,v in sorted(md.info.get('unpacked_absolute_files', {}).items()):
            child_md = md = MetaDirectory.from_md_path(metadir.parent, v)
            with child_md.open(open_file=False, info_write=False):
                labels = ", ".join(child_md.info.get("labels", []))
                print(f'{k}\t{v}\t{labels}')
        for k,v in sorted(md.info.get('unpacked_relative_files', {}).items()):
            child_md = md = MetaDirectory.from_md_path(metadir.parent, v)
            with child_md.open(open_file=False, info_write=False):
                labels = ", ".join(child_md.info.get("labels", []))
                print(f'{k}\t{v}\t{labels}')
        for k,v in sorted(md.info.get('unpacked_symlinks', {}).items()):
            print(f'{k}\t{v}\t(symlink)')
        for k,v in sorted(md.info.get('unpacked_hardlinks', {}).items()):
            print(f'{k}\t{v}\t(hardlink)')


if __name__=="__main__":
    app()
