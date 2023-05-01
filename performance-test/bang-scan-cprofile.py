import cProfile, pstats
import click
import pathlib
import threading
import logging
from bang.meta_directory import *
from bang.scan_job import *
from bang.log import log
from bang.scan_environment import ScanEnvironment
import bang.signatures

def create_scan_environment_from_config(config):
    e = ScanEnvironment(
            unpackdirectory = '',
            temporarydirectory = '',
            scan_queue = None,
            )
    return e

def run_scan_loop(scan_environment):
    try:
        process_jobs(scan_environment)
    except queue.Empty:
        pass

class MockSemaphore:
    def __init__(self, queue, value):
        self.value = value
        self.queue = queue

    def acquire(self, blocking=False, timeout=0):
        return not self.queue.empty()

    def release(self):
        pass

def _scan_file(scan_file, temporary_directory, unpack_directory):
    scan_environment = create_scan_environment_from_config(None)
    scan_environment.temporarydirectory = temporary_directory.absolute()
    scan_environment.unpackdirectory = unpack_directory.absolute()
    scan_environment.scan_queue = queue.Queue(maxsize=0)
    scan_environment.scan_semaphore = MockSemaphore(scan_environment.scan_queue, 1)
    unpack_parsers = bang.signatures.get_unpackers()
    scan_environment.parsers.unpackparsers = unpack_parsers
    scan_environment.parsers.build_automaton()

    md = MetaDirectory(scan_environment.unpackdirectory, None, True)
    md.file_path = pathlib.Path(scan_file).absolute()

    j = ScanJob(md.md_path)
    scan_environment.scan_queue.put(j)
    process_jobs(scan_environment)



@click.command()
@click.option('-q', '--quiet', help='don\'t print statistics to standard output', is_flag=True)
@click.option('-v', '--verbose', help='enable debug logging', is_flag=True)
@click.option('-u', '--unpack-directory', type=click.Path(path_type=pathlib.Path), default=pathlib.Path('/tmp'))
@click.option('-t', '--temporary-directory', type=click.Path(path_type=pathlib.Path), default=pathlib.Path('/tmp'))
@click.option('-s', '--stats-file', help='stats file to write to or read from', type=click.Path(path_type=pathlib.Path))
@click.option('-f', '--scan-file', help='file to scan', type=click.Path(path_type=pathlib.Path))
def run(quiet, verbose, unpack_directory, temporary_directory, stats_file, scan_file):
    if verbose:
        log.setLevel(logging.DEBUG)
    if scan_file is not None:
        with cProfile.Profile() as pr:
            #pr.runctx('run_scan_loop(scan_environment)', globals(), locals())
            pr.runcall(_scan_file, scan_file, temporary_directory, unpack_directory)
        p = pstats.Stats(pr)
        if stats_file is not None:
            p.dump_stats(str(stats_file))
    elif stats_file is not None:
        p = pstats.Stats(str(stats_file))
    else:
        raise click.ClickException('Missing option: either specify -s, -f or both')

    if not quiet:
        p.sort_stats('cumulative')
        p.print_stats()
        p.print_callers()
        p.print_callees()

if __name__=="__main__":
    run()
