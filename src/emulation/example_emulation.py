#!/usr/bin/env python3

import os
import pathlib

import click
import qiling
import qiling.const
from qiling.os.posix.syscall.stat import ql_syscall_fstat64


@click.command(short_help='run code in Qiling')
#@click.option('--config', '-c', required=True, help='path to configuration file', type=click.File('r'))
@click.option('--result-directory', '-r', 'rootfs', required=True, help='path to root file system', type=click.Path(exists=True))
#def main(config, result_directory):
def main(rootfs):
    rootfs = pathlib.Path(rootfs)

    # ... and should be a real directory
    if not rootfs.is_dir():
        print("%s is not a directory, exiting." % rootfs, file=sys.stderr)
        sys.exit(1)

    args = str(rootfs / 'bin/busybox')

    #binary = [str(rootfs / 'bin/ls'), r'-l', '/']
    binary = [str(rootfs / 'bin/ls'), r'-li', r'/bin/ls']
    binary = [str(rootfs / 'bin/ls'), r'-i', r'/tmp']
    print(binary)
    #binary = [str(rootfs / 'bin/echo'), r'*']
    #binary = [str(rootfs / 'bin/echo'), r'--help']
    #binary = [str(rootfs / 'bin/busybox'), '/']

    # just assume it contains code
    #ql = qiling.Qiling(binary, str(rootfs), verbose=qiling.const.QL_VERBOSE.OFF, multithread=True)
    ql = qiling.Qiling(binary, str(rootfs), multithread=True)
    #ql.add_fs_mapper('/proc', '/proc')
    #ql.add_fs_mapper('/dev', '/dev')
    #ql.add_fs_mapper('/sys', '/sys')
    ql.run()
    #print(ql.__dict__)


if __name__ == "__main__":
    main()
