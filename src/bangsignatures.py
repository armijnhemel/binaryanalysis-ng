#!/usr/bin/env python3

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
# Copyright 2018-2021 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License
# version 3
# SPDX-License-Identifier: AGPL-3.0-only

import math

# store a few standard signatures
signatures = {
    'webp': b'WEBP',
    'wav': b'WAVE',
    'ani': b'ACON',
    'png': b'\x89PNG\x0d\x0a\x1a\x0a',
    'mng': b'\x8aMNG\x0d\x0a\x1a\x0a',
    'gzip': b'\x1f\x8b\x08',  # RFC 1952 says x08 is the only compression method allowed
    'bmp': b'BM',  # https://en.wikipedia.org/wiki/BMP_file_format
    'xz': b'\xfd\x37\x7a\x58\x5a\x00',
    'lzma_var1': b'\x5d\x00\x00',
    'lzma_var2': b'\x6d\x00\x00',  # used in OpenWrt
    'lzma_var3': b'\x6c\x00\x00',  # some routers, like ZyXEL NBG5615, use this
    'timezone': b'TZif',  # man 5 tzfile
    'tar_posix': b'ustar\x00',  # /usr/share/magic
    'tar_gnu': b'ustar\x20\x20\x00',  # /usr/share/magic
    'ar': b'!<arch>',
    'squashfs_var1': b'sqsh',
    'squashfs_var2': b'hsqs',
    'squashfs_var3': b'shsq',
    'squashfs_var4': b'qshs',
    'squashfs_var5': b'tqsh',
    'squashfs_var6': b'hsqt',
    'squashfs_var7': b'sqlz',
    'appledouble': b'\x00\x05\x16\x07',  # https://tools.ietf.org/html/rfc1740 Appendix B
    'icc': b'acsp',  # http://www.color.org/specification/ICC1v43_2010-12.pdf, section 7.2
    'zip': b'PK\x03\x04',  # https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT section 4.3.6
    'dahua': b'DH\x03\x04', # https://ipcamtalk.com/threads/dahua-ipc-easy-unbricking-recovery-over-tftp.17189/#post-288739
    'bzip2': b'BZh',  # https://en.wikipedia.org/wiki/Bzip2#File_format
    'xar': b'\x78\x61\x72\x21',  # https://github.com/mackyle/xar/wiki/xarformat
    'gif87': b'GIF87a',  # https://www.w3.org/Graphics/GIF/spec-gif89a.txt
    'gif89': b'GIF89a',  # https://www.w3.org/Graphics/GIF/spec-gif89a.txt
    'iso9660': b'CD001',  # ECMA 119
    'lzip': b'LZIP',  # http://www.nongnu.org/lzip/manual/lzip_manual.html#File-format
    'jpeg': b'\xff\xd8',
    'woff': b'wOFF',
    'opentype': b'OTTO',
    'ttc': b'ttcf',
    'truetype': b'\x00\x01\x00\x00',
    'android_backup': b'ANDROID BACKUP\n',
    'ico': b'\x00\x00\x01\x00',  # https://en.wikipedia.org/wiki/ICO_%28file_format%29
    'gnu_message_catalog_le': b'\xde\x12\x04\x95',  # /usr/share/magic
    'gnu_message_catalog_be': b'\x95\x04\x12\xde',  # /usr/share/magic
    'cab': b'MSCF\x00\x00\x00\x00',  # /usr/share/magic
    'sgi': b'\x01\xda',  # https://media.xiph.org/svt/SGIIMAGESPEC
    'aiff': b'FORM',
    'terminfo': b'\x1a\x01',
    'rzip': b'RZIP',  # /usr/share/magic
    'au': b'.snd',
    'jffs2_little_endian': b'\x85\x19',  # /usr/share/magic
    'jffs2_big_endian': b'\x19\x85',  # /usr/share/magic
    'cpio_old': b'\xc7\x71',  # man 5 cpio
    'cpio_portable': b'070707',  # man 5 cpio
    'cpio_newascii': b'070701',  # man 5 cpio
    'cpio_newcrc': b'070702',  # man 5 cpio
    '7z': b'7z\xbc\xaf\x27\x1c',  # documentation in 7-Zip source code
    'chm': b'ITSF\x03\x00\x00\x00',  # /usr/share/magic but only use a part and only support version 3
    'mswim': b'MSWIM\x00\x00\x00',  # /usr/share/magic
    'sunraster': b'\x59\xa6\x6a\x95',  # https://www.fileformat.info/format/sunraster/egff.htm
    'ext2': b'\x53\xef',  # /usr/share/magic
    'rpm': b'\xed\xab\xee\xdb',
    'zstd_08': b'\x28\xb5\x2f\xfd',  # /usr/share/magic
    'apple_icon': b'icns',  # https://en.wikipedia.org/wiki/Apple_Icon_Image_format
    'androidsparse': b'\x3a\xff\x26\xed',
    'lz4': b'\x04\x22\x4d\x18',  # https://github.com/lz4/lz4/blob/master/doc/lz4_Frame_format.md
    'lz4_legacy': b'\x02\x21\x4c\x18',  # https://github.com/lz4/lz4/blob/master/doc/lz4_Frame_format.md#legacy-frame
    'vmdk': b'KDMV',
    'qcow2': b'QFI\xfb',
    'vdi': b'<<< Oracle VM VirtualBox Disk Image >>>\n',
    'javaclass': b'\xca\xfe\xba\xbe',
    'dex': b'dex\n',
    'odex': b'dey\n',
    'snappy_framed': b'\xff\x06\x00\x00\x73\x4e\x61\x50\x70\x59',  # https://github.com/google/snappy/blob/master/framing_format.txt
    'elf': b'\x7f\x45\x4c\x46',
    'swf': b'FWS',
    'swf_zlib': b'CWS',
    'swf_lzma': b'ZWS',
    'ubootlegacy': b'\x27\x05\x19\x56',
    'certificate': b'-----BEGIN ',
    'git_index': b'DIRC',  # https://github.com/git/git/blob/master/Documentation/technical/index-format.txt
    'flv': b'FLV',
    'lzop': b'\x89\x4c\x5a\x4f\x00\x0d\x0a\x1a\x0a',
    'dlinkromfs': b'ROMFS v',
    'pdf': b'%PDF-',
    'gimpbrush': b'GIMP',
    'zim': b'\x5a\x49\x4d\x04',
    'pack200': b'\xca\xfe\xd0\x0d',
    'midi': b'MThd',
    'javakeystore': b'\xfe\xed\xfe\xed',
    'xg3d': b'XG3D',
    'acdb': b'QCMSNDDB',
    'dds': b'DDS ',
    'ktx11': b'\xabKTX 11\xbb\r\n\x1a\n',
    'avb': b'AVB0',
    'sqlite3': b'SQLite format 3\x00',
    'dtb': b'\xd0\x0d\xfe\xed',
    'trx': b'HDR0',
    'psd': b'8BPS',
    'minidump': b'MDMP',
    'ppm': b'P6',
    'pgm': b'P5',
    'pbm': b'P4',
    'androidbootmsm': b'BOOTLDR!',
    'androidbootimg': b'ANDROID!',
    'androidboothuawei': b'\x3c\xd6\x1a\xce',
    'fat': b'\x55\xaa',
    'cbfs': b'LARCHIVE', # https://www.coreboot.org/CBFS
    'minix_1l': b'\x8f\x13', # minix v1, linux variant
    'compress': b'\x1f\x9d', # /usr/share/magic
    'romfs': b'-rom1fs-',
    'cramfs_le': b'\x45\x3d\xcd\x28',
    'cramfs_be': b'\x28\xcd\x3d\x45',
    'quakepak': b'PACK',
    'doomwad': b'IWAD',
    'ambarella': b'\x90\xeb\x24\xa3',
    'romfs_ambarella': b'\x8a\x32\xfc\x66',
    'bflt': b'bFLT', # https://web.archive.org/web/20120123212024/http://retired.beyondlogic.org/uClinux/bflt.htm
    'ubi': b'UBI#', # http://www.dubeiko.com/development/FileSystems/UBI/ubidesign.pdf
    'ubifs': b'\x31\x18\x10\x06',
    'nar': b'\x0d\x00\x00\x00\x00\x00\x00\x00nix-archive-1\x00\x00\x00',
    'grub2font': b'FILE\x00\x00\x00\x04PFF2',
    'bittorrent': b'd8:announce',
    'pcapng': b'\x0a\x0d\x0d\x0a',
    'pcap_le': b'\xd4\xc3\xb2\xa1',
    'pcap_be': b'\xa1\xb2\xc3\xd4',
    'pcap_le_nano': b'\x4d\x3c\xb2\xa1',
    'pcap_be_nano': b'\xa1\xb2\x3c\x4d',
    'android_binary_xml': b'\x03\x00\x08\x00',
    'serialized_java': b'\xac\xed\x00\x05',
    'mapsforge': b'mapsforge binary OSM',
    'plf': b'PLF!',
    'pfs': b'PFS/0.9\x00',
    'yaffs_le_1': b'\x03\x00\x00\x00\x01\x00\x00\x00\xff\xff',
    'yaffs_le_2': b'\x01\x00\x00\x00\x01\x00\x00\x00\xff\xff',
    'yaffs_be_1': b'\x00\x00\x00\x03\x00\x00\x00\x01\xff\xff',
    'yaffs_be_2': b'\x00\x00\x00\x01\x00\x00\x00\x01\xff\xff',
    'qcdt': b'QCDT',
    'dhtb': b'DHTB\x01\x00\x00\x00',
    'crx': b'Cr24',
}

# some signatures do not start at the beginning of the file
signaturesoffset = {
    'wav': 8,
    'ani': 8,
    'tar_posix': 0x101,
    'tar_gnu': 0x101,
    'icc': 36,
    'iso9660': 32769,
    'ext2': 0x438,
    'dlinkromfs': 16,
    'gimpbrush': 20,
    'fat': 0x1fe,
    'minix_1l': 0x410,
    'ambarella': 0x818,
    'romfs_ambarella': 4,
}


# The result of the scan is a dictionary containing:
#
# * the status of the scan (successful or not)
#
# Successful scans also contain:
#
# * the length of the data
# * list of files that were unpacked, if any, plus
#   labels for the unpacked files
# * labels that were added, if any
#
# Unsucccesful scans contain:
#
# * errors that were encountered
#
# unpacking error contains:
#
# * offset in the file where the error occured
#   (integer)
# * error message (human readable)
# * flag to indicate if it is a fatal error
#   (boolean)
#


# keep a list of signatures to the (built in) functions
signaturetofunction = {
}

# a lookup table to map signatures to a name for
# pretty printing.
signatureprettyprint = {
    'lzma_var1': 'lzma',
    'lzma_var2': 'lzma',
    'lzma_var3': 'lzma',
    'tar_posix': 'tar',
    'tar_gnu': 'tar',
    'squashfs_var1': 'squashfs',
    'squashfs_var2': 'squashfs',
    'squashfs_var3': 'squashfs',
    'squashfs_var4': 'squashfs',
    'squashfs_var5': 'squashfs',
    'squashfs_var6': 'squashfs',
    'squashfs_var7': 'squashfs',
    'gif87': 'gif',
    'gif89': 'gif',
    'jffs2_little_endian': 'jffs2',
    'jffs2_big_endian': 'jffs2',
    'cpio_old': 'cpio',
    'cpio_portable': 'cpio',
    'cpio_newascii': 'cpio',
    'cpio_newcrc': 'cpio',
    'zstd_08': 'zstd',
    'swf_zlib': 'swf',
    'swf_lzma': 'swf',
    'ktx11': 'ktx',
    'minix_1l': 'minix',
    'cramfs_le': 'cramfs',
    'cramfs_be': 'cramfs',
    'pcap_le': 'pcap',
    'pcap_be': 'pcap',
    'pcap_le_nano': 'pcap',
    'pcap_be_nano': 'pcap',
    'android_binary_xml': 'androidresource',
    'yaffs_le_1': 'yaffs2',
    'yaffs_le_2':'yaffs2',
    'yaffs_be_1':'yaffs2',
    'yaffs_be_2':'yaffs2',
}

# extensions to unpacking functions. This should only be
# used for files with a known extension that cannot be
# reliably recognized any other way.
# One example is the Android sparse data format.
# These extensions should be lower case
extensiontofunction = {
}

import os
import pkgutil
import importlib
import inspect
import parsers
import pathlib
from UnpackParser import UnpackParser, WrappedUnpackParser

def _get_unpackers_recursive(unpackers_root, parent_module_path):
    unpackers = []
    abs_module_path = unpackers_root / parent_module_path
    for m in pkgutil.iter_modules([str(abs_module_path)]):
        full_module_path = parent_module_path / m.name
        if (unpackers_root / full_module_path).is_dir():
            try:
                full_module_name = ".".join(full_module_path.parts)
                module_name = 'parsers.{}.UnpackParser'.format(full_module_name)
                module = importlib.import_module(module_name)
                for name, member in inspect.getmembers(module):
                    if inspect.isclass(member) and issubclass(member, UnpackParser) \
                        and member != UnpackParser \
                        and member != WrappedUnpackParser:
                        unpackers.append(member)
            except ModuleNotFoundError as e:
                pass
            unpackers.extend(_get_unpackers_recursive(
                unpackers_root, full_module_path ))
    return unpackers


def get_unpackers():
    unpackers = _get_unpackers_recursive(
            pathlib.Path(os.path.dirname(parsers.__file__)), pathlib.Path('.'))
    return unpackers

def get_unpackers_for_extensions():
    d = {}
    for u in get_unpackers():
        for e in u.extensions:
            d.setdefault(e,[])
            d[e].append(u)
    return d

extension_to_unpackparser = get_unpackers_for_extensions()

def get_unpackers_for_signatures():
    d = {}
    for u in get_unpackers():
        for s in u.signatures:
            d.setdefault(s,[])
            d[s].append(u)
    return d

signature_to_unpackparser = get_unpackers_for_signatures()

def get_unpackers_for_featureless_files():
    return [u for u in get_unpackers() if u.scan_if_featureless ]

unpackers_for_featureless_files = get_unpackers_for_featureless_files()

# a lookup table to map extensions to a name
# for pretty printing.
extensionprettyprint = {
    '.swp': 'vimswapfile',
    '.new.dat': 'androidsparsedata',
    '.pak': 'pak',
    '.ihex': 'ihex',
    '.hex': 'ihex',
    '.srec': 'srec',
    '.xml': 'xml',
    '.xsd': 'xml',
    '.ncx': 'xml',
    '.opf': 'xml',
    '.svg': 'xml',
    '.tar': 'tar',
    'resources.arsc': 'androidresource',
    'manifest.mf': 'javamanifest',
    '.sf': 'javamanifest',
    '.dockerfile': 'dockerfile',
    'dockerfile': 'dockerfile',
    'pkg-info': 'pkginfo',
    'known_hosts': 'ssh_known_hosts',
    'ssh_known_hosts': 'ssh_known_hosts',
    '.rsa': 'certificate',
    '.pem': 'certificate',
    '.lsm': 'lsm',
    '.json': 'json',
    'passwd': 'passwd',
    'shadow': 'shadow',
    'group': 'group',
    '.css': 'css',
    'tzdata': 'tzdata',
    'fstab': 'fstab',
    '.pc': 'pc',
    '.ics': 'ics',
    'trans.tbl': 'trans.tbl',
    'smbpasswd': 'smbpasswd',
    '.ini': 'ini',
    'wcprops': 'subversion_hash',
}

def matches_file_pattern(filename, extension):
    return filename.name.lower().endswith(extension)

# certain unpacking functions if the whole file is text
textonlyfunctions = {}

# The result of the scan is a dictionary with the
# following data, depending on the status of the scan
# * the status of the scan (successful or not)
# * the length of the data
# * list of files that were unpacked, if any, plus
#   labels for the unpacked files
# * labels that were added, if any
# * errors that were encountered, if any
#
# The unpack errror returned has more information:
#
# * offset in the file where the error occured
#   (integer)
# * error message (human readable)
# * flag to indicate if it is a fatal error
#   (boolean)
def unpack_file_with_extension(fileresult, scanenvironment, unpackparser, unpack_directory):
    return unpackparser().parse_and_unpack(fileresult, scanenvironment, 0, unpack_directory)

# Prescan functions:
#
# first perform a few sanity checks to prevent
# false positives for the built in unpack
# functions in BANG, as function calls are
# expensive so prevent them as much as possible.
# For big files this can easily save hundreds of
# thousands of function calls.
#
# Included here are checks for:
#
# * LZMA
# * bzip2
# * gzip
# * BMP
# * SGI images
# * ICO
# * PNG
# * MNG
# * TrueType and OpenType fonts
# * terminfo

def prescan_true(scanbytes, bytesread, filesize, offset, offsetinfile):
    return True

def prescan_lzma(scanbytes, bytesread, filesize, offset, offsetinfile):
    # header of LZMA files is 13 bytes
    if filesize - (offset + offsetinfile) < 13:
        return False
    # Only do this if there are enough bytes
    # left to test on, otherwise let the sliding
    # window do its work
    if bytesread - offset >= 13:
        # bytes 5 - 13 are the size field. It
        # could be that it is undefined, but if
        # it is defined then check if it is too
        # large or too small.
        if scanbytes[offset+5:offset+13] != b'\xff\xff\xff\xff\xff\xff\xff\xff':
            lzmaunpackedsize = int.from_bytes(scanbytes[offset+5:offset+13], byteorder='little')
            if lzmaunpackedsize == 0:
                return False
            # XZ Utils cannot unpack or create
            # files with size of 256 GiB or more
            if lzmaunpackedsize > 274877906944:
                return False
    return True

def prescan_bzip2(scanbytes, bytesread, filesize, offset, offsetinfile):
    # first some sanity checks consisting of
    # header checks:
    #
    # * block size
    # * magic
    #
    # Only do this if there are enough bytes
    # left to test on, otherwise
    # let the sliding window do its work
    if bytesread - offset >= 10:
        # the byte indicating the block size
        # has to be in the range 1 - 9
        try:
            blocksize = int(scanbytes[offset+3])
        except:
            return False
        # block size byte cannot be 0
        if blocksize == 0:
            return False
        # then check if the file is a stream or
        # not. If so, some more checks can be
        # made (bzip2 source code decompress.c,
        # line 224).
        if scanbytes[offset+4] != b'\x17':
            if scanbytes[offset+4:offset+10] != b'\x31\x41\x59\x26\x53\x59':
                return False
    return True

def prescan_gzip(scanbytes, bytesread, filesize, offset, offsetinfile):
    # first some sanity checks consisting of
    # header checks.
    #
    # RFC 1952 http://www.zlib.org/rfc-gzip.html
    # describes the flags, but omits the
    # "encrytion" flag (bit 5)
    #
    # Python 3's zlib module does not support:
    # * continuation of multi-part gzip (bit 2)
    # * encrypt (bit 5)
    #
    # RFC 1952 says that bit 6 and 7 should not
    # be set.
    if bytesread - offset >= 4:
        gzipbyte = scanbytes[offset+3]
        if (gzipbyte >> 2 & 1) == 1:
            # continuation of multi-part gzip
            return False
        if (gzipbyte >> 5 & 1) == 1:
            # encrypted
            return False
        if (gzipbyte >> 6 & 1) == 1:
            # reserved
            return False
        if (gzipbyte >> 7 & 1) == 1:
            # reserved
            return False
    return True

def prescan_bmp(scanbytes, bytesread, filesize, offset, offsetinfile):
    # header of BMP files is 26 bytes
    if filesize - (offset + offsetinfile) < 26:
        return False
    if bytesread - offset >= 6:
        bmpsize = int.from_bytes(scanbytes[offset+2:offset+6], byteorder='little')
        if offsetinfile + offset + bmpsize > filesize:
            return False
    return True

def prescan_ico(scanbytes, bytesread, filesize, offset, offsetinfile):
    # check the number of images
    if filesize - (offset + offsetinfile) < 22:
        return False
    numberofimages = int.from_bytes(scanbytes[offset+4:offset+6], byteorder='little')
    if numberofimages == 0:
        return False

    # images cannot be outside of the file
    if offsetinfile + offset + 6 + numberofimages * 16 > filesize:
        return False

    # Then check the first image, as this
    # is where most false positives happen.
    imagesize = int.from_bytes(scanbytes[offset+14:offset+18], byteorder='little')
    if imagesize == 0:
        return False

    # ICO cannot be outside of the file
    imageoffset = int.from_bytes(scanbytes[offset+18:offset+22], byteorder='little')

    if offsetinfile + offset + imageoffset + imagesize > filesize:
        return False

    return True

def prescan_png(scanbytes, bytesread, filesize, offset, offsetinfile):
    # minimum size of PNG files is 57 bytes
    if filesize - (offsetinfile + offset) < 57:
        return False
    if bytesread - offset >= 13:
        # bytes 8 - 11 are always the same in
        # every PNG
        if scanbytes[offset+8:offset+12] != b'\x00\x00\x00\x0d':
            return False
    return True

def prescan_truetype(scanbytes, bytesread, filesize, offset, offsetinfile):
    if filesize - (offsetinfile + offset) < 12:
        return False
    # two simple sanity checks: number of
    # tables and search range
    numtables = int.from_bytes(scanbytes[offset+4:offset+6], byteorder='big')

    if numtables == 0:
        return False

    # then the search range
    searchrange = int.from_bytes(scanbytes[offset+6:offset+8], byteorder='big')
    if pow(2, int(math.log2(numtables)))*16 != searchrange:
        return False
    return True

def prescan_terminfo(scanbytes, bytesread, filesize, offset, offsetinfile):
    if filesize - (offsetinfile + offset) < 12:
        return False

    # simple sanity check: names section
    # size cannot be < 2 or > 128
    namessectionsize = int.from_bytes(scanbytes[offset+2:offset+4], byteorder='little')

    if namessectionsize < 2 or namessectionsize > 128:
        return False

    return True

prescan_functions = {
    'lzma_var1': prescan_lzma,
    'lzma_var2': prescan_lzma,
    'lzma_var3': prescan_lzma,
    'bzip2': prescan_bzip2,
    'gzip': prescan_gzip,
    'bmp' : prescan_bmp,
    'ico' : prescan_ico,
    'png' : prescan_png,
    'truetype' : prescan_truetype,
    'opentype' : prescan_truetype,
    'terminfo' : prescan_terminfo,
}

def prescan(s, scanbytes, bytesread, filesize, offset, offsetinfile):
    f = prescan_functions.get(s, prescan_true)
    return f(scanbytes, bytesread, filesize, offset, offsetinfile)

# store the maximum look ahead window. This is unlikely to matter, but
# just in case.
# maxsignaturelength = max(map(lambda x: len(x), signatures.values()))
maxsignaturelength = max([0] + [ len(x[1]) for x in signature_to_unpackparser.keys() ])
maxsignaturesoffset = max([0] + [ x[0] for x in signature_to_unpackparser.keys() ]) + maxsignaturelength

# maxsignaturesoffset = max(signaturesoffset.values()) + maxsignaturelength
