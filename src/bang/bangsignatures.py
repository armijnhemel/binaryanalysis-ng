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
# Copyright 2018-2019 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License
# version 3
# SPDX-License-Identifier: AGPL-3.0-only

import math

import bangandroid
import bangfilesystems
import bangmedia
import bangtext
import bangunpack

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
    'webp': 8,
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
    'webp': bangmedia.unpack_webp,
    'wav': bangmedia.unpack_wav,
    'ani': bangmedia.unpack_ani,
    'mng': bangmedia.unpack_mng,
    'gzip': bangunpack.unpack_gzip,
    'xz': bangunpack.unpack_xz,
    'lzma_var1': bangunpack.unpack_lzma,
    'lzma_var2': bangunpack.unpack_lzma,
    'lzma_var3': bangunpack.unpack_lzma,
    'tar_posix': bangunpack.unpack_tar,
    'tar_gnu': bangunpack.unpack_tar,
    'ar': bangunpack.unpack_ar,
    'squashfs_var1': bangfilesystems.unpack_squashfs,
    'squashfs_var2': bangfilesystems.unpack_squashfs,
    'squashfs_var3': bangfilesystems.unpack_squashfs,
    'squashfs_var4': bangfilesystems.unpack_squashfs,
    'squashfs_var5': bangfilesystems.unpack_squashfs,
    'squashfs_var6': bangfilesystems.unpack_squashfs,
    'squashfs_var7': bangfilesystems.unpack_squashfs,
    'icc': bangunpack.unpack_icc,
    'zip': bangunpack.unpack_zip,
    'dahua': bangunpack.unpack_dahua,
    'bzip2': bangunpack.unpack_bzip2,
    'xar': bangunpack.unpack_xar,
    'iso9660': bangfilesystems.unpack_iso9660,
    'lzip': bangunpack.unpack_lzip,
    'jpeg': bangmedia.unpack_jpeg,
    'woff': bangunpack.unpack_woff,
    'opentype': bangunpack.unpack_opentype_font,
    'ttc': bangunpack.unpack_opentype_font_collection,
    'truetype': bangunpack.unpack_truetype_font,
    'android_backup': bangandroid.unpack_android_backup,
    'cab': bangunpack.unpack_cab,
    'sgi': bangmedia.unpack_sgi,
    'aiff': bangmedia.unpack_aiff,
    'terminfo': bangunpack.unpack_terminfo,
    'rzip': bangunpack.unpack_rzip,
    'jffs2_little_endian': bangfilesystems.unpack_jffs2,
    'jffs2_big_endian': bangfilesystems.unpack_jffs2,
    '7z': bangunpack.unpack_7z,
    'chm': bangunpack.unpack_chm,
    'mswim': bangunpack.unpack_wim,
    'sunraster': bangmedia.unpack_sunraster,
    'ext2': bangfilesystems.unpack_ext2,
    'rpm': bangunpack.unpack_rpm,
    'zstd_08': bangunpack.unpack_zstd,
    'lz4': bangunpack.unpack_lz4,
    'lz4_legacy': bangunpack.unpack_lz4legacy,
    'vmdk': bangfilesystems.unpack_vmdk,
    'qcow2': bangfilesystems.unpack_qcow2,
    'vdi': bangfilesystems.unpack_vdi,
    'javaclass': bangunpack.unpack_java_class,
    'dex': bangandroid.unpack_dex,
    'odex': bangandroid.unpack_odex,
    'snappy_framed': bangunpack.unpack_snappy,
    'swf': bangmedia.unpack_swf,
    'swf_zlib': bangmedia.unpack_swf,
    'swf_lzma': bangmedia.unpack_swf,
    'certificate': bangunpack.unpack_certificate,
    'git_index': bangunpack.unpack_git_index,
    'flv': bangmedia.unpack_flv,
    'pdf': bangmedia.unpack_pdf,
    'pack200': bangunpack.unpack_pack200,
    'zim': bangunpack.unpack_zim,
    'javakeystore': bangunpack.unpack_java_keystore,
    'xg3d': bangmedia.unpack_xg3d,
    'acdb': bangunpack.unpack_acdb,
    'ktx11': bangmedia.unpack_ktx11,
    'avb': bangandroid.unpack_avb,
    'sqlite3': bangunpack.unpack_sqlite,
    'trx': bangunpack.unpack_trx,
    'psd': bangmedia.unpack_psd,
    'ppm': bangmedia.unpack_pnm,
    'pgm': bangmedia.unpack_pnm,
    'pbm': bangmedia.unpack_pnm,
    'androidbootimg': bangandroid.unpack_android_boot_img,
    'fat': bangfilesystems.unpack_fat,
    'cbfs': bangfilesystems.unpack_cbfs,
    'minix_1l': bangfilesystems.unpack_minix1l,
    'compress': bangunpack.unpack_compress,
    'romfs': bangfilesystems.unpack_romfs,
    'cramfs_le': bangfilesystems.unpack_cramfs,
    'cramfs_be': bangfilesystems.unpack_cramfs,
    'bflt': bangunpack.unpack_bflt,
    'ubi': bangfilesystems.unpack_ubi,
    'bittorrent': bangunpack.unpack_bittorrent,
    'pcapng': bangunpack.unpack_pcapng,
    'pcap_le': bangunpack.unpack_pcap,
    'pcap_be': bangunpack.unpack_pcap,
    'pcap_le_nano': bangunpack.unpack_pcap,
    'pcap_be_nano': bangunpack.unpack_pcap,
    'android_binary_xml': bangandroid.unpack_android_resource,
    'serialized_java': bangunpack.unpack_serialized_java,
    'mapsforge': bangmedia.unpack_mapsforge,
    'plf': bangfilesystems.unpack_plf,
    'pfs': bangfilesystems.unpack_pfs,
    'yaffs_le_1': bangfilesystems.unpack_yaffs2,
    'yaffs_le_2': bangfilesystems.unpack_yaffs2,
    'yaffs_be_1': bangfilesystems.unpack_yaffs2,
    'yaffs_be_2': bangfilesystems.unpack_yaffs2,
    #'dhtb': bangandroid.unpack_dhtb,
    'crx': bangunpack.unpack_crx,
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
    '.swp': bangunpack.unpack_vim_swapfile,
    '.new.dat': bangandroid.unpack_android_sparse_data,
    '.ihex': bangtext.unpack_ihex,
    '.hex': bangtext.unpack_ihex,
    '.srec': bangtext.unpack_srec,
    '.xml': bangunpack.unpack_xml,
    '.xsd': bangunpack.unpack_xml,
    '.ncx': bangunpack.unpack_xml,
    '.opf': bangunpack.unpack_xml,
    '.svg': bangunpack.unpack_xml,
    '.tar': bangunpack.unpack_tar,
    'resources.arsc': bangandroid.unpack_android_resource,
    '.rsa': bangunpack.unpack_certificate,
    '.pem': bangunpack.unpack_certificate,
    '.json': bangunpack.unpack_json,
    'tzdata': bangandroid.unpack_android_tzdata,
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
    for m in pkgutil.iter_modules([abs_module_path]):
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

def get_unpacker_by_pretty_name(name):
    l = [ u for u in get_unpackers() if u.pretty_name == name ]
    return l[0]

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
textonlyfunctions = {
    'ihex': bangtext.unpack_ihex,
    'srec': bangtext.unpack_srec,
    'base64': bangtext.unpack_base64,
}

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

def prescan_sgi(scanbytes, bytesread, filesize, offset, offsetinfile):
    # header of SGI files is 512 bytes
    if filesize - (offset + offsetinfile) < 512:
        return False
    if bytesread - offset > 512:
        # storage format
        if not (scanbytes[offset+2] == 0 or scanbytes[offset+2] == 1):
            return False
        # BPC
        if not (scanbytes[offset+3] == 1 or scanbytes[offset+3] == 2):
            return False
        # dummy values, last 404 bytes of
        # the header are 0x00
        if not scanbytes[offset+108:offset+512] == b'\x00' * 404:
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

def prescan_mng(scanbytes, bytesread, filesize, offset, offsetinfile):
    # minimum size of MNG files is 52 bytes
    if filesize - (offsetinfile + offset) < 52:
        return False
    if bytesread - offset >= 13:
        # bytes 8 - 11 are always the same in
        # every MNG
        if scanbytes[offset+8:offset+12] != b'\x00\x00\x00\x1c':
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
    'sgi' : prescan_sgi,
    'ico' : prescan_ico,
    'png' : prescan_png,
    'mng' : prescan_mng,
    'truetype' : prescan_truetype,
    'opentype' : prescan_truetype,
    'terminfo' : prescan_terminfo,
}

def prescan(s, scanbytes, bytesread, filesize, offset, offsetinfile):
    f = prescan_functions.get(s, prescan_true)
    return f(scanbytes, bytesread, filesize, offset, offsetinfile)

# license references extracted from a Fedora 28 system:
# $ cd /usr/share/doc
# $ grep -r license | grep http
#
# Keys are SPDX compatible as far as possible. Included are
# references for both software and data. http://, https://,
# www are removed, as are some extensions to avoid duplication.
# Some of these URLs are no longer valid, or redirect to other
# pages, but are still used in code.
licensereferences = {}

# generic license reference
licensereferences['license'] = ["license", "License", "LICENSE", "licensing",
                                "licence", "Licence", "LICENCE", "licencing"]

# GNU (licenses, URLs, e-mail)
licensereferences['GNU'] = ["gnu.org/licenses/", "gnu.org/gethelp/",
                            "gnu.org/software/", "@gnu.org"]

# GNU GPL license family
licensereferences['GPL family'] = ["General Public License"]

# GNU GPL
licensereferences['GPL'] = ["gnu.org/licenses/gpl."
                            "gnu.org/copyleft/gpl."
                            "gnu.org/copyleft/gpl.",
                            "www.opensource.org/licenses/gpl-license.php",
                            "www.fsf.org/copyleft/gpl.html"]
licensereferences['GPL-2.0'] = ["gnu.org/licenses/gpl-2.0.",
                                "gnu.org/licenses/old-licenses/gpl-2.0",
                                "creativecommons.org/licenses/GPL/2.0/",
                                "opensource.org/licenses/GPL-2.0"]
licensereferences['GPL-3.0'] = ["opensource.org/licenses/gpl-3.0."]

# GNU LGPL
licensereferences['LGPL'] = ["www.fsf.org/copyleft/lesser.html",
                             "www.fsf.org/licenses/lgpl.html",
                             "gnu.org/licenses/lgpl.html",
                             "opensource.org/licenses/lgpl-license"]
licensereferences['LGPL-2.0'] = ["gnu.org/licenses/old-licenses/lgpl-2.0"]
licensereferences['LGPL-2.1'] = ["gnu.org/licenses/old-licenses/lgpl-2.1",
                                 "creativecommons.org/licenses/LGPL/2.1/",
                                 "opensource.org/licenses/LGPL-2.1"]
licensereferences['LGPL-3.0'] = ["opensource.org/licenses/lgpl-3.0."]

# GNU FDL
licensereferences['GFDL'] = ["gnu.org/copyleft/fdl.html",
                             "www.fsf.org/licensing/licenses/fdl.html"]
licensereferences['GFDL-1.3'] = ["gnu.org/licenses/fdl-1.3.html"]

# SISSL
licensereferences['SISSL'] = ["www.openoffice.org/licenses/sissl_license.html"]

# Apache licenses
licensereferences['Apache'] = ["apache.org/licenses/"]
licensereferences['Apache-1.1'] = ["apache.org/licenses/LICENSE-1.1",
                                   "opensource.org/licenses/Apache-1.1"]
licensereferences['Apache-2.0'] = ["apache.org/licenses/LICENSE-2.0",
                                   "opensource.org/licenses/apache2.0.php"]

# Creative Commons
licensereferences['CC-SA-1.0'] = ["creativecommons.org/licenses/sa/1.0"]
licensereferences['CC-BY-2.0'] = ["creativecommons.org/licenses/by/2.0/"]
licensereferences['CC-BY-SA-2.0'] = ["creativecommons.org/licenses/by-sa/2.0/"]
licensereferences['CC-BY-SA-2.5'] = ["creativecommons.org/licenses/by-sa/2.5/"]
licensereferences['CC-BY-SA-3.0'] = ["creativecommons.org/licenses/by-sa/3.0/"]
licensereferences['CC-BY-3.0'] = ["creativecommons.org/licenses/by/3.0/"]
licensereferences['CC-BY-4.0'] = ["creativecommons.org/licenses/by/4.0/"]
licensereferences['CC-BY-SA-4.0'] = ["creativecommons.org/licenses/by-sa/4.0/"]

# Unlicense
licensereferences['Unlicense'] = ["unlicense.org"]

# ODbL
licensereferences['ODbL'] = ["opendatacommons.org/licenses/odbl/"]

# LaTeX
licensereferences['LaTeX'] = ["latex-project.org/lppl.txt"]

# ImageMagick
licensereferences['ImageMagick'] = ["www.imagemagick.org/script/license.php"]

# Open LDAP
licensereferences['OLDAP'] = ["www.OpenLDAP.org/license.html"]

# infozip
licensereferences['infozip'] = ["www.info-zip.org/pub/infozip/license.html"]

# Perl
licensereferences['Perl'] = ["dev.perl.org/licenses/"]

# SIL Open Font License
licensereferences['OFL'] = ["scripts.sil.org/OFL"]

# font awesome
licensereferences['fontawesome'] = ["fontawesome.io/license"]

# GUST font license
licensereferences["gust font license"] = ["www.gust.org.pl/fonts/licenses/GUST-FONT-LICENSE.txt"]

# MTX licensing
licensereferences['MTX'] = ["www.monotype.com/legal/mtx-licensing-statement/",
                            "monotypeimaging.com/aboutus/mtx-license.aspx"]

# MPL licenses
licensereferences['MPL'] = ["mozilla.org/MPL"]
licensereferences['MPL-1.0'] = ["opensource.org/licenses/MPL-1.0",
                                "opensource.org/licenses/mozilla1.0.php"]
licensereferences['MPL-1.1'] = ["mozilla.org/MPL/MPL-1.1.html",
                                "opensource.org/licenses/MPL-1.1",
                                "opensource.org/licenses/mozilla1.1.php"]
licensereferences['MPL-2.0'] = ["mozilla.org/MPL/2.0/"]

# MIT license
licensereferences['MIT'] = ["opensource.org/licenses/mit-license",
                            "opensource.org/licenses/MIT"]

# lodash
licensereferences['lodash'] = ["lodash.com/license"]

# ncurses
licensereferences['ncurses'] = ["invisible-island.net/ncurses/ncurses-license.html"]

# BSD licenses
licensereferences['BSD'] = ["opensource.org/licenses/bsd-license",
                            "creativecommons.org/licenses/BSD/"]
licensereferences['BSD-2-Clause'] = ["nmap.org/svn/docs/licenses/BSD-simplified"]
licensereferences['BSD-3-Clause'] = ["opensource.org/licenses/BSD-3-Clause"]

# FreeBSD
licensereferences['freebsd'] = ['www.freebsd.org/copyright/freebsd-license.html']

# Artistic
licensereferences['Artistic'] = ["opensource.org/licenses/artistic-license.php"]
licensereferences['Artistic-1.0'] = ["opensource.org/licenses/Artistic-1.0",
                                     "opensource.org/licenses/Artistic-Perl-1.0",
                                     "www.perlfoundation.org/artistic_license_1_0"]
licensereferences['Artistic-2.0'] = ["www.perlfoundation.org/artistic_license_2_0",
                                     "opensource.org/licenses/artistic-license-2.0.php"]

# OpenSSL
licensereferences['openssl'] = ["www.openssl.org/source/license.html"]

# WTFPL
licensereferences['WTFPL'] = ['sam.zoy.org/wtfpl/']

# OpenOffice
licensereferences['OpenOffice'] = ["www.openoffice.org/license.html"]

# BitTorrent
licensereferences['BitTorrent'] = ["www.bittorrent.com/license/"]

# Tizen
licensereferences['Tizen'] = ["www.tizenopensource.org/license"]

# OpenSSL
licensereferences['OpenSSL'] = ["www.openssl.org/source/license.html"]

# Boost
licensereferences['BSL-1.0'] = ["www.boost.org/LICENSE_1_0.txt",
                                "pocoproject.org/license.html"]

# zlib
licensereferences['Zlib'] = ["www.zlib.net/zlib_license.html"]

# jQuery
licensereferences['jQuery'] = ["jquery.org/license"]

# libxml
licensereferences['libxml'] = ["xmlsoft.org/FAQ.html#License"]

# ICU
licensereferences['ICU'] = ["source.icu-project.org/repos/icu/icu/trunk/license.html",
                            "source.icu-project.org/repos/icu/trunk/icu4c/LICENSE"]

# Yui3
licensereferences['yui'] = ["developer.yahoo.com/yui/license.html"]

# Lua
licensereferences['lua'] = ["www.lua.org/license.html"]

# IETF
licensereferences['IETF'] = ["trustee.ietf.org/license-info/"]

# libstemmer
licensereferences['libstemmer'] = ["snowball.tartarus.org/license.php"]

# espeak
licensereferences['espeak'] = ["espeak.sf.net/license.html"]

# webm
licensereferences['webm'] = ["www.webmproject.org/license/software/"]

# firebird sql
licensereferences['firebird'] = ["firebirdsql.org/en/licensing/"]

# W3
licensereferences['W3'] = ["www.w3.org/Consortium/Legal/copyright-software-19980720"]

# PLOS
licensereferences['PLOS'] = ["www.ploscompbiol.org/static/license"]

# forge references extracted from various sources Wikipedia:
#
# https://en.wikipedia.org/wiki/Forge_(software)
#
# and quite a few from Fedora 28:
#
# $ cd /usr/share/doc
# $ grep -r git  | grep http
forgereferences = {}
forgereferences['GitHub'] = ["github.com", "github.io",
                             "raw.githubusercontent.com"]
forgereferences['GitLab'] = ["gitlab.com", "gitlab.io"]
forgereferences['Gitorious'] = ["gitorious.org"]
forgereferences['Bitbucket'] = ["bitbucket.org"]
forgereferences['SourceForge'] = ["sourceforge.net"]
forgereferences['GNOME'] = ["git.gnome.org", "gitlab.gnome.org"]
forgereferences['Perl'] = ["git.perl.org"]
forgereferences['Fedora'] = ["git.fedorahosted.org",
                             "src.fedoraproject.org/cgit/",
                             "pkgs.fedoraproject.org/cgit/"]
forgereferences['Debian'] = ["git.debian.org", "anonscm.debian.org"]
forgereferences['LibreOffice'] = ["gerrit.libreoffice.org"]
forgereferences['kernel.org'] = ["git.kernel.org"]
forgereferences['freedesktop.org'] = ["cvs.freedesktop.org",
                                      "git.freedesktop.org"]
forgereferences['Google Code'] = ["code.google.com", "googlecode.com"]
forgereferences['savannah.gnu.org'] = ["savannah.gnu.org", "git.sv.gnu.org"]
forgereferences['bitbucket.org'] = ["bitbucket.org"]
forgereferences['tigris.org'] = ["tigris.org"]
forgereferences['svn.apache.org'] = ["svn.apache.org"]
forgereferences['launchpad.net'] = ["git.launchpad.net", "launchpad.net"]
forgereferences['sourceware.org'] = ["sourceware.org/git/"]

# store the maximum look ahead window. This is unlikely to matter, but
# just in case.
# maxsignaturelength = max(map(lambda x: len(x), signatures.values()))
maxsignaturelength = max([0] + [ len(x[1]) for x in signature_to_unpackparser.keys() ])
maxsignaturesoffset = max([0] + [ x[0] for x in signature_to_unpackparser.keys() ]) + maxsignaturelength

# maxsignaturesoffset = max(signaturesoffset.values()) + maxsignaturelength
