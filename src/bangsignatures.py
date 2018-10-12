#!/usr/bin/python3

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
# Copyright 2018 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License
# version 3
# SPDX-License-Identifier: AGPL-3.0-only

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
    'appledouble': b'\x00\x05\x16\x07',  # https://tools.ietf.org/html/rfc1740 Appendix B
    'icc': b'acsp',  # http://www.color.org/specification/ICC1v43_2010-12.pdf, section 7.2
    'zip': b'\x50\x4b\x03\04',  # https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT section 4.3.6
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
}

# keep a list of signatures to the (built in) functions
signaturetofunction = {
    'webp': bangunpack.unpackWebP,
    'wav': bangunpack.unpackWAV,
    'ani': bangunpack.unpackANI,
    'png': bangunpack.unpackPNG,
    'mng': bangunpack.unpackMNG,
    'gzip': bangunpack.unpackGzip,
    'bmp': bangunpack.unpackBMP,
    'xz': bangunpack.unpackXZ,
    'lzma_var1': bangunpack.unpackLZMA,
    'lzma_var2': bangunpack.unpackLZMA,
    'lzma_var3': bangunpack.unpackLZMA,
    'timezone': bangunpack.unpackTimeZone,
    'tar_posix': bangunpack.unpackTar,
    'tar_gnu': bangunpack.unpackTar,
    'ar': bangunpack.unpackAr,
    'squashfs_var1': bangunpack.unpackSquashfs,
    'squashfs_var2': bangunpack.unpackSquashfs,
    'appledouble': bangunpack.unpackAppleDouble,
    'icc': bangunpack.unpackICC,
    'zip': bangunpack.unpackZip,
    'bzip2': bangunpack.unpackBzip2,
    'xar': bangunpack.unpackXAR,
    'gif87': bangunpack.unpackGIF,
    'gif89': bangunpack.unpackGIF,
    'iso9660': bangunpack.unpackISO9660,
    'lzip': bangunpack.unpackLzip,
    'jpeg': bangunpack.unpackJPEG,
    'woff': bangunpack.unpackWOFF,
    'opentype': bangunpack.unpackOpenTypeFont,
    'ttc': bangunpack.unpackOpenTypeFontCollection,
    'truetype': bangunpack.unpackTrueTypeFont,
    'android_backup': bangunpack.unpackAndroidBackup,
    'ico': bangunpack.unpackICO,
    'gnu_message_catalog_le': bangunpack.unpackGNUMessageCatalog,
    'gnu_message_catalog_be': bangunpack.unpackGNUMessageCatalog,
    'cab': bangunpack.unpackCab,
    'sgi': bangunpack.unpackSGI,
    'aiff': bangunpack.unpackAIFF,
    'terminfo': bangunpack.unpackTerminfo,
    'rzip': bangunpack.unpackRzip,
    'au': bangunpack.unpackAU,
    'jffs2_little_endian': bangunpack.unpackJFFS2,
    'jffs2_big_endian': bangunpack.unpackJFFS2,
    'cpio_old': bangunpack.unpackCpio,
    'cpio_portable': bangunpack.unpackCpio,
    'cpio_newascii': bangunpack.unpackCpio,
    'cpio_newcrc': bangunpack.unpackCpio,
    '7z': bangunpack.unpack7z,
    'chm': bangunpack.unpackCHM,
    'mswim': bangunpack.unpackWIM,
    'sunraster': bangunpack.unpackSunRaster,
    'ext2': bangunpack.unpackExt2,
    'rpm': bangunpack.unpackRPM,
    'zstd_08': bangunpack.unpackZstd,
    'apple_icon': bangunpack.unpackAppleIcon,
    'androidsparse': bangunpack.unpackAndroidSparse,
    'lz4': bangunpack.unpackLZ4,
    'vmdk': bangunpack.unpackVMDK,
    'qcow2': bangunpack.unpackQcow2,
    'vdi': bangunpack.unpackVDI,
    'javaclass': bangunpack.unpackJavaClass,
    'dex': bangunpack.unpackDex,
    'odex': bangunpack.unpackOdex,
    'snappy_framed': bangunpack.unpackSnappy,
    'elf': bangunpack.unpackELF,
    'swf': bangunpack.unpackSWF,
    'swf_zlib': bangunpack.unpackSWF,
    'swf_lzma': bangunpack.unpackSWF,
    'ubootlegacy': bangunpack.unpackUBootLegacy,
    'certificate': bangunpack.unpackCertificate,
    'git_index': bangunpack.unpackGitIndex,
    'flv': bangunpack.unpackFLV,
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
}

# extensions to unpacking functions. This should only be
# used for files with a known extension that cannot be
# reliably recognized any other way.
# One example is the Android sparse data format.
# These extensions should be lower case
extensiontofunction = {
    '.swp': bangunpack.unpackVimSwapfile,
    '.new.dat': bangunpack.unpackAndroidSparseData,
    '.pak': bangunpack.unpackChromePak,
    '.ihex': bangunpack.unpackIHex,
    '.hex': bangunpack.unpackIHex,
    '.srec': bangunpack.unpackSREC,
    '.xml': bangunpack.unpackXML,
    '.tar': bangunpack.unpackTar,
    'resources.arsc': bangunpack.unpackAndroidResource,
    'manifest.mf': bangunpack.unpackJavaManifest,
    '.sf': bangunpack.unpackJavaManifest,
    'dockerfile': bangunpack.unpackDockerfile,
    '.dockerfile': bangunpack.unpackDockerfile,
    'pkg-info': bangunpack.unpackPythonPkgInfo,
    'known_hosts': bangunpack.unpackSSHKnownHosts,
    'ssh_known_hosts': bangunpack.unpackSSHKnownHosts,
    '.rsa': bangunpack.unpackCertificate,
    '.pem': bangunpack.unpackCertificate,
    '.lsm': bangunpack.unpackLSM,
}

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
}

# certain unpacking functions if the whole file is text
textonlyfunctions = {
    'ihex': bangunpack.unpackIHex,
    'srec': bangunpack.unpackSREC,
    'css': bangunpack.unpackCSS,
    'kernelconfig': bangunpack.unpackKernelConfig,
    #'dockerfile': bangunpack.unpackDockerfile,
    'base64': bangunpack.unpackBase64,
}

# a lookup table to map various extensions to file types
extensiontofiletype = {
    '.py': ['Python source code'],
    '.pyc': ['Python compiled code'],
    '.pl': ['Perl source code'],
    '.pm': ['Perl module'],
    '.sh': ['shell script'],
}
