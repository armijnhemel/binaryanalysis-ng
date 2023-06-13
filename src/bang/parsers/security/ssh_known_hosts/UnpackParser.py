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
# Copyright Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License
# version 3
# SPDX-License-Identifier: AGPL-3.0-only

# SSH known host files
# format is described in sshd man page
# man 8 sshd

import base64

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException


class SshKnownHostsUnpackParser(UnpackParser):
    extensions = ['ssh_known_hosts', 'known_hosts']
    signatures = [
    ]
    pretty_name = 'ssh_known_hosts'

    # valid key types, probably incomplete
    # $ ssh -Q key-sig
    key_types = ["ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
                 "ecdsa-sha2-nistp521", "ssh-ed25519", "ssh-dss",
                 "ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"]

    def parse(self):
        # open the file again, but then in text mode
        try:
            ssh_file = open(self.infile.name, 'r', newline='')
        except Exception as e:
            ssh_file.close()
            raise UnpackParserException(e.args)

        data_unpacked = False
        len_unpacked = 0
        try:
            for ssh_line in ssh_file:
                line = ssh_line.rstrip()

                # comment
                if line.startswith('#'):
                    len_unpacked += len(ssh_line)
                    continue

                # empty line
                if line == '':
                    len_unpacked += len(ssh_line)
                    continue

                # split the line on spaces
                ssh_known_hosts_parts = line.split(' ')

                index = 0

                # then first look at cert-authority or revoked entries
                # this is an optional field
                if ssh_known_hosts_parts[0].startswith('@'):
                    if ssh_known_hosts_parts[0] not in ['@cert-authority', '@revoked']:
                        raise UnpackParserException("invalid @ in line")
                    index += 1

                # there have to be at least three other fields
                check_condition(len(ssh_known_hosts_parts) - index >= 3,
                                "not enough fields")

                # hostnames is the first regular field
                # TODO: more checks
                hostnames = ssh_known_hosts_parts[index].split(',')

                # then the key type
                key_type = ssh_known_hosts_parts[index+1]
                check_condition(key_type in self.key_types, "invalid key")

                # then the key, base64 encoded
                ssh_key = base64.standard_b64decode(ssh_known_hosts_parts[index+2])

                len_unpacked += len(ssh_line)
                data_unpacked = True
        except Exception as e:
            raise UnpackParserException(e.args)
        finally:
            ssh_file.close()

        check_condition(data_unpacked, "no SSH known host data could be unpacked")
        self.unpacked_size = len_unpacked

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    labels = ['ssh_known_hosts']
    metadata = {}
