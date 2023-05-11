#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright 2022 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License version 3
# SPDX-License-Identifier: AGPL-3.0-only

'''
A simple connector class for VulnerableCode
'''

import requests
import urllib.parse

import packageurl


class VulnerableCodeException(Exception):
    pass


class VulnerableCodeConnector():
    '''Connector class for VulnerableCode'''
    def __init__(self, env):
        '''Sanity check the environment and set up a session for queries'''
        # store the environment after sanity checking
        try:
            self.check_configuration(env)
            self.env = env
        except VulnerableCodeException as e:
            raise e
        self.session = requests.Session()

    def query(self, purl):
        '''Query a package URL string, verify and look up'''
        # verify that the version is a valid package url. If
        # not return
        try:
            query_purl = packageurl.PackageURL.from_string(purl)
        except ValueError as e:
            raise VulnerableCodeException(e.args)

        connection_string = "%s/packages/?purl=%s" % ( self.env['url'], purl)

        # query VulnerableCode instance
        try:
            req = self.session.get(connection_string, auth=(self.env.get('user', None), self.env.get('password', None)))
            return req.json()
        except requests.exceptions.RequestException as e:
            raise VulnerableCodeException(e.args)

    def check_configuration(self, env):
        '''Verify the configuration'''
        if not 'url' in env:
            raise VulnerableCodeException('No url configured')

        # check if the URL is actually valid
        try:
            parsed_url = urllib.parse.urlparse(env['url'])
        except Exception as e:
            raise VulnerableCodeException(e.args)

        # check if the scheme is valid
        if parsed_url.scheme not in ['http', 'https']:
            raise VulnerableCodeException("invalid URL scheme")

        # check if there are no conflicting username,
        # and password configurations
        if parsed_url.password is not None:
            if env['password'] != '':
                if parsed_url.password != env['password']:
                    raise VulnerableCodeException("conflicting passwords provided")
            else:
                env['password'] = parsed_url.password

        if parsed_url.username is not None:
            if env['user'] != '':
                if parsed_url.username != env['user']:
                    raise VulnerableCodeException("conflicting usernames provided")
            else:
                env['user'] = parsed_url.username
