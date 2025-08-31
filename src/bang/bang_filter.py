#!/usr/bin/env python3

# Licensed under the terms of the Apache license
# SPDX-License-Identifier: Apache-2.0

import shlex

from textual.validation import ValidationResult, Validator


def process_filter(filter_string):
    '''Process filter statements: tokenize and add to right data structures'''
    result = {}

    # A mapping of token names to names used in the result dict.
    name_to_results = {'label': 'labels', 'hash': 'hashes'}

    for name, result_name in name_to_results.items():
        result[result_name] = []

    # Then add some special cases.
    result['is_filtered'] = False
    result['overlay'] = True

    if filter_string:
        # Input was already validated before being sent here
        # so it can be processed without any extra checks.

        tokens = shlex.split(filter_string.lower())

        for t in tokens:
            # First split the tokens in names and values
            # and optional parameters
            params = {}

            name_params, value = t.split('=', maxsplit=1)
            if '?' in name_params:
                name, args = name_params.split('?', maxsplit=1)
                split_args = args.split(';')
                for split_arg in split_args:
                    if ':' in split_arg:
                        param_name, param_value = split_arg.split(':', maxsplit=1)
                        if param_name and param_value:
                            params[param_name] = param_value
            else:
                name = name_params

            # Process each known name. Generic case first.
            if name in name_to_results:
                result[name_to_results[name]].append((value, params))
                result['is_filtered'] = True

            # Then the special cases.
            match name:
                case 'overlays':
                    # special filtering flag
                    if value == 'off':
                        result['overlay'] = False
    return result


class FilterValidator(Validator):
    '''Validator for the filtering language (syntax and values).'''

    def __init__(self, data, **kwargs):
        # Known values: only these will be regarded as valid.
        self.labels = data.get('labels', set())
        self.token_names_params = kwargs.get('token_names', [])
        self.token_names = [x['name'] for x in self.token_names_params]

        # A mapping for filter error messages. These are not displayed
        # in the TUI, but they can used in a CLI.
        self.name_to_error = {}
        for i in self.token_names_params:
            self.name_to_error[i['name']] = i['error']

        # A mapping for names to parameters. This can be used to verify
        # if parameters are actually correct. Unsure if this is a useful
        # feature or not, so disable it for now.
        self.name_to_params = {}
        for i in self.token_names_params:
            if 'params' in i:
                self.name_to_params[i['name']] = i['params']

        self.verify_params = False

    def validate(self, value: str) -> ValidationResult:
        try:
            # Split the value into individual tokens
            tokens = shlex.split(value.lower())
            if not tokens:
                return self.failure("Empty string")

            # Verify each token
            for t in tokens:
                if '=' not in t:
                    return self.failure("Invalid name")

                # Verify if the token is well formed
                # and if it has a valid name.
                params = {}
                name_params, token_value = t.split('=', maxsplit=1)
                if '?' in name_params:
                    name, args = name_params.split('?', maxsplit=1)
                    split_args = args.split(';')
                    for split_arg in split_args:
                        if ':' in split_arg:
                            param_name, param_value = split_arg.split(':', maxsplit=1)
                            if param_name and param_value:
                                params[param_name] = param_value
                else:
                    name = name_params
                if name not in self.token_names:
                    return self.failure("Invalid name")

                is_error = False

                # Then check each individual token.
                match name:
                    case 'label':
                        if token_value not in self.labels:
                            is_error = True
                    case 'overlays':
                        if token_value not in ['off']:
                            is_error = True

                # Then check the parameters, if enabled.
                if self.verify_params:
                    if name in self.name_to_params:
                        for p in params:
                            if p not in self.name_to_params[name]:
                                is_error = True

                if is_error:
                    return self.failure(self.name_to_error[name])
            return self.success()
        except ValueError:
            return self.failure('Incomplete')
