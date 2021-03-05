# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2018 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#


import re
import sys
import os
import argparse
import shlex
import json
import logging
import base64

from . import __version__
from .params import KeeperParams

from . import cli



def usage(m):
    print(m)
    parser.print_help()
    cli.display_command_help(show_enterprise=True, show_shell=True)
    sys.exit(1)


parser = argparse.ArgumentParser(prog='keeper', add_help=False, allow_abbrev=False)
parser.add_argument('--server', '-ks', dest='server', action='store', help='Keeper Host address.')
parser.add_argument('--user', '-ku', dest='user', action='store', help='Email address for the account.')
parser.add_argument('--password', '-kp', dest='password', action='store', help='Master password for the account.')
parser.add_argument('--version', dest='version', action='store_true', help='Display version')
parser.add_argument('--config', dest='config', action='store', help='Config file to use')
parser.add_argument('--debug', dest='debug', action='store_true', help='Turn on debug mode')
parser.add_argument('--batch-mode', dest='batch_mode', action='store_true', help='Run commander in batch or basic UI mode.')
parser.add_argument('--login-v3', '-lv3', dest='login_v3', action='store', help='Use Login v3 to login to Keeper.')
parser.add_argument('command', nargs='?', type=str, action='store', help='Command')
parser.add_argument('options', nargs='*', action='store', help='Options')
parser.error = usage


def handle_exceptions(exc_type, exc_value, exc_traceback):
    import traceback
    traceback.print_exception(exc_type, exc_value, exc_traceback)
    input('Press Enter to exit')
    sys.exit(-1)


def main(from_package=False):
    errno = 0

    if from_package:
        sys.excepthook = handle_exceptions

    sys.argv[0] = re.sub(r'(-script\.pyw?|\.exe)?$', '', sys.argv[0])

    opts, flags = parser.parse_known_args(sys.argv[1:])
    params = KeeperParams.from_config(opts.config)

    if opts.debug:
        params.debug = opts.debug
        is_debug = logging.getLogger().level <= logging.DEBUG
        logging.getLogger().setLevel((logging.WARNING if params.batch_mode else logging.INFO) if is_debug else logging.DEBUG)
        logging.info('Debug %s', 'OFF' if is_debug else 'ON')


    if opts.batch_mode:
        params.batch_mode = True

    if opts.login_v3:
        params.login_v3 = 'TRUE'.startswith(str(opts.login_v3).upper())

    if opts.server:
        params.server = 'https://{0}/api/v2/'.format(opts.server)

    if opts.user:
        params.user = opts.user

    if opts.password:
        params.password = opts.password
    else:
        pwd = os.getenv('KEEPER_PASSWORD')
        if pwd:
            params.password = pwd

    if opts.version:
        print('Keeper Commander, version {0}'.format(__version__))
        return

    if flags and len(flags) > 0:
        if flags[0] == '-h':
            flags.clear()
            opts.command = '?'

    if not opts.command and from_package:
        opts.command = 'shell'

    if (opts.command or '') in {'?', ''}:
        if opts.command == '?' or not params.commands:
            usage('')

    logging.basicConfig(level=logging.WARNING if params.batch_mode else logging.INFO, format='%(message)s')

    if params.timedelay >= 1 and params.commands:
        cli.runcommands(params)
    else:
        if opts.command not in {'shell', '-'}:
            if opts.command:
                flags = ' '.join([shlex.quote(x) for x in flags]) if flags is not None else ''
                options = ' '.join([shlex.quote(x) for x in opts.options]) if opts.options is not None else ''
                command = ' '.join([opts.command, flags])
                if options:
                    command += ' -- ' + options
                params.commands.append(command)
            params.commands.append('q')
            params.batch_mode = True
        else:
            if opts.command == '-':
                params.batch_mode = True

        errno = cli.loop(params)

    sys.exit(errno)


if __name__ == '__main__':
    main()
