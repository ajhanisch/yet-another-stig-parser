#!/usr/bin/env python3

import os
import sys
import time
import logging
import getpass
import argparse

class Setup:
    '''
    VARIABLES
    '''
    version = '0.1'
    program = os.path.basename(__file__)
    repository = 'https://github.com/ajhanisch/yasp'
    wiki = 'https://github.com/ajhanisch'
    date = time.strftime('%Y-%m-%d_%H-%M-%S')
    user = getpass.getuser()

    '''
    ARGUMENT PARSER
    '''
    parser = argparse.ArgumentParser(description='Program to parse SCAP Scanner output (.XML or .CSV) and create skeleton POAM documents.')

    '''
    REQUIRED ARGUMENTS
    '''
    required = parser.add_argument_group('Required', 'Ensure to use all of these parameters to run [{}] successfully.'.format(program))
    required.add_argument(
    '--input',
    type=str,
    help='Directory that contains the .XML and/or .CSV files exported from SCAP Scanner results.'
    )
    '''
    OPTIONAL ARGUMENTS
    '''
    parser.add_argument(
    '--verbose',
    choices=[ 'debug', 'info', 'warning', 'error', 'critical' ],
    default='info',
    help='Enable specific program verbosity. Default is info. Set to debug for complete script processing in logs and screen. Set to warning or critical for minimal script processing in logs and screen.'
    )
    '''
    VERSION
    '''
    parser.add_argument(
    '--version',
    action='version',
    version='[{}] - Version [{}]. Check [{}] for the most up to date information.'.format(program, version, repository)
    )

    args = parser.parse_args()

    '''
    DIRECTORIES
    '''
    dir_working = os.getcwd()
    dir_working_log = os.path.join(dir_working, 'LOGS', date)
    dir_output = os.path.join(dir_working, 'OUTPUT')
    dir_output_poams = os.path.join(dir_output, 'POAMS')

    '''
    FILES
    '''
    file_log = os.path.join(dir_working_log, '{}_{}.log'.format(date, program))

    '''
    DICTIONARIES
    '''
    dict_directories = {
    'dir_working_log' : dir_working_log,
    'dir_output' : dir_output,
    'dir_output_poams' : dir_output_poams
    }

class Stig:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    # 


def main():
    '''
    MAIN FUNCTION
    '''
    setup = Setup()
    args = setup.args

    '''
    REQUIRED DIRECTORIES CREATION
    '''
    for key, value in setup.dict_directories.items():
        if not os.path.exists(value):
            os.makedirs(value)

    '''
    SETUP LOGGING
    '''
    dict_levels = {
    'debug': logging.DEBUG,
    'info': logging.INFO,
    'warning': logging.WARNING,
    'error': logging.ERROR,
    'critical': logging.CRITICAL,
    }
    level_name = args.verbose
    level = dict_levels.get(level_name)
    format = '[%(asctime)s] - [%(levelname)s] - %(message)s'
    handlers = [logging.FileHandler(setup.file_log), logging.StreamHandler()]
    logging.basicConfig(
    level = level,
    format = format,
    handlers = handlers
    )

    logging.debug('Hello [{}]! You are running [{}] with the following arguments: '.format(setup.user, setup.program))
    for a in args.__dict__:
        logging.debug(str(a) + ' : ' + str(args.__dict__[a]))

    '''
    ARGUMENT HANDLING
    '''

if __name__ == '__main__':
    main()
