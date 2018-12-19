#!/usr/bin/env python3

from pprint import pprint

from os.path import isdir, exists, basename
from os import walk
from sys import exit
import csv
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
    parser = argparse.ArgumentParser(description='Program to parse STIG Viewer .CSV output and create skeleton POAM documents.')

    '''
    REQUIRED ARGUMENTS
    '''
    required = parser.add_argument_group('Required', 'Ensure to use all of these parameters to run [{}] successfully.'.format(program))
    required.add_argument(
    '--input',
    type=str,
    help='|dir|.csv| Directory that contains the .CSV files exported from STIG Viewer results or individual .csv file.'
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

class stig_parser:

    def __init__(self, filename_csv):
        if filename_csv == None or filename_csv == '':
            print('[!] No filename specified!')
            exit()

        # Parse input values in order to find valid .csv files
        self._csv_source = []
        if isdir(filename_csv):
            if not filename_csv.endswith('/'):
                filename_csv += '/'
            # Automatic searching of files into specified directory
            for path, dirs, files in walk(filename_csv):
                for f in files:
                    if f.endswith('.csv'):
                        self._csv_source.append(filename_csv + f)
                break
        elif filename_csv.endswith('.csv'):
            if not exists(filename_csv):
                print('[!] File [{}] does not exist.'.format(filename_csv))
                exit()
            self._csv_source.append(filename_csv)

        if not self._csv_source:
            print('[!] No file [{}] to parse was found!'.format(filename_csv))
            exit()

        # Dictionary to store information
        self._results = {}

        # For each .csv file found...
        for report in self._csv_source:
            # Parse and extract information
            self._parse_results(report)

    def _parse_results(self, file_report):
        with open(file_report, encoding='UTF-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                if row['Severity'] == 'medium':
                    pprint(row)

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

    if not args.input:
        print('[!] No operation specified!')
        exit()

    parser = stig_parser(args.input)

if __name__ == '__main__':
    main()
