#!/usr/bin/env python3

from pprint import pprint

from os.path import isdir, exists, basename
from os import walk
from sys import exit
from socket import inet_aton
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
    version = '0.2'
    program = os.path.basename(__file__)
    repository = 'https://github.com/ajhanisch/yet-another-stig-parser'
    wiki = 'https://github.com/ajhanisch/yet-another-stig-parser/wiki'
    date = time.strftime('%Y-%m-%d_%H-%M-%S')
    user = getpass.getuser()

    '''
    ARGUMENT PARSER
    '''
    parser = argparse.ArgumentParser(description='Program to perform extraction from .csv STIG Viewer files and creates customized output.')

    '''
    REQUIRED ARGUMENTS
    '''
    required = parser.add_argument_group('Required', 'Ensure to use all of these parameters to run [{}] successfully.'.format(program))
    required.add_argument(
    '--input',
    metavar='[dir | .csv]',
    type=str,
    help='Directory that contains the .csv file(s) exported from STIG Viewer results or an individual .csv file.'
    )
    '''
    OPTIONAL ARGUMENTS
    '''
    parser.add_argument(
    '--csv',
    metavar='[filename]',
    type=str,
    help='Save results into csv report.'
    )
    parser.add_argument(
    '--delim',
    metavar='[delim]',
    help='Use custom delimiter to save .csv report as.',
    default=','
    )
    parser.add_argument(
    '--host',
    metavar='[host]',
    type=str,
    help='Print a list of findings associated with a specific host.'
    )
    parser.add_argument(
    '--hosts',
    choices=['full', 'basic'],
    help='Print a list of hosts parsed. Full includes: (ip address, host name, and mac address.). Basic includes: (ip address and host name).'
    )
    parser.add_argument(
    '--vulnid',
    metavar='[Vuln ID]',
    type=str,
    help='Print a list of hosts vulnerable to specific STIG vulnerability ID.'
    )
    parser.add_argument(
    '--raw',
    action='store_true',
    default=False,
    help='Print parsed information in raw mode (debug).'
    )
    parser.add_argument(
    '--stats',
    action='store_true',
    default=False,
    help='Print statistisc about parsed files.'
    )
    parser.add_argument(
    '--txt',
    metavar='[filename]',
    type=str,
    help='Save results into text report.'
    )
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
    # 'dir_output' : dir_output,
    # 'dir_output_poams' : dir_output_poams
    }

class stig_parser:
    '''
    Data structure to store parsed information (IP):

    _results = {
       IP_1: [ info, finding_1, ... , finding_N ]
       ...
       IP_N: ...
    }

    info = {
        'technology_area':  ,
        'host_name':         ,
        'mac_address':
    }

    finding = {
        'vuln_id': ,
        'severity': ,
        'group_title': ,
        'rule_id': ,
        'stig_id': ,
        'rule_title': ,
        'discussion': ,
        'ia_control' : ,
        'check_content': ,
        'fix_text': ,
        'false_positives': ,
        'false_negatives': ,
        'documentable': ,
        'mitigations': ,
        'potential_impact': ,
        'third_party_tools': ,
        'mitigation_control': ,
        'responsibility': ,
        'severity_override_guidance': ,
        'check_content_reference': ,
        'classification': ,
        'stig': ,
        'status': ,
        'comments': ,
        'finding_details': ,
        'severity_override': ,
        'severity_override_justification': ,
        'cci':
    }
    '''

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

        # dictionary to store results
        self._results = {}

        for csv_source in self._csv_source:
            self.dict_results = self._parse_csv(csv_source)

    def _create_poam(self):
        '''
        Save extracted information to skeleton POAM document.
        '''
        finished = False

    def _find_by_host(self, host):
        '''
        Search information by host.
        '''
        try:
            inet_aton(host) # test for valid ip address
        except OSError:
            print('[!] IP address format error in [{}].'.format(host))
            exit()

        if host in self._results:
            for h in self._results.keys():
                if h == host:
                    print(h, self._results[h][0]['host_name'])
                    for finding in self._results[h][1:]:
                        print('{} {} {}'.format(finding['vuln_id'], finding['status'], finding['severity']))
        else:
            print('[!] No results found. Ensure [{}] is a valid host.'.format(host))
            exit()

    def _find_by_vulnid(self, vulnid):
        '''
        Search information by STIG vulnid.
        '''
        if len(vulnid) != 5 or not vulnid.isdigit():
            print('[!] Vuln ID format error in [{}].'.format(vulnid))
            print('[-] To search for V-12345: use --vulnid 12345]')
            exit()

        for host in self._results.keys():
            for finding in self._results[host][1:]:
                vid = 'V-{}'.format(vulnid)
                if finding['vuln_id'] == vid:
                    print('{} {} {}'.format(host, vid, finding['rule_title'], self._results[host][0]['host_name']))

    def _parse_csv(self, file_report):
        with open(file_report, encoding='UTF-8') as csvfile:
            reader = csv.reader(csvfile)
            next(reader, None)  # skip the headers

            for row in reader:
                ip = row[2]
                if not ip in self._results:
                    self._results[ip] = []

                info = {
                    'technology_area': row[0],
                    'host_name': row[1],
                    'mac_address': row[3]
                }
                if not info in self._results[ip]:
                    self._results[ip].append(info)

                finding = {
                    'vuln_id': row[4],
                    'severity': row[5],
                    'group_title': row[6],
                    'rule_id': row[7],
                    'stig_id': row[8],
                    'rule_title': row[9],
                    'discussion': row[10],
                    'ia_control' : row[11],
                    'check_content': row[12],
                    'fix_text': row[13],
                    'false_positives': row[14],
                    'false_negatives': row[15],
                    'documentable': row[16],
                    'mitigations': row[17],
                    'potential_impact': row[18],
                    'third_party_tools': row[19],
                    'mitigation_control': row[20],
                    'responsibility': row[21],
                    'severity_override_guidance': row[22],
                    'check_content_reference': row[23],
                    'classification': row[24],
                    'stig': row[25],
                    'status': row[26],
                    'comments': row[27],
                    'finding_details': row[28],
                    'severity_override': row[29],
                    'severity_override_justification': row[30],
                    'cci': row[31]
                }
                if not finding in self._results[ip]:
                    self._results[ip].append(finding)
                else:
                    print('[!] Duplicate finding! Finding [{}] already exists for host [{}].'.format(finding['rule_title'], ip))
                    exit(1)

    def _print_hosts(self, fullinfo=False):
        '''
        Present hosts present into parsed files.
        '''
        for host in self._results.keys():
            if fullinfo == 'full':
                print('{} {} {}'.format(host, self._results[host][0]['host_name'], self._results[host][0]['mac_address']))
            elif fullinfo == 'basic':
                print('{} {}'.format(host, self._results[host][0]['host_name']))

    def _print_raw(self):
        '''
        Print information in raw format (debug).
        '''
        if self._results:
            pprint(self._results)
        else:
            print('[!] No information available.')

    def _print_statistics(self):
        '''
        Print statistics about parsed files.
        '''
        open_high = 0
        open_medium = 0
        open_low = 0

        nr_high = 0
        nr_medium = 0
        nr_low = 0

        nf_high = 0
        nf_medium = 0
        nf_low = 0

        na_high = 0
        na_medium = 0
        na_low = 0

        list_open_high = []
        list_open_medium = []
        list_open_low = []

        list_nr_high = []
        list_nr_medium = []
        list_nr_low = []

        list_nf_high = []
        list_nf_medium = []
        list_nf_low = []

        list_na_high = []
        list_na_medium = []
        list_na_low = []

        list_cat_I = []
        list_cat_II = []
        list_cat_III = []

        targets = {}

        for host in self._results.keys():
            targets[host] = {
                'open_high': 0,
                'open_medium': 0,
                'open_low': 0,
                'nr_high': 0,
                'nr_medium': 0,
                'nr_low': 0,
                'nf_high': 0,
                'nf_medium': 0,
                'nf_low': 0,
                'na_high': 0,
                'na_medium': 0,
                'na_low': 0,
                'list_open_high': [],
                'list_open_medium': [],
                'list_open_low': [],
                'list_nr_high': [],
                'list_nr_medium': [],
                'list_nr_low': [],
                'list_nf_high': [],
                'list_nf_medium': [],
                'list_nf_low': [],
                'list_na_high': [],
                'list_na_medium': [],
                'list_na_low': []
            }
            for finding in self._results[host][1:]:
                status = finding['status']
                severity = finding['severity']
                if status == 'Open' and severity =='high':
                    open_high += 1
                    targets[host]['open_high'] += 1
                    # add finding (global)
                    if finding['vuln_id'] not in list_open_high:
                        list_open_high.append(finding['vuln_id'])
                    # add finding (local)
                    if finding['vuln_id'] not in targets[host]['list_open_high']:
                        targets[host]['list_open_high'].append(finding['vuln_id'])
                elif status == 'Open' and severity =='medium':
                    open_medium += 1
                    targets[host]['open_medium'] += 1
                    if finding['vuln_id'] not in list_open_medium:
                        list_open_medium.append(finding['vuln_id'])
                    if finding['vuln_id'] not in targets[host]['list_open_medium']:
                        targets[host]['list_open_medium'].append(finding['vuln_id'])
                elif status == 'Open' and severity =='low':
                    open_low += 1
                    targets[host]['open_low'] += 1
                    if finding['vuln_id'] not in list_open_low:
                        list_open_low.append(finding['vuln_id'])
                    if finding['vuln_id'] not in targets[host]['list_open_low']:
                        targets[host]['list_open_low'].append(finding['vuln_id'])
                elif status == 'Not Reviewed' and severity =='high':
                    nr_high += 1
                    targets[host]['nr_high'] += 1
                    if finding['vuln_id'] not in list_nr_high:
                        list_nr_high.append(finding['vuln_id'])
                    if finding['vuln_id'] not in targets[host]['list_nr_high']:
                        targets[host]['list_nr_high'].append(finding['vuln_id'])
                elif status == 'Not Reviewed' and severity =='medium':
                    nr_medium += 1
                    targets[host]['nr_medium'] += 1
                    if finding['vuln_id'] not in list_nr_medium:
                        list_nr_medium.append(finding['vuln_id'])
                    if finding['vuln_id'] not in targets[host]['list_nr_medium']:
                        targets[host]['list_nr_medium'].append(finding['vuln_id'])
                elif status == 'Not Reviewed' and severity =='low':
                    nr_low += 1
                    targets[host]['nr_low'] += 1
                    if finding['vuln_id'] not in list_nr_low:
                        list_nr_low.append(finding['vuln_id'])
                    if finding['vuln_id'] not in targets[host]['list_nr_low']:
                        targets[host]['list_nr_low'].append(finding['vuln_id'])
                elif status == 'Not A Finding' and severity =='high':
                    nf_high += 1
                    targets[host]['nf_high'] += 1
                    if finding['vuln_id'] not in list_nf_high:
                        list_nf_high.append(finding['vuln_id'])
                    if finding['vuln_id'] not in targets[host]['list_nf_high']:
                        targets[host]['list_nf_high'].append(finding['vuln_id'])
                elif status == 'Not A Finding' and severity =='medium':
                    nf_medium += 1
                    targets[host]['nf_medium'] += 1
                    if finding['vuln_id'] not in list_nf_medium:
                        list_nf_medium.append(finding['vuln_id'])
                    if finding['vuln_id'] not in targets[host]['list_nf_medium']:
                        targets[host]['list_nf_medium'].append(finding['vuln_id'])
                elif status == 'Not A Finding' and severity =='low':
                    nf_low += 1
                    targets[host]['nf_low'] += 1
                    if finding['vuln_id'] not in list_nf_low:
                        list_nf_low.append(finding['vuln_id'])
                    if finding['vuln_id'] not in targets[host]['list_nf_low']:
                        targets[host]['list_nf_low'].append(finding['vuln_id'])
                elif status == 'Not Applicable' and severity =='high':
                    na_high += 1
                    targets[host]['na_high'] += 1
                    if finding['vuln_id'] not in list_na_high:
                        list_na_high.append(finding['vuln_id'])
                    if finding['vuln_id'] not in targets[host]['list_na_high']:
                        targets[host]['list_na_high'].append(finding['vuln_id'])
                elif status == 'Not Applicable' and severity =='medium':
                    na_medium += 1
                    targets[host]['na_medium'] += 1
                    if finding['vuln_id'] not in list_na_medium:
                        list_na_medium.append(finding['vuln_id'])
                    if finding['vuln_id'] not in targets[host]['list_na_medium']:
                        targets[host]['list_na_medium'].append(finding['vuln_id'])
                elif status == 'Not Applicable' and severity =='low':
                    na_low += 1
                    targets[host]['na_low'] += 1
                    if finding['vuln_id'] not in list_na_low:
                        list_na_low.append(finding['vuln_id'])
                    if finding['vuln_id'] not in targets[host]['list_na_low']:
                        targets[host]['list_na_low'].append(finding['vuln_id'])

        print('')
        print('#' * 8 + '   STATISTICS  ' + '#' * 8)
        print('')
        print('Total targets:\t\t\t{}'.format(
        len(self._results.keys())
        ))
        print('Total findings:\t\t\t{}\t[  unique: {}  ]'.format(
        (open_high + open_medium + open_low + \
        nr_high + nr_medium + nr_low + \
        nf_high + nf_medium + nf_low + \
        na_high + na_medium + na_low)
        ,
        (len(list_open_high) + len(list_open_medium) + len(list_open_low) + \
        len(list_nr_high) + len(list_nr_medium) + len(list_nr_low) + \
        len(list_nf_high) + len(list_nf_medium) + len(list_nf_low) + \
        len(list_na_high) + len(list_na_medium) + len(list_na_low))
        ))
        print('Open (high):\t\t\t{}\t[  unique: {}  ]'.format(
        open_high
        ,
        len(list_open_high)
        ))
        print('Open (medium):\t\t\t{}\t[  unique: {}  ]'.format(
        open_medium
        ,
        len(list_open_medium)
        ))
        print('Open (low):\t\t\t{}\t[  unique: {}  ]'.format(
        open_low
        ,
        len(list_open_low)
        ))
        print('Not reviewed (high):\t\t{}\t[  unique: {}  ]'.format(
        nr_high
        ,
        len(list_nr_high)
        ))
        print('Not reviewed (medium):\t\t{}\t[  unique: {}  ]'.format(
        nr_medium
        ,
        len(list_nr_medium)
        ))
        print('Not reviewed (low):\t\t{}\t[  unique: {}  ]'.format(
        nr_low
        ,
        len(list_nr_low)
        ))
        print('Not a finding (high):\t\t{}\t[  unique: {}  ]'.format(
        nf_high
        ,
        len(list_nf_high)
        ))
        print('Not a finding (medium):\t\t{}\t[  unique: {}  ]'.format(
        nf_medium
        ,
        len(list_nf_medium)
        ))
        print('Not a finding (low):\t\t{}\t[  unique: {}  ]'.format(
        nf_low
        ,
        len(list_nf_low)
        ))
        print('Not applicable (high):\t\t{}\t[  unique: {}  ]'.format(
        na_high
        ,
        len(list_na_high)
        ))
        print('Not applicable (medium):\t{}\t[  unique: {}  ]'.format(
        na_medium
        ,
        len(list_na_medium)
        ))
        print('Not applicable (low):\t\t{}\t[  unique: {}  ]'.format(
        na_low
        ,
        len(list_na_low)
        ))

        # statistics (per host)
        print('')
        print('#' * 8 + '   HOSTS  ' + '#' * 8)
        print('')
        for host in targets.keys():
            print('[*] {}'.format(host))
            total_findings = targets[host]['open_high'] + targets[host]['open_medium'] + targets[host]['open_low'] + \
            targets[host]['nr_high'] + targets[host]['nr_medium'] + targets[host]['nr_low'] + \
            targets[host]['nf_high'] + targets[host]['nf_medium'] + targets[host]['nf_low'] + \
            targets[host]['na_high'] + targets[host]['na_medium'] + targets[host]['na_low']

            total_findings_uniq = len(targets[host]['list_open_high']) + len(targets[host]['list_open_medium']) + len(targets[host]['list_open_low']) + \
            len(targets[host]['list_nr_high']) + len(targets[host]['list_nr_medium']) + len(targets[host]['list_nr_low']) + \
            len(targets[host]['list_nf_high']) + len(targets[host]['list_nf_medium']) + len(targets[host]['list_nf_low']) + \
            len(targets[host]['list_na_high']) + len(targets[host]['list_na_medium']) + len(targets[host]['list_na_low'])

            print('\tTotal findings:\t\t\t{}\t[  unique: {}  ]'.format(total_findings, total_findings_uniq))
            print('\tOpen high:\t\t\t{}\t[  unique: {}  ]'.format(targets[host]['open_high'], len(targets[host]['list_open_high'])))
            print('\tOpen medium:\t\t\t{}\t[  unique: {}  ]'.format(targets[host]['open_medium'], len(targets[host]['list_open_medium'])))
            print('\tOpen low:\t\t\t{}\t[  unique: {}  ]'.format(targets[host]['open_low'], len(targets[host]['list_open_low'])))
            print('\tNot reviewed (high):\t\t{}\t[  unique: {}  ]'.format(targets[host]['nr_high'], len(targets[host]['list_nr_high'])))
            print('\tNot reviewed (medium):\t\t{}\t[  unique: {}  ]'.format(targets[host]['nr_medium'], len(targets[host]['list_nr_medium'])))
            print('\tNot reviewed (low):\t\t{}\t[  unique: {}  ]'.format(targets[host]['nr_low'], len(targets[host]['list_nr_low'])))
            print('\tNot a finding (high):\t\t{}\t[  unique: {}  ]'.format(targets[host]['nf_high'], len(targets[host]['list_nf_high'])))
            print('\tNot a finding (medium):\t\t{}\t[  unique: {}  ]'.format(targets[host]['nf_medium'], len(targets[host]['list_nf_medium'])))
            print('\tNot a finding (low):\t\t{}\t[  unique: {}  ]'.format(targets[host]['nf_low'], len(targets[host]['list_nf_low'])))
            print('\tNot applicable (high):\t\t{}\t[  unique: {}  ]'.format(targets[host]['nf_high'], len(targets[host]['list_na_high'])))
            print('\tNot applicable (medium):\t{}\t[  unique: {}  ]'.format(targets[host]['na_medium'], len(targets[host]['list_na_medium'])))
            print('\tNot applicable (low):\t\t{}\t[  unique: {}  ]'.format(targets[host]['na_low'], len(targets[host]['list_na_low'])))

    def _save_csv(self, filename, delim=','):
        '''
        Save results into .csv report.
        '''
        if not filename.endswith('.csv'):
            filename += '.csv'

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

    '''
    ARGUMENT HANDLING
    '''
    if not args.input:
        print('[!] No operation specified!')
        exit()

    parser = stig_parser(args.input)

    if args.hosts:
        parser._print_hosts(fullinfo=args.hosts)
    if args.csv:
        parser._save_csv(filename=args.csv, delim=args.delim)
    if args.txt:
        parser._save_txt(filename=args.txt)
    if args.vulnid:
        parser._find_by_vulnid(vulnid=args.vulnid)
    if args.host:
        parser._find_by_host(host=args.host)
    if args.raw:
        parser._print_raw()
    if args.stats:
        parser._print_statistics()

    exit()

if __name__ == '__main__':
    main()
