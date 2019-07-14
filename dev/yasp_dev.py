#!/usr/bin/env python3

import logging
from re import sub
from time import strftime
from csv import DictReader
from getpass import getuser
from xlsxwriter import Workbook
from argparse import ArgumentParser
from os import walk, getcwd, makedirs
from os.path import isdir, exists, basename, join

class Setup:
    '''
    VARIABLES
    '''
    version = '0.7'
    program = basename(__file__)
    repository = 'https://github.com/ajhanisch/yet-another-stig-parser'
    wiki = 'https://github.com/ajhanisch/yet-another-stig-parser/wiki'
    date = strftime('%Y-%m-%d_%H-%M-%S')
    user = getuser()

    '''
    ARGUMENT PARSER
    '''
    parser = ArgumentParser(description='Program to perform extraction from .csv STIG Viewer files and creates customized output.')

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
        '--dashboard',
        choices=['excel'],
        default='excel',
        help='Create summary document from parsed files.'
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
    '--verbose',
    choices=[ 'debug', 'info', 'warning', 'error', 'critical' ],
    default='info',
    help='Enable specific program verbosity. Default is info. Set to debug for complete script processing in logs and screen. Set to warning or critical for minimal script processing in logs and screen.'
    )

    parser.add_argument(
    '--vulnid',
    metavar='[vulnid]',
    type=str,
    help='Print a list of hosts vulnerable to specific STIG vulnerability ID.'
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
    dir_working = getcwd()
    dir_working_log = join(dir_working, 'logs')
    dir_output = join(dir_working, 'output')
    dir_output_poams = join(dir_output, 'poams')

    '''
    FILES
    '''
    file_log = join(dir_working_log, '{}_{}.log'.format(date, program))

    '''
    DICTIONARIES
    '''
    dict_directories = {
        'dir_working_log' : dir_working_log,
        'dir_output' : dir_output,
        'dir_output_poams' : dir_output_poams
    }

class StigParser:

    def __init__(self, parser_input):
        if parser_input == None or parser_input == '':
            logging.error('[!] No filename specified!')
            exit()

        # Parse input values in order to find valid .csv files
        self.list_csv = []
        if isdir(parser_input):
            if not parser_input.endswith('/'):
                parser_input += '/'
            # Automatic searching of files into specified directory
            for path, dirs, files in walk(parser_input):
                for f in files:
                    if f.endswith('.csv'):
                        self.list_csv.append(parser_input + f)
                break
        elif parser_input.endswith('.csv'):
            if not exists(parser_input):
                logging.error('[!] File [{}] does not exist.'.format(parser_input))
                exit()
            self.list_csv.append(parser_input)

        if not self.list_csv:
            logging.error('[!] No file [{}] to parse was found!'.format(parser_input))
            exit()

        # dictionary to store results
        self._results = {}
        self.setup = Setup()

        for file_csv in self.list_csv:
            self.parse_csv(file_csv)

    def parse_csv(self, file_csv):
        content = DictReader(open(file_csv))

        for row in content:
            category = row['TechnologyArea']
            if category not in self._results:
                self._results[category] = {}

            #stig = sub('[^A-Za-z0-9]+', ' ', row['STIG'])
            stig = row['STIG']
            if stig not in self._results[category]:
                self._results[category][stig] = []

            finding = {}
            for key,value in row.items():
                finding[key] = value
            
            if finding not in self._results[category][stig]:
                self._results[category][stig].append(finding)

    def find_by_values(self, category, stig, values):
        list_values = []

        for finding in self._results[category][stig]:
            if(all(x in finding.values() for x in values)):
                list_values.append(finding)
        
        return list_values

    def create_stig_poams_dashboard(self, format_option):
        dict_switch = {
            'excel' : self.create_stig_poams_dashboard_excel
        }
        dict_switch[format_option]()

    def create_stig_poams_dashboard_excel(self):
        workbook = Workbook('hello.xlsx')

        self.create_stig_poams_dashboard_excel_dashboard_tab(workbook=workbook)
        self.create_stig_poams_dashboard_excel_category_tab(workbook=workbook)
        self.create_stig_poams_dashboard_excel_details_tab(workbook=workbook)

        workbook.close()

    def create_stig_poams_dashboard_excel_dashboard_tab(self, workbook):
        '''
        Create dashboard worksheet.
        '''
        worksheet = workbook.add_worksheet('Dashboard')

        '''
        Formatting settings.
        '''
        format_merged_header = workbook.add_format(
            {
                'bold' : 1,
                'border' : 1,
                'align' : 'center',
                'valign' : 'vcenter',
                'fg_color' : '#87CEFA'
            }
        )

        format_overview_header = workbook.add_format(
            {
                'bottom' : 1,
                'top' : 1,
                'bold' : 1,
                'align' : 'center',
                'valign' : 'vcenter'
            }
        )      

        format_overview_values = workbook.add_format(
            {
                'bottom' : 1,
                'top' : 1
            }
        )      

        format_cat_i = workbook.add_format(
            {
                'bottom' : 1,
                'top' : 1,
                'bold' : 1,
                'font_color' : 'red',
                'align' : 'center',
                'valign' : 'vcenter'
            }
        )  

        format_cat_ii = workbook.add_format(
            {
                'bottom' : 1,
                'top' : 1,
                'bold' : 1,
                'font_color' : 'orange',
                'align' : 'center',
                'valign' : 'vcenter'
            }
        )

        format_cat_iii = workbook.add_format(
            {
                'bottom' : 1,
                'top' : 1,
                'bold' : 1,
                'font_color' : 'blue',
                'align' : 'center',
                'valign' : 'vcenter'
            }
        )

        format_total = workbook.add_format(
            {
                'bottom' : 1,
                'top' : 1,
                'bold' : 1,
                'font_color' : 'black',
                'align' : 'center',
                'valign' : 'vcenter'
            }
        )

        '''
        Create each overview section.
        '''
        worksheet.merge_range('A1:E1', 'Category Overview', format_merged_header)
        worksheet.write('A3', 'Category', format_overview_header)
        worksheet.write('B3', 'CAT I', format_cat_i)
        worksheet.write('C3', 'CAT II', format_cat_ii)
        worksheet.write('D3', 'CAT III', format_cat_iii)
        worksheet.write('E3', 'Total', format_overview_header)

        worksheet.merge_range('G1:K1', 'STIG Overview', format_merged_header)
        worksheet.write('G3', 'STIG', format_overview_header)  
        worksheet.write('H3', 'CAT I', format_cat_i)
        worksheet.write('I3', 'CAT II', format_cat_ii)
        worksheet.write('J3', 'CAT III', format_cat_iii)
        worksheet.write('K3', 'Total', format_overview_header)

        '''
        Set each overview row and column numbers.
        '''
        row_category_overview = 3
        column_category_overview = 0

        row_stig_overview = 3
        column_stig_overview = 6

        '''
        Populate category overview cells.
        '''
        for category in self._results.keys():
            count_category_cat_i = 0
            count_category_cat_ii = 0
            count_category_cat_iii = 0

            worksheet.write_url(row_category_overview, column_category_overview, "internal:'{}'!A1".format(category), format_overview_values, string=category)

            for stig_name in self._results[category].keys():
                worksheet.write(row_stig_overview, column_stig_overview, stig_name.split('Security Technical Implementation Guide')[0], format_overview_values)

                count_stig_cat_i = len(self.find_by_values(category=category, stig=stig_name, values=['Open', 'high']))
                count_stig_cat_ii = len(self.find_by_values(category=category, stig=stig_name, values=['Open', 'medium']))
                count_stig_cat_iii = len(self.find_by_values(category=category, stig=stig_name, values=['Open', 'low']))

                count_category_cat_i += count_stig_cat_i
                count_category_cat_ii += count_stig_cat_ii
                count_category_cat_iii += count_stig_cat_iii

                '''
                Write stig overview values.
                '''
                count_stig_total = count_stig_cat_i + count_stig_cat_ii + count_stig_cat_iii
                worksheet.write(row_stig_overview, column_stig_overview + 1, count_stig_cat_i, format_cat_i)
                worksheet.write(row_stig_overview, column_stig_overview + 2, count_stig_cat_ii, format_cat_ii)
                worksheet.write(row_stig_overview, column_stig_overview + 3, count_stig_cat_iii, format_cat_iii)
                worksheet.write(row_stig_overview, column_stig_overview + 4, count_stig_total, format_total)         
                row_stig_overview += 1       
                

            '''
            Write category overview values.
            '''
            count_category_total = count_category_cat_i + count_category_cat_ii + count_category_cat_iii
            worksheet.write(row_category_overview, column_category_overview + 1, count_category_cat_i, format_cat_i)
            worksheet.write(row_category_overview, column_category_overview + 2, count_category_cat_ii, format_cat_ii)
            worksheet.write(row_category_overview, column_category_overview + 3, count_category_cat_iii, format_cat_iii)
            worksheet.write(row_category_overview, column_category_overview + 4, count_category_total, format_total)

            row_category_overview += 1

    def create_stig_poams_dashboard_excel_category_tab(self, workbook):
        for category in self._results.keys():
            '''
            Create category worksheet.
            '''
            worksheet = workbook.add_worksheet(category)

            '''
            Set worksheet row and column values to properly populate values.
            '''
            row = 0
            col = 0

            '''
            Formatting settings.
            '''
            format_finding_headers = workbook.add_format(
                {
                    'bold' : 1,
                    'border' : 1,
                    'align' : 'center',
                    'valign' : 'vcenter',
                    'fg_color' : '#87CEFA'
                }
            )

            format_finding_values = workbook.add_format(
                {
                    'border' : 1,
                    'align' : 'left'
                }
            )

            format_boilerplate_titles = workbook.add_format(
                {
                    'bold' : 1,
                    'border' : 1,
                    'align' : 'center'
                }
            )

            format_boilerplate_headers = workbook.add_format(
                {
                    'bold' : 1,
                    'border' : 1,
                    'align' : 'right',
                    'fg_color' : '#87CEFA'
                }
            )

            format_boilerplate_values = workbook.add_format(
                {
                    'border' : 1,
                    'align' : 'right',
                    'fg_color' : '#C0C0C0'
                }
            )

            '''
            Populate boiler plate information.
            '''
            worksheet.merge_range(row, col, row, 1, 'Plan of Action & Milestones (POA&M)', format_boilerplate_titles)
            row += 1

            worksheet.write(row, col, 'System Name : ', format_boilerplate_headers)
            worksheet.write(row, col + 1, '', format_boilerplate_values)
            row += 1

            worksheet.write(row, col, 'Company/Organization Name : ', format_boilerplate_headers)
            worksheet.write(row, col + 1, '', format_boilerplate_values)
            row += 1

            worksheet.write(row, col, 'Date of this POA&M : ', format_boilerplate_headers)
            worksheet.write(row, col + 1, '', format_boilerplate_values)
            row += 1

            worksheet.write(row, col, 'Date of Last Update : ', format_boilerplate_headers)
            worksheet.write(row, col + 1, '', format_boilerplate_values)
            row += 1

            worksheet.write(row, col, 'Date of Original POA&M : ', format_boilerplate_headers)
            worksheet.write(row, col + 1, '', format_boilerplate_values)
            row += 1

            worksheet.merge_range(row, col, row, 1, 'ISSM Information', format_boilerplate_titles)
            row += 1

            worksheet.write(row, col, 'Name : ', format_boilerplate_headers)
            worksheet.write(row, col + 1, '', format_boilerplate_values)
            row += 1

            worksheet.write(row, col, 'Phone : ', format_boilerplate_headers)
            worksheet.write(row, col + 1, '', format_boilerplate_values)
            row += 1

            worksheet.write(row, col, 'Email : ', format_boilerplate_headers)
            worksheet.write(row, col + 1, '', format_boilerplate_values)
            row += 1

            worksheet.write(row, col, 'IS Type : ', format_boilerplate_headers)
            worksheet.write(row, col + 1, '', format_boilerplate_values)
            row += 1

            worksheet.write(row, col, 'UID : ', format_boilerplate_headers)
            worksheet.write(row, col + 1, '', format_boilerplate_values)
            row += 2

            '''
            Write headers.
            '''
            headers = [
                'HostName',
                'IPAddress',
                'Vuln ID',
                'Status',
                'Severity',
                'Rule Title',
                'Comments',
                'STIG',
                'Security Control',
                'POC',
                'Resources Required',
                'Scheduled Completion Date',
                'Milestones with Completion Dates',
                'Changes to Milestones',
                'Identified By',
                'Estimated Cost',
            ]
            
            worksheet.write_row(row, col, headers, format_finding_headers)
            worksheet.autofilter(row, col, row, len(headers) - 1)
            row += 1

            '''
            Populate category values.
            '''            
            for stig_name in self._results[category].keys():
                for finding in self._results[category][stig_name]:
                    if finding['Status'] == 'Open':
                        dict_modified_finding = {}
                        dict_modified_finding['HostName'] = finding['HostName']
                        dict_modified_finding['IPAddress'] = finding['IPAddress']
                        dict_modified_finding['Vuln ID'] = finding['Vuln ID']
                        dict_modified_finding['Status'] = finding['Status']
                        dict_modified_finding['Severity'] = finding['Severity']
                        dict_modified_finding['Rule Title'] = finding['Rule Title']
                        dict_modified_finding['Comments'] = finding['Comments']
                        dict_modified_finding['STIG'] = finding['STIG']
                        dict_modified_finding['Security Control'] = ''
                        dict_modified_finding['POC'] = ''
                        dict_modified_finding['Resources Required'] = ''
                        dict_modified_finding['Scheduled Completion Date'] = ''
                        dict_modified_finding['Milestones with Completion Dates'] = ''
                        dict_modified_finding['Changes to Milestones'] = ''
                        dict_modified_finding['Identified By'] = ''
                        dict_modified_finding['Estimated Cost'] = ''
                        worksheet.write_row(row, col, dict_modified_finding.values(), format_finding_values)
                        row += 1

    def create_stig_poams_dashboard_excel_details_tab(self, workbook):
        '''
        Create dashboard worksheet.
        '''
        worksheet = workbook.add_worksheet('Details')

        '''
        Set worksheet row and column values to properly populate values.
        '''
        row = 0
        col = 0

        '''
        Formatting settings.
        '''
        format_finding_headers = workbook.add_format(
            {
                'bold' : 1,
                'border' : 1,
                'align' : 'center',
                'valign' : 'vcenter',
                'fg_color' : '#87CEFA'
            }
        )

        format_finding_values = workbook.add_format(
            {
                'border' : 1,
                'align' : 'left'
            }
        )

        '''
        Populate all category/stig values.
        '''
        for category in self._results.keys():
            for stig_name in self._results[category].keys():
                for finding in self._results[category][stig_name]:
                    if finding['Status'] == 'Open':
                        if row > 0:
                            worksheet.write_row(row, col, finding.values(), format_finding_values)
                            row += 1
                        else:
                            worksheet.write_row(row, col, finding.keys(), format_finding_headers)
                            worksheet.autofilter(row, col, row, len(finding.keys()) - 1)
                            row += 1

def main():
    '''
    MAIN FUNCTION
    '''
    setup = Setup()
    args = setup.args

    if not args.input:
        logging.error('[!] No operation specified!')
        exit()

    '''
    REQUIRED DIRECTORIES CREATION
    '''
    for value in setup.dict_directories.values():
        if not exists(value):
            makedirs(value)

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

    parser = StigParser(args.input)

    '''
    ARGUMENT HANDLING
    '''
    if args.hosts:
        parser.print_hosts(fullinfo=args.hosts)
    if args.vulnid:
        parser.find_by_vulnid(vulnid=args.vulnid, output='print')
    if args.host:
        parser.find_by_host(host=args.host)
    if args.raw:
        parser.print_raw()
    if args.stats:
        parser.print_statistics()
    if args.dashboard:
        parser.create_stig_poams_dashboard(format_option=args.dashboard)

    exit()

if __name__ == '__main__':
