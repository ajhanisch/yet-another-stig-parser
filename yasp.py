#!/usr/bin/env python3

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
        '-i',
        metavar='[dir | .csv]',
        type=str,
        help='Directory that contains the .csv file(s) exported from STIG Viewer results or an individual .csv file.'
    )

    '''
    OPTIONAL ARGUMENTS
    '''
    parser.add_argument(
        '--output',
        '-o',
        choices=['excel'],
        default='excel',
        help='output summary from parsed files.'
    )

    '''
    VERSION
    '''
    parser.add_argument(
        '--version',
        '-v',
        action='version',
        version='{}'.format(version)
    )

    args = parser.parse_args()

class StigParser:

    def __init__(self, parser_input):
        if parser_input == None or parser_input == '':
            print('No filename specified!')
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
                print('File [{}] does not exist.'.format(parser_input))
                exit()
            self.list_csv.append(parser_input)

        if not self.list_csv:
            print('No file [{}] to parse was found!'.format(parser_input))
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
        workbook = Workbook('STIG_Category_Report_{}.xlsx'.format(self.setup.date))

        '''
        Headers used by Category and Completed POA&M tabs.
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

        self.create_stig_poams_dashboard_excel_dashboard_tab(workbook=workbook)
        self.create_stig_poams_dashboard_excel_category_tab(workbook=workbook, headers=headers)
        self.create_stig_poams_dashboard_excel_details_tab(workbook=workbook)
        self.create_stig_poams_dashboard_excel_completed_poams_tab(workbook=workbook, headers=headers)

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

        '''
        Create each overview section.
        '''
        worksheet.merge_range('A1:D1', 'Category Overview', format_merged_header)
        worksheet.write('A3', 'Category', format_overview_header)
        worksheet.write('B3', 'CAT I', format_cat_i)
        worksheet.write('C3', 'CAT II', format_cat_ii)
        worksheet.write('D3', 'CAT III', format_cat_iii)

        '''
        Set each overview row and column numbers.
        '''
        row_category_overview = 3
        column_category_overview = 0

        '''
        Populate category overview cells.
        '''
        for category in self._results.keys():
            count_category_cat_i = 0
            count_category_cat_ii = 0
            count_category_cat_iii = 0

            worksheet.write_url(row_category_overview, column_category_overview, "internal:'{}'!A1".format(category), format_overview_values, string=category)

            for stig_name in self._results[category].keys():
                count_stig_cat_i = len(self.find_by_values(category=category, stig=stig_name, values=['Open', 'high']))
                count_stig_cat_ii = len(self.find_by_values(category=category, stig=stig_name, values=['Open', 'medium']))
                count_stig_cat_iii = len(self.find_by_values(category=category, stig=stig_name, values=['Open', 'low']))

                count_category_cat_i += count_stig_cat_i
                count_category_cat_ii += count_stig_cat_ii
                count_category_cat_iii += count_stig_cat_iii              

            '''
            Write category overview values.
            '''
            count_category_total = count_category_cat_i + count_category_cat_ii + count_category_cat_iii

            worksheet.write_formula(row_category_overview, column_category_overview + 1, "=COUNTIF('{}'!E15:E{}, \"{}\")".format(category, count_category_total + 15, "high"), format_cat_i)
            worksheet.write_formula(row_category_overview, column_category_overview + 2, "=COUNTIF('{}'!E15:E{}, \"{}\")".format(category, count_category_total + 15, "medium"), format_cat_ii)
            worksheet.write_formula(row_category_overview, column_category_overview + 3, "=COUNTIF('{}'!E15:E{}, \"{}\")".format(category, count_category_total + 15, "low"), format_cat_iii)
            row_category_overview += 1

    def create_stig_poams_dashboard_excel_category_tab(self, workbook, headers):
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

    def create_stig_poams_dashboard_excel_completed_poams_tab(self, workbook, headers):
        '''
        Create complete POA&M worksheet.
        '''
        worksheet = workbook.add_worksheet('Completed POA&Ms')

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
        worksheet.merge_range(row, col, row, 1, 'Completed POA&M Items', format_boilerplate_titles)
        row += 1

        worksheet.write(row, col, 'System Name : ', format_boilerplate_headers)
        worksheet.write(row, col + 1, '', format_boilerplate_values)
        row += 1

        worksheet.write(row, col, 'Company/Organization Name : ', format_boilerplate_headers)
        worksheet.write(row, col + 1, '', format_boilerplate_values)
        row += 1

        worksheet.write(row, col, 'Sponsoring Service/Agency : ', format_boilerplate_headers)
        worksheet.write(row, col + 1, '', format_boilerplate_values)
        row += 2

        '''
        Write headers.
        '''            
        worksheet.write_row(row, col, headers, format_finding_headers)
        worksheet.autofilter(row, col, row, len(headers) - 1)
        row += 1

        '''
        Populate example values.
        '''
        list_blank_values = [ '' for header in headers ]
        for i in range(5):
            worksheet.write_row(row, col, list_blank_values, format_finding_values)
            row += 1

def main():
    '''
    MAIN FUNCTION
    '''
    setup = Setup()
    args = setup.args

    if not args.input:
        print('No operation specified!')
        exit()

    parser = StigParser(args.input)

    '''
    ARGUMENT HANDLING
    '''
    if args.output:
        parser.create_stig_poams_dashboard(format_option=args.output)

    exit()

if __name__ == '__main__':
