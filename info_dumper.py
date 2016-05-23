#!/usr/bin/python
#-*-coding: utf-8-*-
"""
This script produces a test for the ability to dump information from PE files:
- Runs the test for the specified directory with  files;
- Stores information in the database -> logfile.db;
- Generates a report about collected information -> logfile.json;

"""
import os
import sys
from datetime import datetime
import json
import sqlite3

import pefile


class InfoDumper(object):
    """
    This class runs a test of dumping information from pe-file.
    It consist of four methods:
        - find_pe_files - finds all files in ours path;
        - dump_pe_file - dumps information from PE files and collect some data;
        - create_table - creates a table (logfile.db) with data from dump_pe_file method;
        - db_to_json - creates a json file (logfile.json) from database (logfile.db);
    The files logfile.db, logfile.json are created in the current directory.

    """

    def __init__(self, directory):
        self.directory = directory
        # Take the path of the current directory.
        self.path = os.path.join(str(os.getcwd()), "logfile.db")
        self.logdata = []

    def find_pe_files(self, recpath='', rec=False):
        '''
        This function  try to find all files in ours path.
        The function supports absolute and relative paths.

        '''
        lst_find_files = []
        # Choosing the correct path.
        if not rec:
            # Path for directory without subdirectories.
            files_path = os.listdir(self.directory)
            file_dir = self.directory
        else:
            # Path for subdirectories.
            files_path = os.listdir(recpath)
            file_dir = recpath
        # Recursive directory bypass
        for next_file in files_path:
            # Create the path allowing for the Windows and Linux.
            path = os.path.join(file_dir, next_file)
            # If it's a file at the end of path, append to the list of paths.
            if not os.path.isdir(path):
                lst_find_files.append(path)
                # If it's a directory at the end of path,
                # find all files in this path.
            else:
                # Recursive going directories
                rec_dir = self.find_pe_files(recpath=path, rec=True)
                # Adds path of the subdirectories with the file.
                lst_find_files += rec_dir
        return lst_find_files

    def dump_pe_file(self, lst_files):
        '''
        This function  try dump information from PE files in ours path.
        If file is PE file write "OK" information to the logfile.bd.
        If file is PE file write "FAIL" information to the logfile.bd.

        '''
        count_id = 1
        for filepath in lst_files:
            data = []
            # Append id test
            data.append(count_id)
            count_id += 1
            # Create date and time like type - CARRENT_TIMESTAMP.
            time_now = datetime.strftime(datetime.now(), "%Y-%m-%d %H:%M:%S")
            # Append date and time of test create
            data.append(time_now)
            # Splitting a path to a file path, file name and file type.
            if filepath.find("/") != -1:
                dir_file = filepath.rpartition("/")
            else:
                dir_file = filepath.rpartition("\\")
            file_path = (dir_file[0] + dir_file[1])
            name_type = dir_file[-1].split(".")
            # Append file name
            file_name = name_type[0]
            data.append(file_name)
            # Append file type
            file_type = name_type[1]
            data.append(file_type)
            # Append file path
            data.append(file_path)
            # Dump information from PE file.
            try:
                pef = pefile.PE(filepath, fast_load=True)
                # The test result is OK
                data.append("OK")
                # Crash report - NULL
                data.append("NULL")
                # Append PE file dump
                data.append(str(pef.dump_info()))
                # Save the result of the whole test.
                self.logdata.append(tuple(data))
            except pefile.PEFormatError as detail:
                # The test result is Fail
                data.append("pefile.PEFormatError")
                # Crash report - Fail details
                data.append(str(detail))
                # Append PE file dump - NULL
                data.append("NULL")
                # Save the result of the whole test.
                self.logdata.append(tuple(data))
                continue
            except TypeError as detail1:
                # The test result is Fail
                data.append("TypeError")
                # Crash report - Fail details
                c_report = "Perhaps you are using python 2.x on Windows. " + \
                    str(detail1)
                data.append(str(c_report))
                # Append PE file dump - NULL
                data.append("NULL")
                # Save the result of the whole test.
                self.logdata.append(tuple(data))
                continue
        return self.logdata

    def create_table(self):
        '''
        This function create a table -> logfile.db.
        The table has the following attributes: test_id,
        date_time, name_file, type_file, path_file, test_result,
        crash_report, pe_file_dump.

        '''
        # Connect to sqlite3, сreate logfile.db in the current directory.
        conn = sqlite3.connect(self.path)
        cur = conn.cursor()
        # Create the table logfile
        cur.execute('''create table if not exists logfile (test_id INTEGER, date_time TEXT,
					name_file TEXT, type_file TEXT, path_file TEXT,
					test_result TEXT, crash_report TEXT, pe_file_dump TEXT)''')
        for tuple_data in self.logdata:
            cur.execute(
                'insert into logfile values (?,?,?,?,?,?,?,?)',
                tuple_data)
            conn.commit()
        cur.close()

    def db_to_json(self):
        '''
        This function create a json file - "logfile.json".
        The file has the following keys: test_id,
        date_time, name_file, type_file, path_file, test_result,
        crash_report, pe_file_dump.

        '''
        def dict_factory(cur, row):
            """
            Create data of the table to the dictionary with attributes as keys.

            """
            dic = {}
            for idx, col in enumerate(cur.description):
                dic[col[0]] = row[idx]
            return dic
        # Connect to sqlite3, import logfile.db from the current directory.
        conn = sqlite3.connect(self.path)
        conn.row_factory = dict_factory
        cur = conn.cursor()
        # Take whole data from the logfile.db
        cur.execute('select * from logfile')
        result = cur.fetchall()
        # Generate a report on the information collected
        # in the form of json file.
        with open(os.path.join(str(os.getcwd()), "logfile.json"), 'w') as outfile:
            json.dump(result, outfile)
        cur.close()
        return json.dumps(result)


if __name__ == '__main__':
    # Start dumping information with the path from the console.
    INF = InfoDumper(sys.argv[1])
    # Find all files in directory.
    LST_FILES = INF.find_pe_files()
    # Dump information from PE files.
    INF.dump_pe_file(LST_FILES)
    # Create table -> logfile.db.
    INF.create_table()
    # Generate a report -> logfile.json.
    INF.db_to_json()
