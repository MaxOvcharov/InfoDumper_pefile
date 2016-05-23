# info_dump_pefile
This script produces a test for the ability to dump information from PE files: 
  - Runs the test for the specified directory with  files (finds all files in ours path); 
  - Stores information in the database -> logfile.db (creates a table (logfile.db) with data from dump_pe_file method); 
  - Generates a report about collected information -> logfile.json (creates a json file (logfile.json) from database (logfile.db));
The files logfile.db, logfile.json are created in the current directory. 
For running this script type: python info_dumper.py <DIRECTORY>

P.s: This script supports absolute and relative paths and works on Windows and Linux

