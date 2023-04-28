#!/usr/bin/env python3
# coded by AuxGrep (MasterMind)
# 2023
# it's raining over here !! lets code
# Powerful Network pcaps analyzer 


import subprocess
from prettytable import PrettyTable
import sys
import os as f
import time
from banner import banner
import pymongo

# colr
BLACK = "\033[0;30m"
RED = "\033[0;31m"
GREEN = "\033[0;32m"
BROWN = "\033[0;33m"
BLUE = "\033[0;34m"
PURPLE = "\033[0;35m"
CYAN = "\033[0;36m"
LIGHT_GRAY = "\033[0;37m"
DARK_GRAY = "\033[1;30m"
LIGHT_RED = "\033[1;31m"
LIGHT_GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
LIGHT_BLUE = "\033[1;34m"
LIGHT_PURPLE = "\033[1;35m"
LIGHT_CYAN = "\033[1;36m"
LIGHT_WHITE = "\033[1;37m"
BOLD = "\033[1m"
FAINT = "\033[2m"
ITALIC = "\033[3m"
UNDERLINE = "\033[4m"
BLINK = "\033[5m"
NEGATIVE = "\033[7m"
CROSSED = "\033[9m"
END = "\033[0m"


menu = [
    f'{BOLD}Import {BOLD}{RED}{sys.argv[1]}{END}{BOLD} for investigation{END}',
    f'{BOLD}Longer Connection{END}',
    f'{BOLD}HTTP requests{END}',
    f'{BOLD}DNS and devices detection{END}',
    f'{BOLD}rita view{END}',
    f'{BOLD}{RED}Exit{END}'
    ]


banner()
def info():
    
    # Run the capinfos command and capture its output
    print(f'{YELLOW}{BOLD} GENERAL PCAP INFO == {sys.argv[1]}{END}')
    print('')
    print(f'{BOLD}{PURPLE}{ITALIC} ==> This will show you start and end capturing time of a given pcap, in our case is {sys.argv[1]}{END}')
    print('')
    result = subprocess.run(['capinfos', '-aeu', sys.argv[1]], stdout=subprocess.PIPE)
    output = result.stdout.decode()

    # Split the output into lines and create a PrettyTable object
    table = PrettyTable()
    table.field_names = [f'{BOLD}{CYAN}Field{END}', f'{BOLD}{CYAN}Value{END}']
    for line in output.split('\n'):
        if line:
            field, value = line.split(': ')
            table.add_row([field.strip(), value.strip()])
    # Print the table
    print(table)
    print('')

info()

def output():
    print(f'{BOLD}{BLUE}Main Menu{END}')
    for i, x in enumerate(menu, start=1):
                time.sleep(0.2)
                print(f'{i}. ==> {x}')
    print('')
output()

def extract_files():
    extract = subprocess.run(['zeek', '--no-checksums', '--readfile', sys.argv[1]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Now we have logfile let's make sure ops was succcessed by checking those files
    logs = [
        'dns.log',
        'http.log',
        'packet_filter.log',
        'ssl.log',
        'conn.log',
        'files.log',
        'ocsp.log',
        'x509.log'
    ]

    # create the log directory if it doesn't exist
    pcap_file = sys.argv[1].split('.')[0]
    if not f.path.exists(f'{pcap_file}'):
        f.mkdir(f'{pcap_file}')

    # move each log file to the log directory
    for x in logs:
        if f.path.isfile(x):
            f.rename(x, f'{pcap_file}/{x}')
        else:
            print(f'{x} not found in directory!! Exiting program!!')   

while True:
    try:
        print(f'{BOLD}{FAINT}Main_Menu: [0]clear [1]import pcap file [2]Longer connection hosts [3]HTTP requests made [4]DNS query [5]rita [6]Exit{END}')
        user_choose = int(input(f'{BOLD}{BROWN}[<{sys.argv[1]}>]: Enter ID to view table DAta:{END} '))
        if user_choose > len(menu):
            print('')
            print(f'{BOLD}{RED}Invalid ID! Kindly choose id from 1 to {len(menu)}{END}')
            continue
        elif user_choose == int(1):
            print(f'{BOLD}{GREEN}{sys.argv[1]} successful Imported [✔]{END}')
            time.sleep(3)
            f.system('clear')
            extract_files()
            output()
            
            
        elif user_choose == int(6):
            f.system('clear')
            print(f'{BOLD}{RED}Exit command detected !! See you next time{END}')
            break
        
        
        elif user_choose == int(0):
            f.system('clear')
            output()
            
            
        elif user_choose == int(2):
            f.system('clear')
            print('')
            check_in = sys.argv[1].split('.')[0]
            if f.path.isfile(f'{check_in}/conn.log') == True:
                pass
            else:
                f.system('clear')
                print(f'ERROR:{BOLD}{RED}{ITALIC}{ITALIC}You need to import the pcap file first{END}')
                time.sleep(3)
                output()
                continue
            
            
            output()       
            # Analyse network connection made
            print(f'{BOLD}{YELLOW}LONGER CONNECTION HOSTS DETECTED IN {sys.argv[1]}{END}')
            print('')
            print(f'{BOLD}{PURPLE}{ITALIC} ==> Below are the hosts with longer connection to the server, its recommended to note down for investigations.{END}')
            print(f'{BOLD}{PURPLE}{ITALIC} ==> Most of remote network malwares they have longest connection to maintain its persistences capabilities.{END}')
            print(f'{BOLD}{PURPLE}{ITALIC} ==> Its better to oversee and note down all foreign IPs with maximum time for investigations{END}')
            print('')


            def display_conn_table(pcap_file): 
                pcap_file = pcap_file.split('.')[0]
                conn_output = subprocess.check_output(f"cat {pcap_file}/conn.log | zeek-cut id.orig_h id.orig_p id.resp_h id.resp_p duration | sort | grep -v '-' | \
                    grep -v '^$' | datamash -g 1,2,3,4 sum 5 | sort -k5rn", shell=True)
                conn_lines = conn_output.decode().splitlines()

                # create a PrettyTable instance with the column names
                table = PrettyTable([f'{BOLD}{CYAN}Source IP{END}', f'{BOLD}{CYAN}Source Port{END}', f'{BOLD}{CYAN}Destination IP{END}', f'{BOLD}{CYAN}Destination_Port{END}', f'{BOLD}{CYAN}Duration (h:m:s){END}'])

                # add each row to the table
                for line in conn_lines:
                    row = line.split()
                    duration_seconds = int(float(row[-1]))
                    duration_hours = duration_seconds // 3600
                    duration_minutes = (duration_seconds % 3600) // 60
                    duration_seconds = duration_seconds % 60
                    row[-1] = f"{duration_hours:02d}:{duration_minutes:02d}:{duration_seconds:02d}"
                    table.add_row(row)

                # add red to the highest duration row
                max_duration = float(conn_lines[0].split()[4])
                max_row = None
                for row in table._rows:
                    if float(row[-1].replace(':', '')) == max_duration:
                        max_row = row
                        for i in range(len(row)):
                            row[i] = f"{RED}{row[i]}{END}"
                        break

                # print the table
                print(table)
            display_conn_table(sys.argv[1])

        elif user_choose == int(3):
            # check if user has import the pcap file 
            check_in = sys.argv[1].split('.')[0]
            if f.path.isfile(f'{check_in}/http.log') == True:
                pass
            else:
                f.system('clear')
                print(f'{BOLD}{RED}{ITALIC}ERROR:You need to import the pcap file first{END}')
                print('')
                time.sleep(3)
                output()
                continue
            
            
            def http(pcap_file):
                base_name, ext = f.path.splitext(pcap_file)
                print('')
                print(f'{BOLD}{YELLOW}HTTP request detected from the {base_name}{ext}{END}')
                
                # Run the command and capture its output
                command = f"cat {base_name}/http.log | zeek-cut id.orig_h id.orig_p id.resp_h id.resp_p host uri resp_filenames method | sort | uniq -c"
                con = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
                conn_lines = con.stdout.splitlines()

                # Create a new PrettyTable object
                table = PrettyTable([f"{BOLD}{CYAN}Count{END}", f"{BOLD}{CYAN}Source IP{END}", f"{BOLD}{CYAN}Src POrt{END}", f"{BOLD}{CYAN}Destination IP{END}", \
                    f"{BOLD}{CYAN}Dst_port{END}", f"{BOLD}{CYAN}host{END}", \
                    f"{BOLD}{CYAN}uri{END}", f"{BOLD}{CYAN}Filename{END}", f"{BOLD}{CYAN}method{END}"])

                # Loop through the lines of output and add each one to the table
                for line in conn_lines:
                    parts = line.split()
                    count = parts[0]
                    fields = parts[1:]
                    table.add_row([count] + fields)

                # Print the table
                print(table)
            http(sys.argv[1])
            
        elif user_choose == int(4): 
            
            # check if user has successfully import the pcap
            check_in = sys.argv[1].split('.')[0]
            if f.path.isfile(f'{check_in}/dns.log') == True:
                pass
            else:
                f.system('clear')
                print(f'ERROR:{BOLD}{RED}{ITALIC}{ITALIC}You need to import the pcap file first{END}')
                print('')
                time.sleep(3)
                output()
                continue  
            
                    
            def DNS(pcap_file):
                print('')
                print(f'{BOLD}{YELLOW}DNS QUERIES + INFECTED DEVICES{END}\n')
                print(f'{BOLD}{PURPLE}{ITALIC}==> The following are the DNS detected from {sys.argv[1]}{END}')
                base_name, ext = f.path.splitext(pcap_file)
                xz = f"cat {base_name}/dns.log | zeek-cut id.orig_h id.orig_p id.resp_h id.resp_p query | sort | uniq -c"
                con = subprocess.run(xz, shell=True, check=True, capture_output=True, text=True)
                conn_lines = con.stdout.splitlines()

                # Create a PrettyTable object and add columns
                table = PrettyTable()
                table.field_names = [f'{BOLD}{CYAN}Count{END}', f'{BOLD}{CYAN}Source IP{END}', f'{BOLD}{CYAN}Source Port{END}', f'{BOLD}{CYAN}Dest. IP{END}', f'{BOLD}{CYAN}Dest. Port{END}', f'{BOLD}{CYAN}DNS{END}']

                # Add rows to the table
                for line in conn_lines:
                    count, src_ip, src_port, dest_ip, dest_port, query = line.split()
                    table.add_row([count, src_ip, src_port, dest_ip, dest_port, query])

                # Print the table
                print(table)

            # Call the DNS function with the command line argument
            DNS(sys.argv[1])
            
        elif user_choose == 5:
            f.system('clear')
            db_file = sys.argv[1].split('.')[0]
            print('Preparing DATABASE for RITA and MongoDB')
            print('Checking MongoDB... Please wait.')
            try:
                client = pymongo.MongoClient()
                client.server_info()
                time.sleep(4)
                print("MongoDB is running.")
                print(f'Importing the database files: {db_file}')
                time.sleep(2)

                # Check if MongoDB is running
                mongo_running = subprocess.run(["systemctl", "is-active", "mongod"], capture_output=True, text=True).stdout.strip()

                # Check if MongoDB is inactive
                if mongo_running == "inactive":
                    # If MongoDB is not running, start it
                    subprocess.run(["sudo", "systemctl", "start", "mongod"], check=True)

                # Import the database files to RITA
                db_path = f.path.abspath(db_file)
                subprocess.run(["rita", "import", db_path, f"DB-{db_file}"], check=True)

                f.system('clear')
                print(f'Starting to export the {db_file} files...')
                subprocess.run(["rita", "html-report", db_file, db_file], check=True)
            except pymongo.errors.ConnectionFailure as e:
                print("MongoDB is not running.")
                time.sleep(2)
                print('Starting MongoDB...')
                subprocess.run(['systemctl', 'start', 'mongod'], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
                print('')
                print('')
    except Exception as e:
        f.system('clear')
        print('We got some errors')
        sys.exit(e)