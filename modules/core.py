#!/usr/bin/env python

import sys
import os
import shutil
import subprocess
import csv

# exit routine
def exit_program():
    print "\n\nQuitting...\n"
    sys.exit()
    
# cleanup old or stale files
def cleanup_routine(output_dir):
    '''Returns 'False' if the output directory is dirty and users select not to clean'''
    
    try:
        if not os.listdir(output_dir) == []:
            response = raw_input("\nOutput directory is not empty - delete existing contents? (enter no if you want to append data to existing output files)? [no] ")
            if "y" in response or "Y" in response:
                print("Deleting old output files...\n")
                shutil.rmtree(output_dir, True)
            else:             
                return False
    except:
        pass

def check_config(config_file):
    if os.path.exists(config_file):
        pass
    else:
        print "Specified config file not found. Copying example config file..."
        shutil.copyfile("config/default.example", config_file)

def execute(command, suppress_stdout=False):
    '''
    Execute a shell command and return output as a string
    
    By default, shell command output is also displayed in standard out, which can be suppressed
    with the boolean suppress_stdout
    
    TODO - catch keyboard interrupts and kill subprocesses so we can exit gracefully!
    '''
    
    output = ""
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    
        # Poll process for new output until finished
        while True:
            nextline = process.stdout.readline()
            output += nextline
            if nextline == '' and process.poll() != None:
                break
            if not suppress_stdout:
                sys.stdout.write(nextline)
            sys.stdout.flush()
        
        return output

    except Exception as exception:
        print '   [!] Error running command %s' % command
        print '   [!] Exception: %s' % exception

def write_outfile(path, filename, output_text):
    #path variable should be passed as relative path to working directory
    
    if not os.path.exists(path):
        os.makedirs(path)
        
    outfile = os.path.join(path, filename)
    
    file = open(outfile, 'a+')
    file.write(output_text)
    file.close

def write_target_lists_by_port(ports, output_dir):
    '''
    iterate through port array and write target lists to text files for each service
    which contain a list of all IP addresses with a corresponding open port
    
    Accepts dict output from nmap_parse_hosts_by_port as input
    e.g. {(80, 'tcp'): ['192.168.0.171'], (111, 'tcp'): ['192.168.0.169', '192.168.0.171']}
    
    '''
    for port,array in ports.iteritems():
        output_text = ""
        filename = port[1]+"_"+str(port[0])+'.txt'
        for host in array:
            output_text += host + "\n"
        write_outfile(output_dir, filename, output_text)
        
def write_target_list(hosts, output_dir):
    '''
    iterate through host list and write all hosts to a text file
    
    '''
    output_text = ""
    filename = "all_live_hosts.txt"
    for host in hosts:
        output_text += host + "\n"

    
    write_outfile(output_dir, filename, output_text)
    
def write_html_index(output_folder):
    '''
    write out an html index page containing links to all of the text files that are
    in the output directory
    '''
    if os.path.exists(os.path.join(output_folder,"index.html")):
        os.remove(os.path.join(output_folder,"index.html"))
    html_title = "Autoenum scan output"
    html_body = "<h1>"+html_title+"</h1>\n"
    
    html_body += "<h2>Scan history</h2>\n"
    html_body += "<table>\n"
    
    history_file = csv.reader(open(os.path.join(output_folder, "info", "scan_history.csv"), 'rb'))
    for row in history_file:
        html_body += "    <tr>\n"
        for cell in row:
            html_body += "        <td>" + cell + "</td>\n"
        html_body += "    </tr>\n"
    html_body += "</table>\n"
    
    html_body += "<h2>Enumeration results</h2>\n"
    
    try:
        directory = "enum_scans/"
        for fname in os.listdir(os.path.join(output_folder,directory)):
            html_body += " <a href='" + directory + fname + "'>" + fname + "</a><br>\n"
    except:
        pass
    
    
    html_body += "<br>\n"
    html_body += "<h2>Service scan results</h2>\n"
    
    try:
        directory = "services/"
        for fname in os.listdir(os.path.join(output_folder,directory)):
            html_body += " <a href='" + directory + fname + "'>" + fname + "</a><br>\n"
    except:
        pass
    
    html_body += "<br>\n"
    html_body += "<h2>Target Listings</h2>\n"
    
    try:
        directory = "target_lists/"
        for fname in os.listdir(os.path.join(output_folder,directory)):
            html_body += " <a href='" + directory + fname + "'>" + fname + "</a><br>\n"
    except:
        pass 
    
    input_file = open(os.path.join("templates","index.html"))
    html_out = input_file.read()
    html_out = html_out.replace("<!--title-->",html_title)
    html_out = html_out.replace("<!--body-->",html_body)
    write_outfile(output_folder, "index.html", html_out)

if __name__ == '__main__':
    #self test code goes here!!!
    write_html_index("../output/")