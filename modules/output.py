#!/usr/bin/env python3
'''
@author: Matthew C. Jones, CPA, CISA, OSCP
Symphona LLP

Output functions for autoenum

See README.md for licensing information and credits

'''

import os
import csv

def write_outfile(path, filename, output_text):
    
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
    for port,array in ports.items():
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
    
def write_html_index(output_dir, config):
    '''
    write out an html index page containing links to all of the various files that are
    in the output directory
    
    Accepts output_dir (string) and config (configparser object) from main script
    
    NOTE - output directory variables in main module are full paths, while these
            are folder names only; This is to allow building of relative href
            links in HTML output
    
    '''
    
    output_dir_info = config.get("main_config", "output_dir_info")
    output_dir_nmap_enum = config.get("main_config", "output_dir_nmap_enum")
    output_dir_service_info = config.get("main_config", "output_dir_service_info")
    output_dir_target_lists = config.get("main_config", "output_dir_target_lists")
    
    
    if os.path.exists(os.path.join(output_dir,"index.html")):
        os.remove(os.path.join(output_dir,"index.html"))
    html_title = "Autoenum scan output"
    html_body = "<h1>"+html_title+"</h1>\n"
    
    #-----------------------------------------------------------
    # Output session history table
    
    html_body += "<h2>Session history</h2>\n"
    html_body += "<table>\n"
    
    history_file = csv.reader(open(os.path.join(output_dir, output_dir_info, "scan_history.csv"), 'r'))
    
    headers = next(history_file)
    html_body += "    <tr>\n"
    for header in headers:
        html_body += "        <th>" + header + "</th>\n"
    html_body += "    </tr>\n"
    
    for row in history_file:
        html_body += "    <tr>\n"
        for cell in row:
            html_body += "        <td>" + cell + "</td>\n"
        html_body += "    </tr>\n"
    html_body += "</table>\n"
    
    #-----------------------------------------------------------
    # Output hyperlinks to Nmap enumeration scan reports
    
    html_body += "<h2>Enumeration results</h2>\n"
    
    try:
        directory = output_dir_nmap_enum +"/"
        for fname in os.listdir(os.path.join(output_dir,directory)):
            html_body += " <a href='" + directory + fname + "'>" + fname + "</a><br>\n"
    except:
        pass
    
    
    html_body += "<br>\n"
    
    #-----------------------------------------------------------
    # Output hyperlinks to Nmap service scans
    
    html_body += "<h2>Service scan results</h2>\n"
    
    try:
        directory = output_dir_service_info + "/"
        for fname in os.listdir(os.path.join(output_dir,directory)):
            html_body += " <a href='" + directory + fname + "'>" + fname + "</a><br>\n"
    except:
        pass
    
    html_body += "<br>\n"
    
    #-----------------------------------------------------------
    # Output hyperlinks to target list text files
    
    html_body += "<h2>Target Listings</h2>\n"
    
    try:
        directory = output_dir_target_lists + "/"
        for fname in os.listdir(os.path.join(output_dir,directory)):
            html_body += " <a href='" + directory + fname + "'>" + fname + "</a><br>\n"
    except:
        pass 
    
    #-----------------------------------------------------------
    # Output footer
    
    html_body += "<br><hr><br>\n"
    html_body += "Generated by autoenum enumeration script - "
    html_body += "<a href=https://github.com/isaudits/autoenum/>https://github.com/isaudits/autoenum/</a><br><br>\n"
    
    input_file = open(os.path.join("templates","index.html"))
    html_out = input_file.read()
    html_out = html_out.replace("<!--title-->",html_title)
    html_out = html_out.replace("<!--body-->",html_body)
    write_outfile(output_dir, "index.html", html_out)

if __name__ == '__main__':
    #self test code goes here!!!
    write_html_index("../output/")