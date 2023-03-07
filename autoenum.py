#!/usr/bin/env python3
'''
@author: Matthew C. Jones, CPA, CISA, OSCP
Symphona LLP

Enumeration and script scanning automation script

See README.md for licensing information and credits

'''
import configparser
import argparse
import logging
import time
import datetime
import subprocess
import os

import modules.core
import modules.nmap
import modules.output

#Change the working directory to the main program directory just in case...
os.chdir(os.path.dirname(os.path.realpath(__file__)))

#------------------------------------------------------------------------------
# Configure Argparse to handle command line arguments
#------------------------------------------------------------------------------
desc = "Network enumeration and script scanning automation script"

parser = argparse.ArgumentParser(description=desc)
parser.add_argument('target', action='store',
                    help='Scan target'
)
parser.add_argument('-c','--config',
                    help='Configuration file. (default: config/default.cfg)',
                    action='store', default='config/default.cfg'
)
parser.add_argument('-o','--output',
                    help='Output directory (overrides default relative path: "output")',
                    action='store', default='output'
)
parser.add_argument('-q','--quiet',
                    help='Quiet scan (no service scans, nikto, etc)',
                    action='store_true'
)
parser.add_argument('-d','--debug',
                    help='Print lots of debugging statements',
                    action="store_const",dest="loglevel",const=logging.DEBUG,
                    default=logging.WARNING
)
parser.add_argument('-v','--verbose',
                    help='Be verbose',
                    action="store_const",dest="loglevel",const=logging.INFO
)
args = parser.parse_args()

target = args.target
config_file = args.config
output_dir = args.output
quiet = args.quiet

logging.basicConfig(level=args.loglevel)
logging.info('verbose mode enabled')
logging.debug('Debug mode enabled')

#------------------------------------------------------------------------------
# Get general config file parameters
#------------------------------------------------------------------------------
modules.core.check_config(config_file)
config = configparser.ConfigParser()
config.read(config_file)

try:
    output_dir_info = os.path.join(output_dir, config.get("main_config", "output_dir_info"))
    output_dir_nmap_xml = os.path.join(output_dir, config.get("main_config", "output_dir_nmap_xml"))
    output_dir_nmap_enum = os.path.join(output_dir, config.get("main_config", "output_dir_nmap_enum"))
    output_dir_service_info = os.path.join(output_dir, config.get("main_config", "output_dir_service_info"))
    output_dir_target_lists = os.path.join(output_dir, config.get("main_config", "output_dir_target_lists"))
except:
    print("Missing required config file sections. Check running config file against provided example\n")
    modules.core.exit_program()
    
#------------------------------------------------------------------------------
# Main Program
#------------------------------------------------------------------------------

#Wait a sec for debug messages to display
time.sleep(1)

#Check target input
if "," in target:
    print("Commas found in input target list and will not parse correctly in libnmap")
    modules.core.exit_program()

#Check root
if os.getuid()!=0:
    print("Script not running as root...this breaks stuff with nmap...")
    response = input("Are you sure you wish to continue?!? [no]")
    if "y" in response or "Y" in response:
        pass
    else:
        modules.core.exit_program()

is_output_dir_clean = modules.core.cleanup_routine(output_dir)

timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H.%M.%S")

# Log scan info to history file
if os.path.exists(os.path.join(output_dir_info, "scan_history.csv")):
    output_text = ""
else:
    output_text = "Timestamp,Scan Target,Config\n"
    
output_text += timestamp + "," + target + "," + config_file + "\n"
modules.output.write_outfile(output_dir_info, "scan_history.csv", output_text)

#------------------------------------------------------------------------------
# Live host detection scan

if os.getuid()!=0:
    logging.warn("Script not running as root which prevents proper live host detection...")
    logging.warn("We will continue and scan all targets, but you should really re-run as root!")
else:
    print("Scanning for live hosts in specified target range...")
    scan_options = config.get("scan_config", "live_hosts")
    live_host_scan = modules.nmap.run_nmap_scan(target, scan_options)
    
    outfile_name = "nmap_live_host_scan_"+timestamp
    modules.nmap.nmap_out_to_html(live_host_scan, output_dir_nmap_enum, outfile_name+".html")
    modules.output.write_outfile(output_dir_nmap_xml, outfile_name+".xml", live_host_scan.stdout)
    
    live_hosts = modules.nmap.nmap_parse_live_hosts(live_host_scan.stdout)
    logging.debug(live_hosts)

    modules.output.write_target_list(live_hosts, os.path.join(output_dir,"target_lists"))
    target = live_hosts

#------------------------------------------------------------------------------
# Service enumeration scan

print("Performing initial enumeration scan on live hosts...")

scan_options = config.get("scan_config", "tcp_enum")
tcp_enum_scan = modules.nmap.run_nmap_scan(target, scan_options)
scan_output = tcp_enum_scan.stdout
outfile_name = "nmap_tcp_enum_scan_"+timestamp
modules.nmap.nmap_out_to_html(tcp_enum_scan, output_dir_nmap_enum, outfile_name+".html")
modules.output.write_outfile(output_dir_nmap_xml, outfile_name+".xml", tcp_enum_scan.stdout)

hosts = modules.nmap.nmap_parse_ports_by_host(scan_output)
ports = modules.nmap.nmap_parse_hosts_by_port(scan_output)
webhosts = modules.nmap.nmap_parse_webhosts(scan_output)

scan_options = config.get("scan_config", "udp_enum")
udp_enum_scan = modules.nmap.run_nmap_scan(target, scan_options)
scan_output = udp_enum_scan.stdout
outfile_name = "nmap_udp_enum_scan_"+timestamp
modules.nmap.nmap_out_to_html(udp_enum_scan, output_dir_nmap_enum, outfile_name+".html")
modules.output.write_outfile(output_dir_nmap_xml, outfile_name+".xml", udp_enum_scan.stdout)

hosts.update(modules.nmap.nmap_parse_ports_by_host(scan_output))
ports.update(modules.nmap.nmap_parse_hosts_by_port(scan_output))

logging.debug(hosts)
logging.debug(ports)
logging.debug(webhosts)

modules.output.write_target_lists_by_port(ports, output_dir_target_lists)
modules.output.write_outfile(output_dir_target_lists, "all_webhosts.txt", webhosts)

if not quiet:
    #------------------------------------------------------------------------------
    # Nmap script scans

    #Loop through script scan config file sections and perform script scans
    for section in config.sections():
        #skip over to the script scan sections
        if section == "scan_config" or section == "main_config":
            pass
        else:
            scan_options = config.get("scan_config","script")
            config_ports = config.get(section, "ports")
            config_scripts = config.get(section, "scripts")
            if config.has_option(section, "scan_args"):
                config_scan_args = config.get(section, "scan_args")
            else: config_scan_args = ""
            if config.has_option(section, "script_args"):
                config_script_args = config.get(section, "script_args")
            else: config_script_args = ""
        
            target_list = []
            
            for config_port in map(int,config_ports.split(",")):    #convert ports from to int using map function
                logging.debug(config_port)

                #Loop through the port dictionary and look for each port from the service scan config. If
                #present, then add all hosts associated to the target list for this service scan
                for key,value in ports.items():
                    if config_port in key:
                        for host in ports[key]:
                            logging.debug(host)
                            target_list.append(host)
            target_list = list(set(target_list))                    #convert list to set and back to remove duplicates
            logging.debug(target_list)
            
            if target_list:
                #Target list is not empty - proceed with script scan
                print("Script scanning from config file section " + section + "...\n")
                        
                
                if config_scan_args:
                    scan_options += " " + config_scan_args
                scan_options += " -p"+config_ports
                scan_options += " --script "+config_scripts
                if config_script_args:
                    scan_options += " --script-args "+config_script_args
                
                script_scan = modules.nmap.run_nmap_scan(target_list, scan_options)
                
                outfile_name = section+"_"+timestamp
                modules.nmap.nmap_out_to_html(script_scan, output_dir_service_info, outfile_name+".html")
                modules.output.write_outfile(output_dir_nmap_xml, outfile_name+".xml", script_scan.stdout)
                
            else:
                print("No "+section+" services found during enumeration scan...skipping...\n")


    #------------------------------------------------------------------------------
    # Other scans

    if webhosts:
        run_nikto_scan =input("\nWebhosts detected - run Nikto scan? [yes] ")
        if "n" in run_nikto_scan or "N" in run_nikto_scan:
            pass
        else:
            path = output_dir_service_info
            if not os.path.exists(path):
                os.makedirs(path)
            try:
                p1 = subprocess.Popen(['echo', webhosts], stdout=subprocess.PIPE) #Set up the echo command and direct the output to a pipe
                p2 = subprocess.Popen(['nikto','-h', '-', '-o' , os.path.join(path, "http-nikto_"+timestamp+".html")], stdin=p1.stdout) #send p1's output to p2
                p1.stdout.close() #make sure we close the output so p2 doesn't hang waiting for more input
                output = p2.communicate()[0] #run our commands
            except KeyboardInterrupt:
                print("Keyboard Interrupt - Nikto Scan Operation Killed")
            except:
                print("Nikto could not be executed - ensure it is installed and in your path")


#------------------------------------------------------------------------------
# Wrap it all up

#Write html index of all output files
modules.output.write_html_index(output_dir, config)

#If output directory has old scans in it, merge target lists to prevent duplicates
if is_output_dir_clean == False:
    list_dir = output_dir_target_lists
    for fname in os.listdir(list_dir):
        output_text = ""
        fpath = os.path.join(list_dir, fname)
        lines = open(fpath,'r').read().splitlines()
        unique_lines = sorted(set(lines))
        for line in unique_lines:
            output_text += line + "\n"
        os.remove(fpath)
        modules.output.write_outfile(list_dir, fname, output_text)

#This is the end...beautiful friend...the end...
print("\nOutput files located at " + output_dir + " with timestamp " + timestamp)
