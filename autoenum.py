#!/usr/bin/env python
'''
@author: Matthew C. Jones, CPA, CISA, OSCP
IS Audits & Consulting, LLC
TJS Deemer Dana LLP

Enumeration and script scanning automation script

See README.md for licensing information and credits

'''
import ConfigParser
import argparse
import logging
import time
import datetime
import subprocess

from modules.core import *
from modules.nmap import * 



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

logging.basicConfig(level=args.loglevel)
logging.info('verbose mode enabled')
logging.debug('Debug mode enabled')


#------------------------------------------------------------------------------
# Main Program
#------------------------------------------------------------------------------

#Wait a sec for debug messages to display
time.sleep(1)

#Check root
if os.getuid()!=0:
    print ("Script not running as root...this breaks stuff with nmap...")
    response = raw_input("Are you sure you wish to continue?!? [no]")
    if "y" in response or "Y" in response:
        pass
    else:
        exit_program()

is_output_dir_clean = cleanup_routine(output_dir)

check_config(config_file)
config = ConfigParser.SafeConfigParser()
config.read(config_file)

timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H.%M.%S")

#------------------------------------------------------------------------------
# Live host detection scan

if os.getuid()!=0:
    logging.warn("Script not running as root which prevents proper live host detection...")
    logging.warn("We will continue and scan all targets, but you should really re-run as root!")
else:
    print "Scanning for live hosts in specified target range..."
    scan_options = config.get("scan_config", "live_hosts")
    live_host_scan = run_nmap_scan(target, scan_options)
    
    outfile_name = "nmap_live_host_scan_"+timestamp
    nmap_out_to_html(live_host_scan, output_dir, outfile_name+".html")
    write_outfile(os.path.join(output_dir,"nmap_xml"), outfile_name+".xml", live_host_scan.stdout)
    
    live_hosts = nmap_parse_live_hosts(live_host_scan.stdout)
    logging.debug(live_hosts)

    write_target_list(live_hosts, os.path.join(output_dir,"target_lists"))
    target = live_hosts

#------------------------------------------------------------------------------
# Service enumeration scan

print "Performing initial enumeration scan on live hosts..."

scan_options = config.get("scan_config", "tcp_enum")
tcp_enum_scan = run_nmap_scan(target, scan_options)
scan_output = tcp_enum_scan.stdout
outfile_name = "nmap_tcp_enum_scan_"+timestamp
nmap_out_to_html(tcp_enum_scan, output_dir, outfile_name+".html")
write_outfile(os.path.join(output_dir,"nmap_xml"), outfile_name+".xml", tcp_enum_scan.stdout)

hosts = nmap_parse_ports_by_host(scan_output)
ports = nmap_parse_hosts_by_port(scan_output)
webhosts = nmap_parse_webhosts(scan_output)

scan_options = config.get("scan_config", "udp_enum")
udp_enum_scan = run_nmap_scan(target, scan_options)
scan_output = udp_enum_scan.stdout
outfile_name = "nmap_udp_enum_scan_"+timestamp
nmap_out_to_html(udp_enum_scan, output_dir, outfile_name+".html")
write_outfile(os.path.join(output_dir,"nmap_xml"), outfile_name+".xml", udp_enum_scan.stdout)

hosts.update(nmap_parse_ports_by_host(scan_output))
ports.update(nmap_parse_hosts_by_port(scan_output))

logging.debug(hosts)
logging.debug(ports)
logging.debug(webhosts)

write_target_lists_by_port(ports, os.path.join(output_dir,"target_lists"))
write_outfile(os.path.join(output_dir,"target_lists"), "all_webhosts.txt", webhosts)


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
            for key,value in ports.iteritems():
                if config_port in key:
                    for host in ports[key]:
                        logging.debug(host)
                        target_list.append(host)
        target_list = list(set(target_list))                    #convert list to set and back to remove duplicates
        logging.debug(target_list)
        
        if target_list:
            #Target list is not empty - proceed with script scan
            print "Script scanning from config file section " + section + "...\n"        
                    
            
            if config_scan_args:
                scan_options += " " + config_scan_args
            scan_options += " -p"+config_ports
            scan_options += " --script "+config_scripts
            if config_script_args:
                scan_options += " --script-args "+config_script_args
            
            script_scan = run_nmap_scan(target_list, scan_options)
            
            outfile_name = section+"_"+timestamp
            nmap_out_to_html(script_scan, os.path.join(output_dir,"services"), outfile_name+".html")
            write_outfile(os.path.join(output_dir,"nmap_xml"), outfile_name+".xml", script_scan.stdout)
            
        else:
            print "No "+section+" services found during enumeration scan...skipping...\n"


#------------------------------------------------------------------------------
# Other scans

if webhosts:
    run_nikto_scan = raw_input("\nWebhosts detected - run Nikto scan? [yes] ")
    if "n" in run_nikto_scan or "N" in run_nikto_scan:
        pass
    else:
        path = os.path.join(output_dir, "services")
        if not os.path.exists(path):
            os.makedirs(path)
        try:
            p1 = subprocess.Popen(['echo', webhosts], stdout=subprocess.PIPE) #Set up the echo command and direct the output to a pipe
            p2 = subprocess.Popen(['nikto','-h', '-', '-o' , os.path.join(path, "http-nikto_"+timestamp+".html")], stdin=p1.stdout) #send p1's output to p2
            p1.stdout.close() #make sure we close the output so p2 doesn't hang waiting for more input
            output = p2.communicate()[0] #run our commands
        except KeyboardInterrupt:
            print "Keyboard Interrupt - Nikto Scan Operation Killed"
        except:
            print "Nikto could not be executed - ensure it is installed and in your path"


#------------------------------------------------------------------------------
# Wrap it all up

#Write html index of all output files
write_html_index(output_dir)

#If output directory has old scans in it, merge target lists to prevent duplicates
if is_output_dir_clean == False:
    list_dir = os.path.join(output_dir, "target_lists")
    for fname in os.listdir(list_dir):
        output_text = ""
        fpath = os.path.join(list_dir, fname)
        lines = open(fpath,'r').read().splitlines()
        unique_lines = sorted(set(lines))
        for line in unique_lines:
            output_text += line + "\n"
        os.remove(fpath)
        write_outfile(list_dir, fname, output_text)

#This is the end...beautiful friend...the end...
print "\nOutput files located at " + output_dir + " with timestamp " + timestamp
