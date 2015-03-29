#!/usr/bin/env python
'''
@author: Matthew C. Jones, CPA, CISA, OSCP
IS Audits & Consulting, LLC
TJS Deemer Dana LLP

Nmap scanning functions for autoenum

See README.md for licensing information and credits

'''

import time
import datetime
import logging
import os
import subprocess
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException
#from libnmap.objects import NmapReport

def run_nmap_scan(scan_targets, scan_options):
    '''
    Accepts scan targets and scan options for NmapProcess and launches scan
    Prints scan status updates and summary to stdout
    Returns NmapProcess object for further use
    
    TODO - catch keyboard interrupts and kill tasks so we can exit gracefully!
            nmap_proc.stop does not appear to fully kill threads in script scans
            so program will continue to execute but leaves an orphaned nmap process
    '''
    status_update_interval = 5
    
    #Check for sudo and disable scan options that require root
    if os.getuid()!=0:
        logging.warn("Certain nmap scans require root privileges (SYN, UDP, ICMP, etc)...")
        logging.warn("Disabling incompatible scan types and OS / service version detection options if enabled")
        scan_options = scan_options.replace("-sS", "-sT")
        scan_options = scan_options.replace("-sU", "")
        scan_options = scan_options.replace("-sP", "")
        scan_options = scan_options.replace("-sn", "")
        scan_options = scan_options.replace("-sV", "")
        scan_options = scan_options.replace("-O", "")
    
    nmap_proc = NmapProcess(targets=scan_targets, options=scan_options)
    print "Running scan command:\n"+nmap_proc.command
    nmap_proc.run_background()
    
    while nmap_proc.is_running():
        try:
            time.sleep(status_update_interval)
            
            if nmap_proc.progress > 0:
                
                #Nmap only updates ETC periodically and will sometimes return a result that is behind current system time
                etctime = datetime.datetime.fromtimestamp(int(nmap_proc.etc))
                systime = datetime.datetime.now().replace(microsecond=0)
                if etctime < systime:
                    etctime = systime
                timeleft = etctime - systime
                print("{0} Timing: About {1}% done; ETC: {2} ({3} remaining)".format(nmap_proc.current_task.name, nmap_proc.progress, etctime, timeleft))
        except KeyboardInterrupt:
            print "Keyboard Interrupt - Killing Current Nmap Scan!"
            nmap_proc.stop()
        
    if nmap_proc.rc == 0:
        print nmap_proc.summary + "\n"
    else:
        print nmap_proc.stderr + "\n"
    
    return nmap_proc

def nmap_out_to_html(scan_object, output_dir, filename):
    '''
    accepts an NmapProcess scan object and exports the scan results to HTML
    Currently works by echoing the XML from the NmapProcess.stdout into xsltproc via pipe
    
    TODO - find a more pythonic way to do this instead of relying on xsltproc!
    '''
    
    p1 = subprocess.Popen(['echo', scan_object.stdout], stdout=subprocess.PIPE) #Set up the echo command and direct the output to a pipe
    p2 = subprocess.Popen(['xsltproc', '-o' , os.path.join(output_dir,filename), "-"], stdin=p1.stdout) #send p1's output to p2
    p1.stdout.close() #make sure we close the output so p2 doesn't hang waiting for more input
    output = p2.communicate()[0] #run our commands

def nmap_parse_ports_by_host(scan_output):
    '''Accepts nmap scan output XML and returns a dict of hosts and tuples of corresponding
        open ports; only live hosts and open ports should be returned.
    
        e.g. {'192.168.0.171': [(80, 'tcp'), (111, 'tcp')]}
    
    '''
    try:
        hosts={}
        parsed = NmapParser.parse(scan_output)
        
        for host in parsed.hosts:
            if host.is_up():
                hosts[host.address] =  host.get_open_ports()
        
        return hosts
    except:
        print "\n[!] Error parsing scan output"
        
def nmap_parse_hosts_by_port(scan_output):
    '''Accepts nmap scan output XML and returns a dict of open ports and lists of the corresponding
        hosts with these ports open; only live hosts and open ports should be returned.
        
        e.g. {(80, 'tcp'): ['192.168.0.171'], (111, 'tcp'): ['192.168.0.169', '192.168.0.171']} 
    '''
    try:
        parsed = NmapParser.parse(scan_output)
        
        hosts={}    #e.g. {'192.168.0.171': [(80, 'tcp'), (111, 'tcp')]}
        ports={}    #e.g. {(80, 'tcp'): ['192.168.0.171'], (111, 'tcp'): ['192.168.0.169', '192.168.0.171']}
        
        for host in parsed.hosts:
            if host.is_up():
                host_ports =  host.get_open_ports()
                hosts[host.address] = host_ports
                for port in host_ports:
                    ports.setdefault(port,[]).append(host.address)
        
        return ports
    except:
        print "\n[!] Error parsing scan output"

def nmap_parse_webhosts(scan_output):
    '''Accepts nmap scan output XML and returns text output suitable for passing to Nikto
        
        e.g:
        192.168.1.100:80
        192.168.1.101:8080
    '''
    
    try:
        webhosts = ""
        parsed = NmapParser.parse(scan_output)
        
        for host in parsed.hosts:
            if host.is_up():
                services = host.services
                for service in services:
                    if (service.state == "open") and (service.service[:4]) == "http":
                        webhosts += host.address+":"+str(service.port)+"\n"
        
        return webhosts
    
    except:
        print "\n[!] Error parsing scan output"
        
def nmap_parse_live_hosts(scan_output):
    '''Accepts nmap scan output XML and returns a list of all live hosts

    '''
    
    try:
        live_hosts = []
        parsed = NmapParser.parse(scan_output)
        
        for host in parsed.hosts:
            if host.is_up():
                logging.debug ("live host detected - " + host.address)
                live_hosts.append(host.address)
        
        return live_hosts
    except:
        print "\n[!] Error parsing scan output"
                
    
if __name__ == '__main__':
    #self test code goes here!!!
    target = "localhost"
    scan_output = run_nmap_scan(target, "-sT").stdout
    
    hosts = nmap_parse_ports_by_host(scan_output)
    ports = nmap_parse_hosts_by_port(scan_output)
    webhosts = nmap_parse_webhosts(scan_output)
    print "Host array\n"+str(hosts)
    print "\nPort array \n"+str(ports)
    print "\nWebhosts \n"+ webhosts
