#!/usr/bin/env python3
'''
@author: Matthew C. Jones, CPA, CISA, OSCP
Symphona LLP

Core functions for autoenum

See README.md for licensing information and credits

'''
import sys
import os
import shutil
import subprocess

# exit routine
def exit_program():
    print("\n\nQuitting...\n")
    sys.exit()
    
# cleanup old or stale files
def cleanup_routine(output_dir):
    '''Returns 'False' if the output directory is dirty and users select not to clean'''
    
    try:
        if not os.listdir(output_dir) == []:
            response = input("\nOutput directory is not empty - delete existing contents? (enter no if you want to append data to existing output files)? [no] ")
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
        print("Specified config file not found. Copying example config file...")
        shutil.copyfile("config/default.example", config_file)

def execute(command, suppress_stdout=False):
    '''
    Execute a shell command and return output as a string
    
    By default, shell command output is also displayed in standard out, which can be suppressed
    with the boolean suppress_stdout
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

    except KeyboardInterrupt:
        print("\n[!] Keyboard Interrupt - command '%s' killed..." % command)
        print("[!] Continuing script execution...")
        return ""

    except Exception as exception:
        print("\n[!] Error running command '%s'" % command)
        print("[!] Exception: %s" % exception)
        return ""

if __name__ == '__main__':
    #self test code goes here!!!
    pass