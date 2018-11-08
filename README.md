autoenum.py
===========

Enumeration scan automation script:

- Performs an initial Nmap scan to detect live hosts for enumeration and reduce subsequent scan times (more comprehensive than -sn)
- Performs Nmap service enumeration scans on live hosts; outputs to HTML
- Parses enumeration scan results and performs targeted Nmap script scans on open services
- Exports scan results to html files by service
- Generates target lists by port in text files for later use with other tools
    - Specific web host list generated in Nikto format (192.168.0.1:80)
- Optionally launches a Nikto scan on all detected web hosts and includes results in output directory

---------------------------------------------------------------------------------------------------
## Notes

All scan parameters are pulled from config files so multiple configurations can be developed for
internal vs. external networks or loud vs. quiet and specified with the -c flag.
An example config file (default.example) is included and will be copied into the default path (default.cfg) upon initial launch. 

Traditional Nmap target specifications using commas (e.g. 192.168.0.1-100,200,254) do not work properly
due to the way the python-libnmap parses targets with commas as tuples (thus separate hosts delimited by commas)

Script tested on Kali Linux as well as OSX and should function on UNIX-based systems with required dependencies.

---------------------------------------------------------------------------------------------------
## Dependencies

### Python Module Dependencies:
- python-libnmap (not installed on Kali Linux by default)
    - <https://github.com/savon-noir/python-libnmap>
    - <https://libnmap.readthedocs.org/en/latest/>

`pip install python-libnmap`


### Binary Dependencies (all installed on Kali Linux by default):
- Nmap
- Nikto (optional)

---------------------------------------------------------------------------------------------------
## Todo

- Move additional hard-coded stuff to config file
- Additional external service scan utilities like we have with Nikto
- Sessions
    - Re-use of live host and enum scans for multiple groups / verbosities of script scans
- Optional detection and exclusion of fragile devices such as printers
- Windows - find / remove OS dependencies
    - Nmap scan xml parsing via xsltproc (to Python)

---------------------------------------------------------------------------------------------------

Copyright 2014

Matthew C. Jones, CPA, CISA, OSCP

IS Audits & Consulting, LLC - <http://www.isaudits.com/>

TJS Deemer Dana LLP - <http://www.tjsdd.com/>

Concept based upon functionality observed in the LAN portion of the Kali Discover script by leebaird: <https://github.com/leebaird/discover/>

---------------------------------------------------------------------------------------------------

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <http://www.gnu.org/licenses/>.