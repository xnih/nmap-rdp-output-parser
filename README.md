I needed to start looking for systems that had RDP enabled and determine quickly if they had NLA enabled, low/med/high/fips, etc.  The NLA is a "guess" based on certain attribute settings only with the nmap script.

The script assumes a "well formated" .xml file from nmap, specifically running the script rdp-enum-encryption:
nmap -p3389 --script rdp-enum-encryption 10.0.0.0/22 -oX 10-22.xml

Running it:
python nmap-rdp.py -f 10-22.xml

Input File: 10-22.xml
Output File: nmap-rdp-scan-output.html


output will be html table format, so you can import into excel to modify to your hearts content.
