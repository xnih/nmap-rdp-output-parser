import argparse, datetime
import os
import sys
import re
from xml.dom import minidom
parser = argparse.ArgumentParser(prog='nmap-rdp.py', usage='%(prog)s {-f file} [-o output_file]')
parser.add_argument("-f", "--file", type=str, required=True, help="Parse a single Nmap .xml output file")
parser.add_argument("-o", "--output", type=str, help="Filename of output file for HTML report")
args = parser.parse_args()

#Check and create input and output files
if not os.path.isfile(args.file):
  print '\nThere was an error opening file: %s' % args.file
  sys.exit()

if args.output:
  if args.output.endswith('.html'):
    outFile = open(args.output, 'w')
  else:
    outFile = open(args.output + '.html', 'w')
else:
  outFile = open('nmap-rdp-scan-output.html', 'w')

xmlDoc = minidom.parse(args.file)
hostList = xmlDoc.getElementsByTagName('host')

#List of security headers which are checked for and reported on
headerList = ['hostname', 'credssp', 'native rdp', 'ssl', 'rdp encryption level', '40 bit', '56 bit', '128 bit', 'fips140', 'unknown', 'NLA?', 'Strength']
assetDict = dict()
print '\nInput File: %s' % args.file
print 'Output File: %s' % outFile.name

outFile.write('<html>\n<head>\n<title>NMAP RDP Scan Report</title>\n<style>\ntable,th,td\n{\nborder:1px solid black; text-align:center; font-size:85%; letter-spacing:1px\n}\np\n{\nfont-size:85%; margin: 5; padding: 0;\n}\nh5\n{\nmargin: 0; padding: -5;\n}\nh6\n{\nmargin: 0; padding: 0;\n}\n</style></head>\n<body>\n<table>')
outFile.write('<tr><th>')

for item in headerList:
  value = '</th><th bgcolor="F2F2F2">{0}'.format(item)
  outFile.write(value)
outFile.write('</th></tr>')

#Parse the Nmap .xml file. Create a dictionary where each key is a specific host:port, and each value is a list of found security headers
for host in hostList:
  assets = []
  hostname = ''
  addr = ''

  for hostChildNode in host.childNodes:
    if hostChildNode.nodeName == 'address':
      temp = hostChildNode.getAttribute('addrtype')
      if temp == 'ipv4':  #have to deal with issues where it pulls back both a mac and the IP address and since this is a for loop and the mac is second, that gets written as the IP!
        addr = hostChildNode.getAttribute('addr')
    if hostChildNode.nodeName == 'hostnames':
      for child in hostChildNode.childNodes:
        if child.nodeName == 'hostname':
          hostname = child.getAttribute('name')

    if hostChildNode.nodeName == 'ports':
      for portsChildNode in hostChildNode.childNodes:

        state = ''
        output = ''

        if portsChildNode.nodeName == 'port':

          port = portsChildNode.getAttribute('portid')
          state = ''
          for portChildNode in portsChildNode.childNodes:
            if portChildNode.nodeName == 'state':
              state = portChildNode.getAttribute('state')
            if state == 'open':
              if portChildNode.nodeName == 'script':
                id = portChildNode.getAttribute('id')
                if id == 'rdp-enum-encryption':
                  asset = []
                  credssp = False
                  nativerdp = False
                  ssl = False
                  rdpencryptionlevel = ''
                  bit40 = False
                  bit56 = False
                  bit128 = False
                  fips140 = False
                  unknown = ''
                  notes = ''

                  output = portChildNode.getAttribute('output')
                  items = output.splitlines()
                  for item in items:
                    if item == '':
                     pass
                    elif '  Security layer' in item:
                      pass
                    elif '    CredSSP: ' in item:
                      temp = item[13:]
                      if temp == 'SUCCESS':
                        credssp = True
                      else:
                        credssp = temp
                    elif '    Native RDP: ' in item:
                      temp = item[16:]
                      if temp == 'SUCCESS':
                        nativerdp = True
                      else:
                        nativerdp = temp
                    elif '    SSL: ' in item:
                      temp = item[9:]
                      if temp == 'SUCCESS':
                        ssl = True
                      else:
                        ssl = temp
                    elif '  RDP Encryption level: ' in item:
                      rdpencryptionlevel = item[24:]
                    elif '    40-bit RC4: ' in item:
                      temp = item[16:]
                      if temp == 'SUCCESS':
                        bit40 = True
                      else:
                        bit40 = temp
                    elif '    56-bit RC4: ' in item:
                      temp = item[16:]
                      if temp == 'SUCCESS':
                        bit56 = True
                      else:
                        bit56 = temp
                    elif '    128-bit RC4: ' in item:
                      temp = item[17:]
                      if temp == 'SUCCESS':
                        bit128 = True
                      else:
                        bit128 = temp
                    elif '    FIPS 140-1: ' in item:
                      temp = item[16:]
                      if temp == 'SUCCESS':
                        fips140 = True
                      else:
                        fips140= temp
                    else:
                      unknown = item

                  if credssp == True and nativerdp == False and ssl == False:
                    notes = 'NLA?'
                  if rdpencryptionlevel == 'Client Compatible':
                    notes = 'Client Compatible'
                  elif fips140 == True and bit128 == False:
                    notes = 'Strength = FIPS Compliant'
                  elif bit128 == True and bit56 == False:
                    notes = 'Strength = High'
                  elif bit56 == True and bit40 == False:
                    notes = 'Strength = Medium'
                  elif bit40 == True:
                    notes = 'Strength = Low'
                  elif credssp == True and nativerdp == False and ssl == False and rdpencryptionlevel == '':
                    notes = 'NLA?'
                  else:
                    notes = 'oddity?'
                 
                  asset = [addr, hostname, credssp, nativerdp, ssl, rdpencryptionlevel, bit40, bit56, bit128, fips140, unknown, notes]
                  #print asset

                  outFile.write('<tr>')
                  x = 0
                  test = ''
                  for i in asset:
                    if (x == 6) and (i == True):
                      value = '<td bgcolor="FF0000">{0}</td>'.format(i)
                    elif (x == 7) and (i == True):
                      value = '<td bgcolor="FFFF00">{0}</td>'.format(i)
                    elif (x == 8) and (i == False):
                      value = '<td bgcolor="FFFF33">{0}</td>'.format(i)
                    elif (x == 9) and (i == False):
                      value = '<td bgcolor="FFFF33">{0}</td>'.format(i)
                    elif (x == 10) and (i <> ''):
                      value = '<td bgcolor="FF0000">{0}</td>'.format(i)
                    else:
                      value = '<td>{0}</td>'.format(i)
                    outFile.write(value)
                    x = x + 1
                  if test == 'NoNoNo':
                    outFile.write('<td bgcolor="FF4D4D">Concern</td>')
                  else:
                    outFile.write('<td></td>')
                  outFile.write('</tr>')

outFile.write('</table>')
outFile.write('\n</body>\n</html>')

