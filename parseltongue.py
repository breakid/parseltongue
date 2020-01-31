#!/usr/bin/env python
#
# Copyright (C) 2019 Dan Breakiron
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from optparse import OptionParser
import sys
import os
import re
from datetime import datetime
from datetime import timedelta
import csv
from pprint import pprint

#==============================================================================
#********                    CONFIGURABLE CONSTANTS                    ********
#==============================================================================
# CHANGE THESE TO CONTROL WHICH ATTRIBUTES ARE PARSED
# adspath is required and must appear at the end of the list
COMPUTER_ATTRIBS = ['dnshostname', 'operatingsystem', 'operatingsystemversion', 'operatingsystemservicepack', 'lastlogon', 'lastlogontimestamp', 'useraccountcontrol', 'description', 'memberof', 'primarygroupid', 'location', 'objectsid', 'adspath']

USER_ATTRIBS = ['samaccountname', 'name', 'userprinciplename', 'lastlogon', 'lastlogontimestamp', 'pwdlastset', 'useraccountcontrol', 'memberof', 'description', 'objectsid', 'primarygroupid', 'adspath']

GROUP_ATTRIBS = ['samaccountname', 'name', 'userprinciplename', 'objectsid', 'primarygroupid', 'description', 'memberof', 'adspath']

OU_ATTRIBS = ['name', 'managedby', 'description', 'gplink', 'adspath']

GPO_ATTRIBS = ['displayname', 'name', 'adspath']

MULTI_OBJECT_DELIMITER = '\n'


#==============================================================================
#********                          CONSTANTS                           ********
#==============================================================================
DSQUERY_COMPUTERS = 'dsquery * -filter "(objectclass=computer)" -attr %s -limit 0 -l' % ' '.join(COMPUTER_ATTRIBS)

DSQUERY_USERS = 'dsquery * -filter "(&(objectclass=user)(!(objectclass=computer)))" -attr %s -limit 0 -l' % ' '.join(USER_ATTRIBS)

DSQUERY_GROUPS = 'dsquery * -filter "(objectclass=group)" -attr %s -limit 0 -l' % ' '.join(GROUP_ATTRIBS)

DSQUERY_GPOS = 'dsquery * -filter "(objectclass=grouppolicycontainer)" -attr %s -limit 0 -l' % ' '.join(GPO_ATTRIBS)

DSQUERY_OUS = 'dsquery * -filter "(objectclass=organizationalunit)" -attr %s -limit 0 -l' % ' '.join(OU_ATTRIBS)

KV_PATT = re.compile('^(?P<key>.*?): (?P<value>.*)$')


#==============================================================================
#********                          UTILITIES                           ********
#==============================================================================

def log(msg):
  print(msg)
  # TODO: Write to log file



def convert_uac(uac):
  """
  Converts a numeric Active Directory userAccountControl value to a human-readable string
  Args:
    uac: A numeric Active Directory userAccountControl value

  Returns:
    A human-readable string representation of the given userAccountControl value
  """
  
  if uac.strip() == '':
    return ''
  
  # Source: https://jackstromberg.com/2013/01/useraccountcontrol-attributeflag-values/
  UAC_FLAGS = {
    '0x0001': "SCRIPT",
    '0x0002': "ACCOUNTDISABLE",
    '0x0008': "HOMEDIR_REQUIRED",
    '0x0010': "LOCKOUT",
    '0x0020': "PASSWD_NOTREQD",
    '0x0040': "PASSWD_CANT_CHANGE",
    '0x0080': "ENCRYPTED_TEXT_PWD_ALLOWED",
    '0x0100': "TEMP_DUPLICATE_ACCOUNT",
    '0x0200': "NORMAL_ACCOUNT",
    '0x0202': "Disabled Account",
    '0x0220': "Enabled, Password Not Required",
    '0x0222': "Disabled, Password Not Required",
    '0x0800': "INTERDOMAIN_TRUST_ACCOUNT",
    '0x1000': "WORKSTATION_TRUST_ACCOUNT",
    '0x2000': "SERVER_TRUST_ACCOUNT",
    '0x10000': "DONT_EXPIRE_PASSWORD",
    '0x10200': "Enabled, Password Doesn't Expire",
    '0x10202': "Disabled, Password Doesn't Expire",
    '0x10222': "Disabled, Password Doesn't Expire & Not Required",
    '0x20000': "MNS_LOGON_ACCOUNT",
    '0x40000': "SMARTCARD_REQUIRED",
    '0x40200': "Enabled, Smartcard Required",
    '0x40202': "Disabled, Smartcard Required",
    '0x40222': "Disabled, Smartcard Required, Password Not Required",
    '0x50202': "Disabled, Smartcard Required, Password Doesn't Expire",
    '0x50222': "Disabled, Smartcard Required, Password Doesn't Expire & Not Required",
    '0x80000': "TRUSTED_FOR_DELEGATION",
    '0x82000': "Domain controller",
    '0x100000': "NOT_DELEGATED",
    '0x200000': "USE_DES_KEY_ONLY",
    '0x400000': "DONT_REQ_PREAUTH",
    '0x800000': "PASSWORD_EXPIRED",
    '0x1000000': "TRUSTED_TO_AUTH_FOR_DELEGATION",
    '0x04000000': "PARTIAL_SECRETS_ACCOUNT"
  }
  
  flags = []
  
  for flag in UAC_FLAGS:
    # Perform a bitwise XOR to determine if the flag is part of the UAC value
    if int(uac) ^ int(flag, 16) == 0:
      flags.append(UAC_FLAGS[flag])
  
  return MULTI_OBJECT_DELIMITER.join(sorted(flags))



def convert_nt_time(nt_time):
  """
  Converts Windows NT time value to a human-readable datetime value
  Args:
    nt_time: A Windows NT time value

  Returns:
    A human-readable datetime value
  """
  if nt_time.strip() == '':
    return ''
  
  try:
    nt_time = int(nt_time)
    
    if nt_time == 0:
      return None
      
    epoch_start = datetime(year=1601, month=1, day=1)
    seconds_since_epoch = nt_time / 10 ** 7
    timestamp = epoch_start + timedelta(seconds=seconds_since_epoch)
    
  except ValueError:
    timestamp = datetime.strptime(nt_time.split(".")[0], "%Y%m%d%H%M%S")

  return timestamp.strftime('%Y-%m-%d %H:%M:%S')



def enhance_object(obj, creds=None, dns_data=None, gpo_data=None):
  """
  Performs various conversions and enhancements of AD object data.
    - Picks the more recent of lastLogon and lastLogonTimestamp, and converts it to a human-readable timestamp
    - Converts pwdLastSet to a human-readable timestamp
    - If DNS data was provided, adds IP entries to computer objects
    
  Args:
    obj: A dictionary containing attributes of an Active Directory object
    dns_data (optional): A dictionary containing a hostname-to-IP mapping derived from dnscmd /zoneprint

  Returns:
    An enhanced Active Directory object (dictionary)
  """
  
  GPO_NAME_PATT = re.compile('\{[0-9A-Fa-f\-]{36}\}')
  
  # Attempt to derive name from various fields
  name = ''
  
  if 'samaccountname' in obj.keys():
    name = obj['samaccountname']
    
  if name == '' and 'name' in obj.keys():
    name = obj['name']
    
  if name == '' and 'dnshostname' in obj.keys():
    name = obj['dnshostname'].split('.')[0]
  
  if name == '':
    log('[-] ERROR: Object contains no name field')
    #pprint(obj)
  
  # Add credential fields
  if creds is not None:
    if name in creds:
      tmp_creds = creds[name]
      del tmp_creds['username']
      obj.update(tmp_creds)
    elif name + '$' in creds:
      # Add credential fields for computer accounts
      tmp_creds = creds[name + '$']
      del tmp_creds['username']
      obj.update(tmp_creds)
  
  if 'lastlogon' in obj.keys() and 'lastlogontimestamp' in obj.keys():
    obj['lastlogon'] = convert_nt_time(max(obj['lastlogon'], obj['lastlogontimestamp']))
    del obj['lastlogontimestamp']
  elif 'lastlogontimestamp' in obj.keys():
    obj['lastlogon'] = convert_nt_time(obj['lastlogontimestamp'])
    del obj['lastlogontimestamp']
  elif 'lastlogon' in obj.keys():
    obj['lastlogon'] = convert_nt_time(obj['lastlogon'])
  
  if 'pwdlastset' in obj.keys():
    obj['pwdlastset'] = convert_nt_time(obj['pwdlastset'])
  
  if 'useraccountcontrol' in obj.keys():
    obj['useraccountcontrol'] = convert_uac(obj['useraccountcontrol'])
    
  # If DNS data was provided, add the computer's IP
  if dns_data is not None:
    hostname = name.upper()
    
    if hostname in dns_data and 'ip' in dns_data[hostname]:
      # Account for multiple IP addresses per host
      obj['ip'] = MULTI_OBJECT_DELIMITER.join(set(dns_data[hostname]['ip']))
    else:
      # Set a default so CSV writer doesn't get angry if its 
      obj['ip'] = ''
  
  # Replace values in gplink with
  if gpo_data is not None and bool(gpo_data) and 'gplink' in obj.keys():
    print("GPOs detected")
    gpos = []
    gpo_names = GPO_NAME_PATT.findall(obj['gplink'])
    
    for name in gpo_names:
      if name in gpo_data:
        gpos.append(gpo_data[name])
      else:
        # All GPOs should be found, but just in case, it's good to know if data is missing
        gpos.append(name)
    
    obj['gpos'] = MULTI_OBJECT_DELIMITER.join(gpos)
    del obj['gplink']
  
  return obj



def merge_creds(dict1, dict2):
  """
  Merges two dictionaries containing credentials so no values are overridden
    
  Args:
    dict1: One dictionary containing credentials
    dict2: A seccond dictionary containing credentials

  Returns:
    A dictionary of dictionaries, where the primary key is the username and the assocatiated dictionary is a combination of values from dict1 and dict2; any values from dict2 not in dict1, are added as-is
  """
  for user in dict1:
    if user in dict2:
      dict1[user].update(dict2[user])
      del dict2[user]
  
  # Merge any remaining users that weren't in dict1
  dict1.update(dict2)
  
  return dict1



def write_output(output_prefix, data_type, objects, fieldnames = ['username', 'plaintext', 'ntlm', 'aes128', 'aes256', 'comment']):
  """
  Writes structured Active Directory data to a CSV file
    
  Args:
    output_prefix: The output directory and filename prefix where the CSV data will be written
    objects: A generic list of dictionaries containing keys defined in 'fieldnames'
    fieldnames: An ordered list of object attributes; these will be the columns names in the CSV file
  """
  
  if len(objects) > 0:
    output_filepath = '%s_%s.csv' % (output_prefix, data_type)
  
    log('[*] Writing output to: %s' % output_filepath)
    
    try:
      with open(output_filepath, 'wb') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(objects)
      
      # If a credential file was parsed, output a bonus file formatted for password cracker ingestion
      if data_type == 'creds':
        with open('%s_%s.txt' % (output_prefix, 'password_cracker_ingest'), 'wb') as csvfile:
          writer = csv.DictWriter(csvfile, fieldnames=['username', 'ntlm'], delimiter=':')
          
          # Have to create new dictionary in case creds have other fields like plaintext, aes128, or aes256
          for obj in objects:
            writer.writerow({'username': obj['username'], 'ntlm': obj['ntlm']})
          
    except IOError as e:
      raw_input('[-] Write failed; do you have the file open?')
      write_output(output_prefix, data_type, objects, fieldnames)
  else:
    log('[*] No %s detected; skipping...' % data_type)
    log('    If you think this is a mistakes, try checking that your file encoding is UTF-8')
    



#==============================================================================
#********                          DNS PARSER                          ********
#==============================================================================

def parse_dnscmd(filepath):
  """
  Reads and parses output from "dnscmd /zoneprint" to create a dictionary of hostnames and their associated IPs, CNAMEs, and FQDNs
    
  Args:
    filepath: The path to a file containing output from a "dnscmd /zoneprint" command

  Returns:
    objects: A list of dictionaries, each representing a hostname and the associated IPs, CNAMEs, and FQDNs
    hostname_map: A dictionary containing a mapping of hostnames to IPs, CNAMEs, and FQDNs
  """
  log('[*] Parsing DNSCMD output from: %s' % filepath)
  
  # Regex for A records
  A_REC_PATT = re.compile('^(?P<hostname>[a-zA-Z0-9\-]*?)\s.+?\s?\d*\sA\s(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$')
  
  # Regex for CNAME records
  CNAME_REC_PATT = re.compile('^(?P<alias>[a-zA-Z0-9\-]*?)\s[.+?\s]?\d*\sCNAME\s(?P<fqdn>[a-zA-Z0-9\-\.]*)$')
  
  zone = ''
  objects = []
  hostname_map = {}
  
  with open(filepath, 'r') as zone_file:
    for line in zone_file.readlines():
      line = line.strip()
      
      if ';  Zone:' in line:
        zone = line.split(':')[1].strip().upper()
      
      a_rec = A_REC_PATT.search(line)
    
      if a_rec is not None:
        a_rec = a_rec.groupdict()
        
        hostname = a_rec['hostname'].upper()
        ip = a_rec['ip']
        
        # Skip FORESTDNSZONES and DOMAINDNSZONES (not sure what these are for)
        if hostname.endswith('DNSZONES'):
          continue
    
        # Save the IP in a list to gracefully handle multiple IPs per hostname
        if hostname in hostname_map:
          hostname_map[hostname]['ip'].append(ip)
        else:
          hostname_map[hostname] = {
            'ip': [ip],
            'fqdn': ['%s.%s' % (hostname, zone)],
            'cname': []
          }
      else:
        cname = CNAME_REC_PATT.search(line)
        
        if cname is not None:
          cname = cname.groupdict()
          
          fqdn = cname['fqdn'].strip('.').upper()
          hostname = fqdn.split('.')[0]
          alias = cname['alias'].upper()
          
          # Save the CNAME and FQDN in lists to gracefully handle multiples
          if hostname in hostname_map:
            hostname_map[hostname]['fqdn'].append(fqdn)
            hostname_map[hostname]['cname'].append(alias)
          else:
            #print('[-] ERROR: CNAME without A record...is this even possible?')
            hostname_map[hostname] = {
              'ip': [],
              'fqdn': [fqdn],
              'cname': [alias]
            }
            
      # TODO
      #   - Add other record types records (PTR, SRV, etc.)
  
  # Populate objects in case no other options were specified
  for name in hostname_map.keys():
    obj = {
      'hostname': name
    }
    
    # Add other fields (if applicable), use set() to ensure only unique values
    if 'ip' in hostname_map[name]:
      obj['ip'] = MULTI_OBJECT_DELIMITER.join(set(hostname_map[name]['ip']))
    
    if 'fqdn' in hostname_map[name]:
      obj['fqdn'] = MULTI_OBJECT_DELIMITER.join(set(hostname_map[name]['fqdn']))
    
    if 'cname' in hostname_map[name]:
      obj['cname'] = MULTI_OBJECT_DELIMITER.join(set(hostname_map[name]['cname']))
    
    objects.append(obj)
    
  return objects, hostname_map



#==============================================================================
#********                 CREDENTIAL PARSERS                           ********
#==============================================================================

def parse_hashdump(filepath):
  """
  Parses output from a hashdump (in pwdump format) into a dictionary
    
  Args:
    filepath: The path to a file containing output from a pwdump hashdump

  Returns:
    A dictionary of dictionaries, where the primary key is the username and the assocatiated dictionary contains the username and NTLM
  """
  log('[*] Parsing hashdump output from: %s' % filepath)
  
  user_hash_map = {}

  with open(filepath, 'r') as hashdump:
    for line in hashdump.readlines():
      if ':' in line:
        (username, rid, lm_hash, nt_hash) = line.split(':')[:4]
        ntlm = nt_hash.upper()
        user_hash_map[username] = {'username': username, 'ntlm': ntlm}
  
  return user_hash_map



def parse_lsadump(filepath):
  """
  Parses output from Mimikatz lsadump into a dictionary
    
  Args:
    filepath: The path to a file containing output from Mimikatz lsadump

  Returns:
    A dictionary of dictionaries, where the primary key is the username and the assocatiated dictionary contains the username and NTLM
  """
  log('[*] Parsing lsadump output from: %s' % filepath)
  user_hash_map = {}
  username = ''

  with open(filepath, 'r') as lsadump:
    for line in lsadump.readlines():
      if 'User : ' in line:
        username = KV_PATT.search(line).groupdict()['value']
      elif 'NTLM : ' in line:
        ntlm = KV_PATT.search(line).groupdict()['value'].upper()
        user_hash_map[username] = {'username': username, 'ntlm': ntlm}
        username = ''
  
  return user_hash_map



def parse_export(filepath, domain):
  """
  Parses exported Cobalt Strike credentials into a dictionary
    
  Args:
    filepath: The path to a Cobalt Strike credential export file
    domain: NT domain

  Returns:
    A dictionary of dictionaries, where the primary key is the username and the assocatiated dictionary contains username, NTLM, and plaintext passwords
  """
  log('[*] Parsing Cobalt Strike credential export from: %s' % filepath)
  
  NTLM_PATT = re.compile('^(?P<realm>.*?)\\\\(?P<username>.*?):::(?P<ntlm>[a-fA-F0-9]{32}):::$')
  PLAIN_PATT = re.compile('^(?P<realm>.*)\\\\(?P<username>.*?) (?P<plaintext>.*)$')
  
  user_hash_map = {}
  
  with open(filepath, 'r') as hashdump:
    for line in hashdump.readlines():
      line = line.strip()
      
      data = NTLM_PATT.search(line)
      
      if data is not None:
        data = data.groupdict()
        realm = data['realm']
        username = data['username']
        ntlm = data['ntlm']
        
        if realm == domain:
          if username in user_hash_map:
            user_hash_map[username]['ntlm'] = ntlm
          else:
            user_hash_map[username] = {'username': username, 'ntlm': ntlm}
      else:
        data = PLAIN_PATT.search(line)
      
        if data is not None:
          data = data.groupdict()
          realm = data['realm']
          username = data['username']
          plaintext = data['plaintext']
          
          if realm == domain:
            if username in user_hash_map:
              user_hash_map[username]['plaintext'] = plaintext
            else:
              user_hash_map[username] = {'username': username, 'plaintext': plaintext}
  
  return user_hash_map



def parse_dcsync(filepath):
  """
  Parses output from Mimikatz dcsync into a dictionary
    
  Args:
    filepath: The path to a file containing output from Mimikatz dcsync

  Returns:
    A dictionary of dictionaries, where the primary key is the username and the assocatiated dictionary contains the username, NTLM, aes128, and aes246 hashes (if they exist)
  """
  log('[*] Parsing dcsync output from: %s' % filepath)
  
  user_hash_map = {}
  obj = {}

  with open(filepath, 'r') as lsadump:
    for line in lsadump.readlines():
      if 'SAM Username         : ' in line:
        obj['username'] = KV_PATT.search(line).groupdict()['value']
      else:
        # Ensure the username is set before parsing hashes (prevents entry getting overwritten with values from OldCredentials
        if 'username' in obj:
          if 'Hash NTLM: ' in line:
            obj['ntlm'] = KV_PATT.search(line).groupdict()['value'].upper()
          elif 'aes256_hmac       (4096) :' in line:
            obj['aes256'] = KV_PATT.search(line).groupdict()['value'].upper()
          elif 'aes128_hmac       (4096) :' in line:
            obj['aes128'] = KV_PATT.search(line).groupdict()['value'].upper()
            user_hash_map[obj['username']] = obj
            # Entry is finish, reset object; require username to get reset before parsing more hashes so that aes256_hmac and aes128_hmac don't get overwritte by old credentials
            obj = {}

  return user_hash_map


def parse_logonpasswords(filepath):
  """
  Parses output from Mimikatz logonpasswords into a dictionary
    
  Args:
    filepath: The path to a file containing output from Mimikatz logonpasswords

  Returns:
    A dictionary of dictionaries, where the primary key is the username and the assocatiated dictionary contains username, NTLM and plaintext passwords
  """
  log('[*] Parsing logonpasswords output from: %s' % filepath)
  
  user_hash_map = {}
  obj = {}

  with open(filepath, 'r') as lsadump:
    for line in lsadump.readlines():
      if 'User Name         : ' in line:
        username = KV_PATT.search(line).groupdict()['value']
        
        if username not in ['(null)', 'LOCAL SERVICE', 'DWM-1']:
          obj['username'] = username
        
          # Initialize NTLM so password cracker output doesn't get angry
          obj['ntlm'] = ''
          
      elif obj and 'NTLM     : ' in line:
        obj['ntlm'] = KV_PATT.search(line).groupdict()['value'].upper()
      elif obj and 'Password : ' in line and not obj['username'].endswith('$'):
        # Save plaintext password if it's not null or for a computer account (< 128)
        # Use regex to make sure we get the entire password, even if it ends with a space
        password = KV_PATT.search(line).groupdict()['value']
        
        if password != '(null)' and len(password) < 128:
          obj['plaintext'] = password
      elif obj and 'credman :' in line:
        # Last line of the entry, save the current object to the dictionary if the hash was populated, and reset the object for the next entry
        if obj['ntlm'] != '':
          # Warn user if a duplicate is detected; since the data is saved to a hash, a duplicate will overwrite the original
          if obj['username'] in user_hash_map:
            log('\n[*] IMPORTANT: Duplicate username (%s) detected in logonpasswords; manually verify which hash is accurate\n' % obj['username'])
        
          user_hash_map[obj['username']] = obj
          
        obj = {}
  
  return user_hash_map



#=============================================================================
#********                  DSQUERY PARSERS                            ********
#=============================================================================

def parse_objects(filepath, fieldnames, creds = None, dns_data = None, gpo_data=None):
  """
  Reads output from a dsquery command and parses into a list of dictionaries, each representing an AD object; attempts to enhance the raw data
    
  Args:
    filepath: The path to a file containing output from a dsquery command
    fieldnames: The list of expected object attributes; the last object in the list is used to delimit object entries; it MUST exist AND be unique

  Returns:
    A list of dictionaries representing Active Directory objects
  """
  log('[*] Parsing dsquery output from: %s' % filepath)
  
  objects = []
  obj = {}
  
  with open(filepath, 'r') as dsquery_file:
    data = dsquery_file.read()
    
    # Strip out extraneous data introduced by Cobalt Strike
    data = data.replace('received output:\n', '').replace('received output:\r\n', '')
    
    for line in data.split('\n'):
      data = KV_PATT.search(line)
    
      if data is not None:
        data = data.groupdict()
        key = data['key'].lower()
        value = data['value'].strip()
        
        # Sanity check to prevent the CSV reader from getting angry that the data contains fields not in fieldnames
        if key in fieldnames:
          # Gracefully handle multiples of the same key
          if key in obj.keys():
            obj[key] = obj[key] + MULTI_OBJECT_DELIMITER + value
          else:
            obj[key] = value
          
          # Save the object when the last entry is read and re-initialize the object
          # IMPORTANT: The last element must be unique, otherwise objects won't be delimited properly
          if key == fieldnames[-1]:
            obj = enhance_object(obj, creds, dns_data, gpo_data)
            objects.append(obj)
            obj = {}
  
  return objects



def main():
  global MULTI_OBJECT_DELIMITER
  
  parser = OptionParser()
  parser.add_option("-c", "--computers", dest="computer", help="Dsquery for computers")
  parser.add_option("-d", "--dns", dest="dns", help="Output from dnscmd /zoneprint")
  parser.add_option("--dcsync", dest="dcsync", help="File containing one or more DCsyncs")
  parser.add_option("-e", "--export", dest="export", help="Cobalt Strike credentials export")
  parser.add_option("-g", "--groups", dest="group", help="Dsquery for groups")
  parser.add_option("--gpos", dest="gpo", help="Dsquery for GPOs")
  parser.add_option("--hashdump", dest="hashdump", help="Hashdump (pwdump format)")
  parser.add_option("-k", "--kibana", dest="kibana_delimiter", help="A delimiter to use between values of duplicate keys for applications (such as Kibana) that don't handle multiple lines well")
  parser.add_option("-l", "--logonpasswords", dest="logonpasswords", help="Mimikatz logonpasswords")
  parser.add_option("-m", "--lsadump", dest="lsadump", help="Mimikatz lsadump")
  parser.add_option("-n", "--ntdomain", dest="nt_domain", help="NT domain")
  parser.add_option("-o", "--ous", dest="ou", help="Dsquery for OUs")
  parser.add_option("--output", dest="output_path", help="Output directory", default=".")
  parser.add_option("-u", "--users", dest="user", help="Dsquery output containing users")
  (options, args) = parser.parse_args()
  
  # Handle option errors
  if len(sys.argv) == 1:
    print("""
  QUICK REFERENCE:
    REQUIRED:
      
      -n <nt_domain>
    
    OPTIONAL:
      
      -c <computers dsquery>
      
      -d <path to dnscmd /zoneprint output>
      
      --dcsync <file containing one or more dcsyncs>
      
      -e <Cobalt Strike credentials export>
      
      -g <groups dsquery>
      
      --gpos <GPO dsquery>
      
      --hashdump <hashdump>
      
      -k <multiple key delimiter>
      
      -l <file containing one or more logonpasswords>
      
      -m <mimikatz_lsadump>
      
      -o <OUs dsquery>
      
      --output <path to output directory>
      
      -u <users dsquery>
    
  -------------------------------------------------------------------
    
  DSQUERY COMMANDS:
  
    COMPUTERS: 
      {1}
    
    USERS:
      {2}
      
    GROUPS:
      {3}
      
    OUs:
      {4}
      
    GPOs:
      {5}
  
  -------------------------------------------------------------------
  
  USAGE:
    {0} -s
      - Displays dsquery commands to run to generate expected output
    
    {0} --output <output directory> -n <nt_domain> -d <path to dnscmd /zoneprint output>
      - Generates a list of hostname / IP / CNAME mappings from dnscmd /zoneprint output
      
    {0} --output <output directory> -n <nt_domain> --hashdump <hashdump>
      - Generates a list of hostname / IP / CNAME mappings from dnscmd /zoneprint output
    
    {0} --output <output directory> -n <nt_domain> -c <path to computers dsquery> [-d <path to dnscmd /zoneprint output>]
      - Generates a table containing computer objects, optionally include IPs parsed from a dnscmd /zoneprint file
    
    {0} --output <output directory> -n <nt_domain> -u <path to users dsquery> -m <mimikatz lsadump output>
      - Generates a CSV file containing user objects enhanced with password hashes parsed from the Mimikatz lsadump
      
    {0} --output <output directory> -n <nt_domain> -u <path to users dsquery> -k '|'
      - Generates a CSV file containing user objects with a '|' character separating the values of duplicate keys (such as memberOf)
    """.format(sys.argv[0], DSQUERY_COMPUTERS, DSQUERY_USERS, DSQUERY_GROUPS, DSQUERY_OUS, DSQUERY_GPOS))
    sys.exit(0)
  elif options.output_path is None:
    print('[-] ERROR: No output directory specified')
    sys.exit(1)
  elif options.nt_domain is None:
    print('[-] ERROR: No NT domain specified')
    sys.exit(1)
  
  if options.kibana_delimiter is not None:
    MULTI_OBJECT_DELIMITER = options.kibana_delimiter
  
  objects = None
  dns_data = None
  gpo_data = None
  creds = {}
  gpo_data = {}
  
  outfile_path = os.path.join(options.output_path, '%s_%s' % (options.nt_domain, datetime.now().strftime('%Y-%m-%d')))
  
  # Parse DNS data
  if options.dns is not None:
    (objects, dns_data) = parse_dnscmd(options.dns)
    fieldnames = ['hostname', 'ip', 'fqdn', 'cname']
    
    # Write output to CSV file
    write_output(outfile_path, 'DNS', objects, fieldnames)
  
  # Parse hashdump
  if options.hashdump is not None:
    creds = parse_hashdump(options.hashdump)
  
  # Parse lsadump
  if options.lsadump is not None:
    creds = merge_creds(creds, parse_lsadump(options.lsadump))
    
  # Parse Cobalt Strike credentials export
  if options.export is not None:
    creds = merge_creds(creds, parse_export(options.export, options.nt_domain))
  
  # Parse dcsync
  if options.dcsync is not None:
    creds = merge_creds(creds, parse_dcsync(options.dcsync))
  
  # Parse logonpasswords
  if options.logonpasswords is not None:
    creds = merge_creds(creds, parse_logonpasswords(options.logonpasswords))
  
  objects = [cred_obj for (username, cred_obj) in creds.items()]
  
  # Write output to CSV file
  write_output(outfile_path, 'creds', objects)
  
  # Parse GPO data
  if options.gpo is not None:
    fieldnames = GPO_ATTRIBS
    
    objects = parse_objects(options.gpo, fieldnames)
    
    for obj in objects:
      gpo_data[obj['name']] = obj['displayname']
    
    # Write output to CSV file
    write_output(outfile_path, 'GPOs',  objects, fieldnames)
    
  # Parse OU data
  if options.ou is not None:
    fieldnames = OU_ATTRIBS
    
    objects = parse_objects(options.ou, fieldnames, gpo_data=gpo_data)
    
    if options.gpo is not None:
      fieldnames.remove('gplink')
      fieldnames.insert(-1, 'gpos')
    
    # Write output to CSV file
    write_output(outfile_path, 'OUs',  objects, fieldnames)
    
  # Parse group data
  if options.group is not None:
    fieldnames = GROUP_ATTRIBS
    
    objects = parse_objects(options.group, fieldnames)
    
    # Write output to CSV file
    write_output(outfile_path, 'groups',  objects, fieldnames)
    
  # Parse computer data
  if options.computer is not None:
    fieldnames = COMPUTER_ATTRIBS
    
    objects = parse_objects(options.computer, fieldnames, creds, dns_data)
  
    fieldnames.insert(0, 'ip')
    # Remove lastLogonTimestamp because it's merged with lastLogon
    fieldnames.remove('lastlogontimestamp')
    fieldnames += ['ntlm', 'aes128', 'aes256', 'comment']
    
    # Write output to CSV file
    write_output(outfile_path, 'computers',  objects, fieldnames)
    
  # Parse user data
  if options.user is not None:
    fieldnames = USER_ATTRIBS
    
    objects = parse_objects(options.user, fieldnames, creds)
    
    # Remove lastLogonTimestamp because it's merged with lastLogon
    fieldnames.remove('lastlogontimestamp')
    fieldnames += ['plaintext', 'ntlm', 'aes128', 'aes256', 'comment']
    
    # Write output to CSV file
    write_output(outfile_path, 'users',  objects, fieldnames)
  
  log('[+] Done!')



if __name__ == "__main__":
  main()