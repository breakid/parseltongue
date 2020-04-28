# Copyright (C) 2020 Dan Breakiron
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.    If not, see <http://www.gnu.org/licenses/>.

from argparse import ArgumentParser, ArgumentError
from datetime import datetime
from datetime import timedelta
import sys
import os
import re
import json
import hashlib, binascii
import csv
from xml.etree import ElementTree
from xml.etree.ElementTree import ParseError


#==============================================================================
#********                    CONFIGURABLE CONSTANTS                    ********
#==============================================================================

DEFAULT_CONFIG_FILEPATH = "config.json"

# Default configuration; overridden at runtime by loaded config
CONFIG_DATA = {
    'INPUT': {
        # CHANGE THESE TO CONTROL WHICH ATTRIBUTES ARE PARSED
        # IMPORTANT: The last element must be unique, otherwise objects won't be delimited properly
        'DSQUERY_ATTRS': {
            'COMPUTER': ['dnshostname', 'operatingsystem', 'operatingsystemversion', 'operatingsystemservicepack', 'lastlogon', 'lastlogontimestamp', 'useraccountcontrol', 'description', 'memberof', 'primarygroupid', 'location', 'objectsid', 'adspath'],
            'GPO': ['displayname', 'name', 'adspath'],
            'GROUP': ['samaccountname', 'name', 'distinguishedname', 'objectsid', 'primarygroupid', 'description', 'member', 'adspath'],
            'OU': ['name', 'managedby', 'description', 'gplink', 'adspath'],
            'USER': ['samaccountname', 'name', 'distinguishedname', 'lastlogon', 'lastlogontimestamp', 'pwdlastset', 'useraccountcontrol', 'memberof', 'description', 'objectsid', 'primarygroupid', 'adspath']
        },
        'DATA': {
            'FILENAME_DATE_FORMAT': '%Y-%m-%d',
            'CS_EXPORT': {
                'FOREIGN_DOMAIN': 'include', # Valid options: 'include', 'ignore'
                'INVALID_REALM': 'prompt', # Valid options: 'replace', 'prompt', 'warn', 'ignore', 'warn_and_ignore'
                'POPULATE_COMMENT': 'append' # Valid options: "append", "empty_only", "none"
            }
        },
        'WORDLIST': 'wordlists\\wordlist.txt'
    },
    'OUTPUT': {
        'DATA': {
            'FILENAME_DATE_FORMAT': '%Y-%m-%d',
            'DIR': 'output',
            'MULTI_OBJECT_DELIMITER': '\n',
            'SEPARATE_BY_DOMAIN': False
        },
        'WORDLIST': 'wordlists\\wordlist.txt'
    },
    'LOGGING': {
        'OUTPUT_DIR': 'logs',
        'VERBOSITY': 2,
        'TIMEFORMAT_FILE': '%Y-%m-%d_%H%M%S',
        'TIMEFORMAT_LOG': '%Y-%m-%d %H:%M:%S',
        'WRITE_FILE': True
    },
    'DEBUG': False,
    'VERBOSITY': 1
}


#==============================================================================
#********                          CONSTANTS                           ********
#==============================================================================

KV_PATT = re.compile('^(?P<key>.*?): (?P<value>.*)$')

# Types of data supported by Parseltongue
# These strings must appear at the end of the filename in order to identify the data type
FILE_TYPE_MAP = {
    'computers': CONFIG_DATA['INPUT']['DSQUERY_ATTRS']['COMPUTER'],
    'credentials': ['username', 'plaintext', 'ntlm', 'aes128', 'aes256', 'comment'],
    'dns': ['hostname', 'ip', 'fqdn', 'cname'],
    'gpos': CONFIG_DATA['INPUT']['DSQUERY_ATTRS']['GPO'],
    'groups': CONFIG_DATA['INPUT']['DSQUERY_ATTRS']['GROUP'],
    'ous': CONFIG_DATA['INPUT']['DSQUERY_ATTRS']['OU'],
    'users': CONFIG_DATA['INPUT']['DSQUERY_ATTRS']['USER']
}

# Subset of file types which should be merged into 'credentials' data
CREDENTIAL_TYPES = ['cs_export', 'dcsync', 'hashdump', 'logonpasswords', 'lsadump']

FILE_TYPES = sorted(list(FILE_TYPE_MAP.keys()) + CREDENTIAL_TYPES)

LOG_FILEPATH = os.path.join('logs', 'parseltongue_%s.log' % datetime.now().strftime(CONFIG_DATA['LOGGING']['TIMEFORMAT_FILE']))

VERSION = '2.1.1'

BANNER_SM = """
======================================================================= 
  ____   _    ____  ____  _____ _   _____ ___  _   _  ____ _   _ _____  
 |  _ \ / \  |  _ \/ ___|| ____| | |_   _/ _ \| \ | |/ ___| | | | ____| 
 | |_) / _ \ | |_) \___ \|  _| | |   | || | | |  \| | |  _| | | |  _|   
 |  __/ ___ \|  _ < ___) | |___| |___| || |_| | |\  | |_| | |_| | |___  
 |_| /_/   \_\_| \_\____/|_____|_____|_| \___/|_| \_|\____|\___/|_____| 

=======================================================================
"""

BANNER_LG = """
========================================================================================================= 
 _______  _______  _______  _______  _______  _    _________ _______  _        _______           _______  
(  ____ )(  ___  )(  ____ )(  ____ \(  ____ \( \   \__   __/(  ___  )( (    /|(  ____ \|\     /|(  ____ \ 
| (    )|| (   ) || (    )|| (    \/| (    \/| (      ) (   | (   ) ||  \  ( || (    \/| )   ( || (    \/ 
| (____)|| (___) || (____)|| (_____ | (__    | |      | |   | |   | ||   \ | || |      | |   | || (__     
|  _____)|  ___  ||     __)(_____  )|  __)   | |      | |   | |   | || (\ \) || | ____ | |   | ||  __)    
| (      | (   ) || (\ (         ) || (      | |      | |   | |   | || | \   || | \_  )| |   | || (       
| )      | )   ( || ) \ \__/\____) || (____/\| (____/\| |   | (___) || )  \  || (___) || (___) || (____/\ 
|/       |/     \||/   \__/\_______)(_______/(_______/)_(   (_______)|/    )_)(_______)(_______)(_______/ 

=========================================================================================================
"""

USAGE_TEXT="""
Parseltongue auto-detects information from the name of the data file being processed.
Therefore, data files must be named according to the following format:

    <NT domain>_<date>_<file_type>

The accepted datestamp format can be configured using the ['INPUT']['DATA']['FILENAME_DATE_FORMAT']
option in the config file. Dates are used to chronologically order data of the same file type
so that more recent data overwrites older data, if applicable.

Valid File Types:
    - {0}

Parseltongue can handle both XML and text versions of exported Cobalt Strike credentials; however, XML is highly preferred. The regex for the text version will not properly handle plaintext password entries where the username contains a space; this is a limitation of the text export format, which is space-delimited, not a bug with parseltongue. Since Cobalt Strike credentials may contain data from multiple domains, configuration options are provided that allows users to specify how to handle various situations; see the README for more details.
""".format('\n    - '.join(FILE_TYPES))

EXAMPLES = """
EXAMPLES:
    {0} -s
        - Displays dsquery commands to run to generate expected output
    
    {0} -c custom_config.json -g
        - Creates a custom_config.json with the default config settings, if the file does not exist. If the file does exist, the "-g" argument does nothing. If "-g" is omitted and the specified file does not exist, the user will be prompted whether or not to create the file. Either way, the current configuration is printed to the screen. This can be used to double check settings, especially useful when using command-line options to override config file settings.
    
    {0} -c custom_config.json -d "|" -u SGC_2020-03-11_users.txt
        - Loads a custom config file (custom_config.json)
        - Uses "|" as a delimiter between multiple values of the same type (e.g., member attribute of a group)
        - Updates custom_config.json to use "|" as the delimiter
    
    {0} -o ../parseltongue_output -w wordlist.txt SGC_2020-03-11_hashdump.txt SGC_2020-03-11_users.txt
        - Specifies a custom output directory; overrides output directory specified in config file for current execution
        - Reads a list of plaintext passwords (one per line) from wordlist.txt; uses these to crack hashes specified in the hashdump
        - Parses Active Directory user data and enriches each record with the NTLM hash of the user; if a matching plaintext password was found in wordlist.txt, this will also be included
    
    {0} SGC_2020-03-11_users.txt SGC_2020-03-11_computers.txt SGC_2020-03-11_groups.txt
        - Parses users, computers, and group data for the SGC domain
""".format(sys.argv[0])


#==============================================================================
#********                      GLOBAL VARIABLES                        ********
#==============================================================================

# A dictionary containing parsed system information, grouped by NT domain and broken down by file type
# FORMAT:
# data_objects = {
#     <nt_domain>: {
#         'computers': {},
#         'credentials': {},
#         'dns': {},
#         'gpos': {},
#         'groups': {},
#         'ous': {},
#         'users': {}
#     },
#     ...
# }
data_objects = {}

# A dictionary containing a mapping of hostnames to IPs, CNAMEs, and FQDNs
hostname_map = {}

# A dictionary mapping NTLM hashes to plaintext password; used for rudimentary password cracking
ntlm_plaintext_map = {}


#==============================================================================
#********                          UTILITIES                           ********
#==============================================================================

def pformat(obj):
    """
    Converts the given object into a pretty printed string
    
    Args:
        obj: The object to pretty print
    """
    return json.dumps(obj, indent=4, sort_keys=True, default=str)


def get_dsquery_commands_str():
    """
    Returns a string containing the dsquery commands from which Parseltongue expects to receive output
    
    This is a separate function (as opposed to the hardcoded USAGE and EXAMPLES strings because the command 
    attributes can be set via the config file so this string must be dynamically generated
    """
    computers = 'dsquery * -filter "(objectclass=computer)" -attr %s -limit 0 -l' % ' '.join(CONFIG_DATA['INPUT']['DSQUERY_ATTRS']['COMPUTER'])

    users = 'dsquery * -filter "(&(objectclass=user)(!(objectclass=computer)))" -attr %s -limit 0 -l' % ' '.join(CONFIG_DATA['INPUT']['DSQUERY_ATTRS']['USER'])

    groups = 'dsquery * -filter "(objectclass=group)" -attr %s -limit 0 -l' % ' '.join(CONFIG_DATA['INPUT']['DSQUERY_ATTRS']['GROUP'])

    gpos = 'dsquery * -filter "(objectclass=grouppolicycontainer)" -attr %s -limit 0 -l' % ' '.join(CONFIG_DATA['INPUT']['DSQUERY_ATTRS']['GPO'])

    ous = 'dsquery * -filter "(objectclass=organizationalunit)" -attr %s -limit 0 -l' % ' '.join(CONFIG_DATA['INPUT']['DSQUERY_ATTRS']['OU'])
    
    return """
DSQUERY COMMANDS:

    COMPUTERS:
        {0}

    USERS:
        {1}

    GROUPS:
        {2}

    OUs:
        {3}

    GPOs:
        {4}
    """.format(computers, users, groups, ous, gpos)


def print_usage(parser):
    """
    Prints usage information, including examples and sample queries
    
    Args:
        parser: An ArgumentParser object, used to print default help
    """
    parser.print_help()
    
    # Print usage, examples, sample queries, and current config
    # separated by a horizontal line delimiter
    divider = '\n%s\n' % ('-' * 90)
    log(divider.join([USAGE_TEXT, EXAMPLES]))
    
    print_dsquery_commands()
    
    print_config()


# IMPORTANT: This needs to be a separate function because the dsquery attributes are set
# in the config file so this string must be generated dynamically rather than once at start up
def print_dsquery_commands():
    """
    Returns a string containing the dsquery commands from which Parseltongue expects to receive output
    """
    computers = 'dsquery * -filter "(objectclass=computer)" -attr %s -limit 0 -l' % ' '.join(CONFIG_DATA['INPUT']['DSQUERY_ATTRS']['COMPUTER'])
    
    users = 'dsquery * -filter "(&(objectclass=user)(!(objectclass=computer)))" -attr %s -limit 0 -l' % ' '.join(CONFIG_DATA['INPUT']['DSQUERY_ATTRS']['USER'])
    
    groups = 'dsquery * -filter "(objectclass=group)" -attr %s -limit 0 -l' % ' '.join(CONFIG_DATA['INPUT']['DSQUERY_ATTRS']['GROUP'])
    
    gpos = 'dsquery * -filter "(objectclass=grouppolicycontainer)" -attr %s -limit 0 -l' % ' '.join(CONFIG_DATA['INPUT']['DSQUERY_ATTRS']['GPO'])
    
    ous = 'dsquery * -filter "(objectclass=organizationalunit)" -attr %s -limit 0 -l' % ' '.join(CONFIG_DATA['INPUT']['DSQUERY_ATTRS']['OU'])
    
    template = """
DSQUERY COMMANDS:

    COMPUTERS:
        {0}

    USERS:
        {1}

    GROUPS:
        {2}

    OUs:
        {3}

    GPOs:
        {4}
    """
    
    log('%s\n%s' % ('-' * 90, template.format(computers, users, groups, ous, gpos)))


def print_config():
    """
    Prints a horizontal delimiter and the current config
    """
    log('%s\n\nCURRENT CONFIG:\n\n%s' % ('-' * 90, pformat(CONFIG_DATA)))


def log(msg, level=1, suppress=False):
    """
    Print the specified message to the screen (unless suppressed)
    if the level is below the verbosity threshold.
    
    Write the message to a log file in all cases if the WRITE_LOGFILE is set to True in the config
    
    Args:
        msg: A message to print and log
        level: A number indicating whether at which verbosity threshold the message should be printed
        suppress: A boolean indicating whether the message should be logged only and not printed to the console
    """
    if level <= CONFIG_DATA['VERBOSITY'] and not suppress:
        print(msg)
    
    if CONFIG_DATA['LOGGING']['WRITE_FILE'] and level <= CONFIG_DATA['LOGGING']['VERBOSITY']:
        # Ensure the output directory exists
        output_dir = os.path.dirname(LOG_FILEPATH)
        os.makedirs(output_dir, exist_ok = True)
        
        with open(LOG_FILEPATH, 'a') as log_file:
            msg = '\n' if msg == '' else '%s> %s\n' % (datetime.now().strftime(CONFIG_DATA['LOGGING']['TIMEFORMAT_LOG']), msg)
            log_file.writelines(msg)


def debug(data, msg=None):
    """
    Logs the optional message and value of data, if debugging is enabled
    
    Args:
        data: A string or object whose contents should be written to the log file for debugging
        msg: An optional human-readable message to provide context to the printed data
    """
    if CONFIG_DATA['DEBUG']:
        if msg is not None:
            log('[DEBUG] %s' % msg, 0, suppress=True)
        
        # Convert data to a str, if necessary
        if not isinstance(data, str):
            data = pformat(data)
        
        log('\n%s\n' % data, 0, suppress=True)


# Source: https://stackoverflow.com/questions/7204805/how-to-merge-dictionaries-of-dictionaries
def merge_dict(a, b, path=[]):
    """
    Merges the second dictionary into the first one
    
    Args:
        a: The first dictionary; values from dictionary 'b' will be merged into this one
        b: The second dictionary; values from this object will be merged into dictionary 'a'
        path: A list of keys indicating where the current object falls in the hierarchy of nested objects
    
    Returns:
        Dictionary 'a' with values from 'b' merged into it
    """
    for key in b:
        if key in a:
            if isinstance(a[key], dict) and isinstance(b[key], dict):
                merge_dict(a[key], b[key], path + [str(key)])
            elif a[key] == b[key]:
                pass # same leaf value
            else:
                log('    [*] Overriding default config setting: %s' % '.'.join(path + [str(key)]), 2)
                a[key] = b[key]
        else:
            log('    [-] WARNING: Unused setting %s. Setting may have a typo or be deprecated' % '.'.join(path + [str(key)]), 2)
            a[key] = b[key]
    return a


def group_input_filepaths(filepaths):
    """
    Create a dictionary of all data files supplied as arguments, grouped by NT domain
    and file type. 
    
    Args:
        filepaths: The list of data files supplied as arguments
    
    Returns:
        A dictionary of data files grouped by NT domain and file type
    """
    global data_objects
    
    data_files = {}
    
    # Read in all the arguments, group by NT domain, sort by date
    for filepath in filepaths:
        log('    [*] %s' % filepath, 2)
        (name, ext) = os.path.splitext(os.path.basename(filepath.lower()))
        
        for type in FILE_TYPES:
            if name.endswith(type):
                category = 'credentials' if type in CREDENTIAL_TYPES else type
                
                # Strip type (and the preceeding '_') from the end of the filename; date should now be the last value
                name = name.replace('_' + type, '')
                date = name.split('_')[-1]
                
                # Strip off the date and treat whatever remains as the NT domain
                # Accounts for cases where the NT domain may include an '_'
                nt_domain = name.replace('_' + date, '').upper()
                
                if nt_domain not in data_files:
                    data_files[nt_domain] = {}
                    data_objects[nt_domain] = {}
                
                if category not in data_files[nt_domain]:
                    data_files[nt_domain][category] = []
                    data_objects[nt_domain][category] = {}
                
                # Save parsed data about the current file
                # Save the actual type so the correct parsing function can be called later
                data_files[nt_domain][category].append({
                    'date': datetime.strptime(date, CONFIG_DATA['INPUT']['DATA']['FILENAME_DATE_FORMAT']),
                    'path': filepath,
                    'type': type
                })
                
                # IMPORTANT: Required for the 'for/else' to work
                break
        else:
            log('    [-] ERROR: Unable to determine file type for: %s' % filepath, 0)
    
    return data_files


def generate_ntlm(plaintext):
    """
    Creates an NTLM hash from the given plaintext password. Stores a mapping
    in ntlm_plaintext_map
    
    Args:
        plaintext: A plaintext password
    
    Returns:
        An uppercase hexadecimal string representing an NTLM hash
    """
    global ntlm_plaintext_map
    
    hash = hashlib.new('md4', plaintext.encode('utf-16le')).digest()
    ntlm = binascii.hexlify(hash).upper().decode('utf-8')
    
    # Store NTLM / plaintext association in the global map
    ntlm_plaintext_map[ntlm] = plaintext
    
    return ntlm


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
    
    # Source: https://support.microsoft.com/en-us/help/305144/how-to-use-useraccountcontrol-to-manipulate-user-account-properties
    UAC_FLAGS = {
        '0x0001': "Script",
        '0x0002': "Account Disabled",
        '0x0008': "Homedir Required",
        '0x0010': "Lockout",
        '0x0020': "Password Not Required",
        '0x0040': "Password Can't Change",
        '0x0080': "Encrypted Text Password Allowed",
        '0x0100': "Temp Duplicate Account",
        '0x0200': "Normal Account",
        '0x0800': "Interdomain Trust Account",
        '0x1000': "Workstation Trust Account",
        '0x2000': "Server Trust Account",
        '0x10000': "Password Doesn't Expire",
        '0x20000': "MNS Logon Account",
        '0x40000': "Smartcard Required",
        '0x80000': "Trusted For Delegation",
        '0x100000': "Not Delegated",
        '0x200000': "Use DES Key Only",
        '0x400000': "Don't Require PreAuth",
        '0x800000': "Password Expired",
        '0x1000000': "Trusted to auth for delegation",
        '0x04000000': "Partial Secrets Account"
    }
    
    flags = []
    
    for flag in UAC_FLAGS:
        # Perform a bitwise XOR to determine if the flag is part of the UAC value
        if int(uac) & int(flag, 16) == int(flag, 16):
            flags.append(UAC_FLAGS[flag])
    
    return CONFIG_DATA['OUTPUT']['DATA']['MULTI_OBJECT_DELIMITER'].join(sorted(flags))


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


def enhance_object(obj):
    """
    Performs various conversions and enhancements of AD object data
        - Picks the more recent of lastLogon and lastLogonTimestamp, and converts it to a human-readable timestamp
        - Converts pwdLastSet to a human-readable timestamp
        - If DNS data was provided, adds IP entries to computer objects
    
    Args:
        obj: A dictionary containing attributes of an Active Directory object; must contain an 'nt_domain' attribute
    
    Returns:
        An enhanced Active Directory object (dictionary)
    """
    
    nt_domain = obj['nt_domain']
    
    creds = data_objects[nt_domain]['credentials'] if 'credentials' in data_objects[nt_domain] else None
    gpo_data = data_objects[nt_domain]['gpos'] if 'gpos' in data_objects[nt_domain] else None
    
    delimiter = CONFIG_DATA['OUTPUT']['DATA']['MULTI_OBJECT_DELIMITER']
    
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
        log('    [-] WARNING: Object contains no name field', 2)
    
    # Standardize capitalization to ensure a proper look-up in the creds object
    name = name.lower()
    
    obj['id'] = name
    
    # Add credential fields
    if creds is not None:
        if name in creds:
            # Create a copy of the credential so that username isn't deleted from the original dictionary
            tmp_creds = creds[name].copy()
            del tmp_creds['username']
            obj.update(tmp_creds)
        elif name + '$' in creds:
            # Add credential fields for computer accounts
            # Create a copy of the credential so that username isn't deleted from the original dictionary
            tmp_creds = creds[name + '$'].copy()
            del tmp_creds['username']
            obj.update(tmp_creds)
    
    # Figure out the most recent logon time (between lastlogon and lastlogontimestamp)
    # Convert it to human-readable time
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
    hostname = name.upper()
    
    if hostname in hostname_map and 'ip' in hostname_map[hostname]:
        # Account for multiple IP addresses per host
        obj['ip'] = delimiter.join(set(hostname_map[hostname]['ip']))
    else:
        # Set a default so CSV writer doesn't get angry if it's empty
        obj['ip'] = ''
    
    # Replace values in gplink with human-readable names
    if gpo_data is not None and bool(gpo_data) and 'gplink' in obj.keys() and obj['gplink'] != '':
        gpos = []
        gpo_guids = GPO_NAME_PATT.findall(obj['gplink'].lower())
        
        for guid in gpo_guids:
            if guid in gpo_data and 'displayname' in gpo_data[guid]:
                gpos.append(gpo_data[guid]['displayname'])
            else:
                # All GPOs should be found, but just in case, it's good to know if data is missing
                gpos.append(guid)
        
        obj['gpos'] = delimiter.join(gpos)
        del obj['gplink']
    
    return obj


def merge_creds(cred):
    """
    Adds the specified credential data to the data_objects aggregator variable for the
    current domain if the username has not existing data or updates their credentials
    if they do
    
    Args:
        cred: A dictionary containing credentials
    """
    global data_objects
    
    debug(cred, 'Credential')
    
    nt_domain = cred['nt_domain']
    username = cred['username']
    
    # Ensure the NT domain and credentials keys exist
    if nt_domain not in data_objects:
        data_objects[nt_domain] = {
            'credentials': {}
        }
    
    if username in data_objects[nt_domain]['credentials']:
        data_objects[nt_domain]['credentials'][username].update(cred)
    else:
        data_objects[nt_domain]['credentials'][username] = cred
    
    # Update plaintext password to match NTLM (either an appropriate mapping from ntlm_plaintext_map or '')
    ntlm = cred['ntlm']
    plaintext = ntlm_plaintext_map[ntlm] if ntlm in ntlm_plaintext_map else ''
    data_objects[nt_domain]['credentials'][username]['plaintext'] = plaintext


#==============================================================================
#********                          DNS PARSER                          ********
#==============================================================================

def parse_dnscmd(filepath, nt_domain):
    """
    Reads and parses output from "dnscmd /zoneprint" to create a dictionary of hostnames and their associated IPs, CNAMEs, and FQDNs
    
    Args:
        filepath: The path to a file containing output from a "dnscmd /zoneprint" command
        nt_domain: NT domain
    """
    global data_objects
    global hostname_map
    
    log('    [*] Parsing DNSCMD output from: %s' % filepath)
    
    delimiter = CONFIG_DATA['OUTPUT']['DATA']['MULTI_OBJECT_DELIMITER']
    
    # Regex for A records
    A_REC_PATT = re.compile('^(?P<hostname>[a-zA-Z0-9\-]*?)\s.+?\s?\d*\sA\s(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$')
    
    # Regex for CNAME records
    CNAME_REC_PATT = re.compile('^(?P<alias>[a-zA-Z0-9\-]*?)\s[.+?\s]?\d*\sCNAME\s(?P<fqdn>[a-zA-Z0-9\-\.]*)$')
    
    zone = ''
    
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
            'nt_domain': nt_domain,
            'hostname': name
        }
        
        # Add other fields (if applicable), use set() to ensure only unique values
        if 'ip' in hostname_map[name]:
            obj['ip'] = delimiter.join(set(hostname_map[name]['ip']))
        
        if 'fqdn' in hostname_map[name]:
            obj['fqdn'] = delimiter.join(set(hostname_map[name]['fqdn']))
        
        if 'cname' in hostname_map[name]:
            obj['cname'] = delimiter.join(set(hostname_map[name]['cname']))
        
        # Storing the data in a dictionary using the hostname as the key ensures that entries from more recent files will overwrite the previous records
        data_objects[nt_domain]['dns'][name] = obj
    
    debug(hostname_map, 'Hostname to IP map')


#==============================================================================
#********                      CREDENTIAL PARSERS                      ********
#==============================================================================

def parse_credentials(filepath):
    """
    Parses Parseltongue credential output
    
    Args:
        filepath: The path to a file containing Parseltongue credential output
    """
    with open(filepath, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        
        for row in reader:
            merge_creds(row)


def parse_hashdump(filepath, nt_domain):
    """
    Parses output from a hashdump (in pwdump format) into a dictionary
    
    Args:
        filepath: The path to a file containing output from a pwdump hashdump
        nt_domain: NT domain
    """
    log('    [*] Parsing hashdump output from: %s' % filepath)
    
    with open(filepath, 'r') as hashdump:
        for line in hashdump.readlines():
            if ':' in line:
                (username, rid, lm_hash, nt_hash) = line.lower().split(':')[:4]
                ntlm = nt_hash.upper()
                merge_creds({'nt_domain': nt_domain, 'username': username, 'ntlm': ntlm, 'comment': 'hashdump'})


def parse_lsadump(filepath, nt_domain):
    """
    Parses output from Mimikatz lsadump into a dictionary
    
    Args:
        filepath: The path to a file containing output from Mimikatz lsadump
        nt_domain: NT domain
    """
    log('    [*] Parsing lsadump output from: %s' % filepath)
    username = ''

    with open(filepath, 'r') as lsadump:
        for line in lsadump.readlines():
            if 'User : ' in line:
                username = KV_PATT.search(line).groupdict()['value'].lower()
            elif 'NTLM : ' in line:
                ntlm = KV_PATT.search(line).groupdict()['value'].upper()
                
                if ntlm != '':
                    merge_creds({'nt_domain': nt_domain, 'username': username, 'ntlm': ntlm, 'comment': 'lsadump'})
                
                username = ''


def parse_cs_export(filepath, nt_domain):
    """
    Parses exported Cobalt Strike credentials into a dictionary
    
    Args:
        filepath: The path to a Cobalt Strike credential export file
        nt_domain: NT domain
    """
    log('    [*] Parsing Cobalt Strike credential export from: %s' % filepath)
    
    # Attempt to parse the input file as XML; if it throws a 
    # ParseError assume it is a text export
    try:
        tree = ElementTree.parse(filepath)
        credentials = tree.getroot()
        
        log('        [*] Auto-detected Cobalt Strike XML export', 2)
        
        # Save the invalid domain handling option for convenient access
        cs_export_settings = CONFIG_DATA['INPUT']['DATA']['CS_EXPORT']
        
        NTLM_PATT = re.compile('^[A-Fa-f0-9]{32}$')
        
        # Store user provided DNS to NT domain mapping for future use
        dns_to_nt_map = {}
        
        for entry in credentials.iter('entry'):
            # Convert entry back to XML for debugging
            debug('    ' + ElementTree.tostring(entry).decode('utf-8').replace('\t', '    ').strip(), 'XML entry')
            
            realm = entry.find('realm').text.upper()
            
            # Convert DNS domain to NT domain, if applicable and possible
            if realm in dns_to_nt_map:
                log('        [*] Replacing invalid realm %s with %s' % (realm, dns_to_nt_map[realm]), 2)
                realm = dns_to_nt_map[realm]
            
            cred = {
                'nt_domain': realm,
                'username': entry.find('user').text,
                'comment': entry.find('note').text if entry.find('note').text else ''
            }
            
            password = entry.find('password').text
            
            # Determine if the 'password' element is an NTLM hash or a plaintext password
            if NTLM_PATT.match(password):
                cred['ntlm'] = password.upper()
            else:
                # generate_ntlm() will store the plaintext in the ntlm_plaintext_map
                # merge_creds() will add the plaintext, so no need to store it here
                cred['ntlm'] = generate_ntlm(password)
            
            # IMPORTANT: Domain manipulation takes place after the password manipulation to ensure that any plaintext
            # passwords encountered still make it into the ntlm_plaintext_map for cracking and wordlist output
            
            # Determine whether the realm is a DNS domain rather than an NT one
            if '.' in cred['nt_domain']:
                setting = cs_export_settings['INVALID_REALM']
                
                if setting == 'replace':
                    log('        [*] Replacing invalid realm %s with %s' % (realm, nt_domain), 2)
                    cred['nt_domain'] = nt_domain
                elif setting == 'prompt':
                    while '.' in cred['nt_domain']:
                        log('        [*] %s is not a valid NT domain' % cred['nt_domain'])
                        cred['nt_domain'] = input('        [?] Please enter the NT domain that matches %s: ' % realm).upper()
                        
                        # Reset to the original value if user did not provide input
                        if cred['nt_domain'] == '':
                            cred['nt_domain'] = realm
                    
                    log('        [*] Replacing invalid realm %s with %s' % (realm, cred['nt_domain']), 2)
                    
                    # Add it to a map for future reference
                    dns_to_nt_map[realm] = cred['nt_domain']
                elif 'warn' in setting:
                    log('        [-] WARNING: %s is not a valid NT domain' % cred['nt_domain'])
                
                # If set to ignore, skip this entry and continue with the next
                if 'ignore' in setting:
                    continue
            
            # Skip foreign realms (i.e., ones that do not match the NT domain 
            # specified in the filename) if configured to do so
            if cred['nt_domain'] != nt_domain and cs_export_settings['FOREIGN_DOMAIN'] == 'ignore':
                continue
            
            # Optionally save the source and host information in the comment
            source = entry.find('source').text
            host = entry.find('host').text
            src_host_info = source if host is None else '%s on %s' % (source, host)
            
            if cred['comment'] == '' and cs_export_settings['POPULATE_COMMENT'] in ['append', 'empty_only']:
                cred['comment'] = src_host_info
            elif cred['comment'] != '' and cs_export_settings['POPULATE_COMMENT'] == 'append':
                cred['comment'] += '; %s' % src_host_info
            
            merge_creds(cred)
    except ParseError as e:
        if filepath.lower().endswith('xml'):
            log('        [-] ERROR: Filename indicates XML, but failed to parse XML; see error message below')
            log('            %s' % e)
            return
        
        log('        [*] Auto-detected Cobalt Strike text export', 2)
        
        NTLM_PATT = re.compile('^(?P<realm>.*?)\\\\(?P<username>.*?):::(?P<ntlm>[a-fA-F0-9]{32}):::$')
        PLAIN_PATT = re.compile('^(?P<realm>.*)\\\\(?P<username>.*?) (?P<plaintext>.*)$')
        
        with open(filepath, 'r') as in_file:
            for line in in_file.readlines():
                line = line.strip()
                
                data = NTLM_PATT.search(line)
                
                if data is not None:
                    data = data.groupdict()
                    realm = data['realm']
                    username = data['username'].lower()
                    ntlm = data['ntlm'].upper()
                    
                    if realm == nt_domain:
                        merge_creds({'nt_domain': nt_domain, 'username': username, 'ntlm': ntlm, 'comment': 'cs_export'})
                else:
                    data = PLAIN_PATT.search(line)
                    
                    if data is not None:
                        data = data.groupdict()
                        realm = data['realm']
                        username = data['username'].lower()
                        plaintext = data['plaintext']
                        
                        if realm == nt_domain:
                            merge_creds({'nt_domain': nt_domain, 'username': username, 'ntlm': generate_ntlm(plaintext), 'plaintext': plaintext, 'comment': 'cs_export'})


def parse_dcsync(filepath, nt_domain):
    """
    Parses output from Mimikatz dcsync into a dictionary
    
    Args:
        filepath: The path to a file containing output from Mimikatz dcsync
        nt_domain: NT domain
    """
    log('    [*] Parsing dcsync output from: %s' % filepath)
    
    cred = {'nt_domain': nt_domain}
    
    with open(filepath, 'r') as lsadump:
        for line in lsadump.readlines():
            if 'SAM Username         : ' in line:
                cred['username'] = KV_PATT.search(line).groupdict()['value'].lower()
            else:
                # Ensure the username is set before parsing hashes (prevents entry getting overwritten with values from OldCredentials
                if 'username' in cred:
                    if 'Hash NTLM: ' in line:
                        cred['ntlm'] = KV_PATT.search(line).groupdict()['value'].upper()
                    elif 'aes256_hmac       (4096) :' in line:
                        cred['aes256'] = KV_PATT.search(line).groupdict()['value'].upper()
                    elif 'aes128_hmac       (4096) :' in line:
                        cred['aes128'] = KV_PATT.search(line).groupdict()['value'].upper()
                        cred['comment'] = 'dcsync'
                        merge_creds(cred)
                        
                        # Entry is finish, reset object; require username to get reset before parsing more hashes so that aes256_hmac and aes128_hmac don't get overwritte by old credentials
                        cred = {'nt_domain': nt_domain}


def parse_logonpasswords(filepath, nt_domain):
    """
    Parses output from Mimikatz logonpasswords into a dictionary
    
    Args:
        filepath: The path to a file containing output from Mimikatz logonpasswords
        nt_domain: NT domain
    """
    log('    [*] Parsing logonpasswords output from: %s' % filepath)
    
    cred = {'nt_domain': nt_domain}
    usernames = []
    realmified_username = ''
    
    with open(filepath, 'r') as lsadump:
        for line in lsadump.readlines():
            if 'User Name         : ' in line:
                username = KV_PATT.search(line).groupdict()['value'].lower()
                
                if username not in ['(null)', 'local service', 'dwm-1']:
                    cred['username'] = username
                    
                    # Initialize NTLM so password cracker output doesn't get angry
                    cred['ntlm'] = ''
            elif 'username' in cred:
                # If there was no valid username for the block, ignore everything else
                if 'Domain            : ' in line:
                    cred['nt_domain'] = line.split(':')[1].strip()
                    realmified_username = '%s\%s' % (cred['nt_domain'], cred['username'])
                elif 'NTLM     : ' in line:
                    cred['ntlm'] = KV_PATT.search(line).groupdict()['value'].upper()
                elif 'Password : ' in line and not cred['username'].endswith('$'):
                    # Save plaintext password if it's not null or for a computer account (< 128)
                    # Use regex to make sure we get the entire password, even if it ends with a space
                    password = KV_PATT.search(line).groupdict()['value']
                    
                    if password != '(null)' and len(password) < 128:
                        cred['plaintext'] = password
                        
                        # Generate NTLM to ensure correct mapping and to save the 
                        # association to the global ntlm_plaintext_map
                        cred['ntlm'] = generate_ntlm(password)
                elif 'credman :' in line:
                    # Last line of the entry, save the current object to the dictionary if the hash was populated, and reset the object for the next entry
                    if cred['ntlm'] != '':
                        # Newer entries appear at the top of the file, so only keep the
                        # first entry for each user (include the domain in case you have
                        # the same username from different domains)
                        if realmified_username not in usernames:
                            cred['comment'] = 'logonpasswords'
                            merge_creds(cred)
                            
                            # Add the username to a list so we don't overwrite their information using subsequent entries
                            usernames.append(realmified_username)
                        else:
                            # Warn user if a duplicate is detected; only saving the first of each entry "should" work...but doesn't hurt to manually verify
                            print('')
                            log('    [-] WARNING: Duplicate username (%s) detected in logonpasswords; manually verify which creds are accurate\n' % cred['username'], 0)
                    
                    cred = {'nt_domain': nt_domain}


#=============================================================================
#********                       DSQUERY PARSER                        ********
#=============================================================================

def parse_ad_objects(data_type, filepath, nt_domain, fieldnames):
    """
    Reads output from a dsquery command and parses into a list of dictionaries, each representing an AD object; attempts to enhance the raw data
    
    Args:
        filepath: The path to a file containing output from a dsquery command
        nt_domain: NT domain
        fieldnames: The list of expected object attributes; the last object in the list is used to delimit object entries; it MUST exist AND be unique
    """
    global data_objects
    log('    [*] Parsing dsquery output from: %s' % filepath)
    
    obj = {'nt_domain': nt_domain}
    
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
                        obj[key] = obj[key] + CONFIG_DATA['OUTPUT']['DATA']['MULTI_OBJECT_DELIMITER'] + value
                    else:
                        obj[key] = value
                    
                    # Save the object when the last entry is read and re-initialize the object
                    # IMPORTANT: The last element must be unique, otherwise objects won't be delimited properly
                    if key == fieldnames[-1]:
                        obj = enhance_object(obj)
                        data_objects[nt_domain][data_type][obj['id']] = obj
                        debug(obj, 'AD object (%s)' % data_type)
                        obj = {'nt_domain': nt_domain}


#=============================================================================
#********                  INPUT / OUTPUT FUNCTIONS                   ********
#=============================================================================

def save_config(config_path, gen_config=True):
    """
    Saves the contents of CONFIG_DATA to the specified path.
    
    Used to write the default settings to a new config file or optionally 
    update a config file using command-line settings if the '--save-config'
    option is specified
    
    Args:
        config_path: The path to the config file to be created
        gen_config: A boolean indicating whether a new config file should 
                    be created if one does not exist
    """
    create_config = True
    
    # If config file doesn't exist and '--generate-config' was NOT specified, prompt the user whether they want to create the file
    if not os.path.isfile(config_path) and config_path != DEFAULT_CONFIG_FILEPATH and not gen_config:
        create_config = input('[-] ERROR: %s does not exist; do you want to create it? [Y | n]: ' % config_path).lower() not in ['n', 'no']
    
    if create_config:
        action = 'Updating' if os.path.isfile(config_path) else 'Creating'
        
        log('[*] %s config file: %s' % (action, config_path), 0)
        
        with open(config_path, 'w') as outfile:
            json.dump(CONFIG_DATA, outfile, indent=4)


def load_config(config_path, verbosity):
    """
    Loads config data from the specified file, if it exists, and updates the scripts default settings
    
    Args:
        config_path: The path to the config file from which to load data
    """
    global CONFIG_DATA
    
    log('[*] Loading config: %s' % config_path, 2)
    
    if os.path.exists(config_path):
        with open(config_path, 'r') as infile:
            loaded_config = json.load(infile)
            
            # Override config with loaded config; maintain any defaults not specified in the loaded config to ensure they exist
            merge_dict(CONFIG_DATA, loaded_config)
            #CONFIG_DATA.update(loaded_config)
        
        # If specified as a command-line argument, reset verbosity prior to calls to log()
        if verbosity is not None:
            CONFIG_DATA['VERBOSITY'] = verbosity
        
        log('[+] Successfully loaded config: %s\n' % config_path)
    else:
        log('[-] ERROR: Config file (%s) does not exist; exiting...' % config_path, 0)
        sys.exit(1)


def load_wordlist(filepath):
    """
    Reads a list of plaintext passwords from a file (one per line), generates NTLM
    hashes for each, and stores the mapping in ntlm_plaintext_map. This is used for 
    rudimentary password cracking
    
    Args:
        filepath: The path to a wordlist file
    
    Returns:
        A boolean indicating whether the wordlist was successfully loaded or not
    """
    log('    [*] Loading wordlist: %s' % filepath, 2)
    
    if os.path.isfile(filepath):
        # Read all plaintext passwords from file, generate NTLM hashes and store them in ntlm_plaintext_map
        with open(filepath, 'r') as in_file:
            for password in in_file.readlines():
                # Don't strip spaces because Windows allows spaces at the end of passwords... :-/
                generate_ntlm(password.strip('\t\n'))
        
        return True
    
    log('    [-] WARNING: Wordlist %s does not exist' % os.path.abspath(filepath))
    return False


def load_wordlists():
    """
    Loads plaintext passwords from a single file or from all files in or below a directory
    """
    filepath = CONFIG_DATA['INPUT']['WORDLIST']
    wordlists_loaded = 0
    
    log('[*] Loading wordlist(s) from: %s' % filepath)
    
    if os.path.isdir(filepath):
        # Walk the specified wordlist dir and add all files
        for root, dirs, files in os.walk(filepath):
            for file in files:
                wordlists_loaded += 1 if load_wordlist(os.path.join(root, file)) else 0
    else:
        wordlists_loaded += 1 if load_wordlist(filepath) else 0
    
    # It is impossible to have a partial success, either all files are loaded or none are.
    # If a single file is specified and it exists, it will be parsed (wordlists_loaded == 1);
    # if it doesn't exist (wordlists_loaded == 0).
    # If a directory is specified, it either has files which will be parsed (wordlists_loaded > 0)
    # or it has no files, in which case wordlists_loaded == 0
    if wordlists_loaded > 1:
        log('[+] Successfully loaded %i wordlists\n' % wordlists_loaded)
    elif wordlists_loaded == 1:
        log('[+] Successfully loaded 1 wordlist\n')
    else:
        log('[-] WARNING: Failed to load wordlist(s)\n')


def write_output(nt_domain, data_type):
    """
    Writes structured system data to a CSV file
    
    Args:
        nt_domain: An NT domain that exists in data_objects
        data_type: A string indicating the type of data (must exist as a key as FILE_TYPE_MAP)
    """
    objects = data_objects[nt_domain][data_type].values() if nt_domain in data_objects and data_type in data_objects[nt_domain] else []
    
    if len(objects) > 0:
        output_dir = CONFIG_DATA['OUTPUT']['DATA']['DIR']
        
        # Optionally, separate output by NT domain
        if CONFIG_DATA['OUTPUT']['DATA']['SEPARATE_BY_DOMAIN']:
            output_dir = os.path.join(output_dir, 'nt_domain')
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok = True)
        
        # Format: '<output_dir>/<nt_domain>_<date>'
        output_prefix = os.path.join(output_dir, '%s_%s' % (nt_domain, datetime.now().strftime(CONFIG_DATA['OUTPUT']['DATA']['FILENAME_DATE_FORMAT'])))
        
        # Format: '<output_dir>/<nt_domain>_<date>_<data_type>.csv'
        output_filepath = '%s_%s.csv' % (output_prefix, data_type)
        
        log('    [*] Writing output to: %s' % output_filepath)
        
        fieldnames = FILE_TYPE_MAP[data_type]
        
        # Modify fieldnames, if applicable
        if data_type == 'users':
            fieldnames += ['plaintext', 'ntlm', 'aes128', 'aes256', 'comment']
        elif data_type == 'computers':
            fieldnames.insert(0, 'ip')
            fieldnames += ['ntlm', 'aes128', 'aes256', 'comment']
        elif data_type == 'ous':
            fieldnames = [name if name != 'gplink' else 'gpos' for name in fieldnames]
        
        # Remove lastLogonTimestamp because it's merged with lastLogon
        if 'lastlogontimestamp' in fieldnames:
            fieldnames.remove('lastlogontimestamp')
        
        try:
            with open(output_filepath, 'w', newline='') as csvfile:
                # Quote all fields in case some data (e.g., plaintext passwords) contain commas
                # Ignore any extra fields not in fieldnames
                writer = csv.DictWriter(csvfile, fieldnames=['nt_domain'] + fieldnames, quoting=csv.QUOTE_ALL, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(objects)
            
            # If writing credential data, output a bonus file formatted for password cracker ingestion
            if data_type == 'credentials':
                with open('%s_%s.txt' % (output_prefix, 'password_cracker_ingest'), 'w', newline='') as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=['username', 'ntlm'], delimiter=':', extrasaction='ignore')
                    
                    # Only output credentials for cracking if we don't already have the plaintext
                    for obj in objects:
                        if 'plaintext' in obj and obj['plaintext'] == '':
                            writer.writerow(obj)
        except IOError as e:
            input('    [-] Write failed; do you have the file open? ')
            write_output(nt_domain, data_type)
    else:
        log('    [*] No %s detected; skipping...' % data_type, 2)
        log('        If you think this is a mistakes, try checking that your input file encoding is UTF-8', 2)


def write_wordlist():
    """
    Optionally outputs a plaintext wordlist that contains all parsed plaintext 
    passwords, as well as all passwords initally loaded from a wordlist
    """
    if CONFIG_DATA['OUTPUT']['WORDLIST']:
        filepath = CONFIG_DATA['OUTPUT']['WORDLIST']
        
        # Extract (first) date format from filepath
        # For example, '%Y-%m-%d' from 'wordlists\\wordlist_<%Y-%m-%d>.txt'
        date_format = re.search('<(.*?)>', filepath)
        
        # If a date format was specified, replace the placeholder with today's date
        if date_format:
            date_str = datetime.now().strftime(date_format.group(1))
            filepath = re.sub('<(.*?)>', date_str, filepath)
        
        # IMPORTANT:
        # The WORDLIST output config option can be used to specify a custom 
        # directory path and filename. If a static filename is specified, 
        # the file will be overwritten. Alternatively, a date format can be
        # specified within '<>'; this will create separate wordlists based 
        # on the datetime string
        
        # Ensure any custom output directories exist
        output_dir = os.path.dirname(filepath)
        os.makedirs(output_dir, exist_ok=True)
        
        with open(filepath, 'w') as out_file:
            out_file.writelines('\n'.join(sorted(ntlm_plaintext_map.values())))


def main():
    """
    Parses command-line arguments, loads config and (optionally) wordlist data,
    sorts and processes input files, and writes processed output
    """
    global CONFIG_DATA
    
    term_width = os.get_terminal_size().columns
    
    if term_width >= 107:
        # Large banner requires a terminal width of at least 107 to display without wrapping
        print(BANNER_LG)
    elif term_width >= 73:
        # Large banner requires a terminal width of at least 73 to display without wrapping
        print(BANNER_SM)
    
    start_time = datetime.now()
    
    # Log entire command-line for context; add an extra new line for readability
    log(' '.join(sys.argv) + '\n', suppress=True)
    log('Parseltongue v%s\n' % VERSION)
    
    # Parse command-line arguments
    parser = ArgumentParser(description='Parses Windows system data and outputs CSV files to facilitate analysis')
    parser.add_argument('filepaths', metavar='data_filepath', nargs='*', help='Paths to files containing system data (e.g., dsquery, dnscmd, etc.)')
    parser.add_argument('-c', '--config', dest='config_filepath', default=DEFAULT_CONFIG_FILEPATH, help='Path to config file')
    parser.add_argument('--debug', dest='debug', action='store_true', help='Enable debugging output to log file')
    parser.add_argument('-d', '--delimiter', dest='delimiter', help='Character to delimit multiple objects (overrides config file setting)')
    parser.add_argument('-g', '--generate-config', dest='gen_config', action='store_true', help='Generate a default config file')
    parser.add_argument('-o', '--output', dest='output_dir', help='Output directory (overrides config file setting)')
    parser.add_argument('-s', '--show', dest='show_dsqueries', action='store_true', help='Show dsquery commands')
    parser.add_argument('-u', '--update-config', dest='update_config', action='store_true', help='Update config file based on command-line arguments')
    parser.add_argument('-v', '--verbosity', dest='verbosity', type=int, choices=[0, 1, 2], help='Control output verbosity')
    parser.add_argument('-w', '--wordlist', dest='wordlist', help='A wordlist file (one plaintext password per line) OR a directory containing wordlist files; used for rudimentary password cracking ')
    args = parser.parse_args()
    
    debug(args, 'Parsed arguments')
    
    # Print usage info if run without args
    if len(sys.argv) == 1:
        print_usage(parser)
        sys.exit(0)
    
    debug(CONFIG_DATA, 'Config data prior to arg parsing')
    
    # Set the verbosity immediately so it takes effect before config parsing functions
    if args.verbosity is not None:
        CONFIG_DATA['VERBOSITY'] = args.verbosity
    
    # Log start time; add an extra newline for readability
    log('[+] Start Time: %s\n' % start_time.strftime(CONFIG_DATA['LOGGING']['TIMEFORMAT_LOG']), 0)
    
    # Optionally create config file if it does not exist
    if not os.path.exists(args.config_filepath):
        save_config(args.config_filepath, args.gen_config)
    
    # Load custom config data, if config file exists
    load_config(args.config_filepath, args.verbosity)
    
    # Override config data with command-line arguments
    if args.debug:
        CONFIG_DATA['DEBUG'] = args.debug
    
    # Override config data with command-line arguments
    if args.output_dir:
        CONFIG_DATA['OUTPUT']['DATA']['DIR'] = args.output_dir
    
    if args.delimiter:
        CONFIG_DATA['OUTPUT']['DATA']['MULTI_OBJECT_DELIMITER'] = args.delimiter
    
    if args.wordlist:
        if os.path.exists(args.wordlist):
            CONFIG_DATA['INPUT']['WORDLIST'] = args.wordlist
        else:
            # Exit if the user manually specified a wordlist path that doesn't exist
            log('[-] ERROR: Wordlist %s does not exist' % args.wordlist, 0)
            sys.exit(1)
    
    debug(CONFIG_DATA, 'Config data after to arg parsing')
    
    if args.update_config:
        save_config(args.config_filepath)
    
    if args.show_dsqueries:
        print_dsquery_commands()
        sys.exit(0)
    
    # If no files specified, simply print the updated config and exit
    if len(args.filepaths) == 0:
        log('[*] No files specified; printing config and exiting\n')
        print_config()
        sys.exit(0)
    
    # Import a list of plaintext passwords for basic password cracking
    if CONFIG_DATA['INPUT']['WORDLIST']:
        load_wordlists()
    
    debug(ntlm_plaintext_map, 'Wordlist loaded into ntlm_plaintext_map')
    
    log('[*] Organizing input files...', 0)
    
    # Read in all the arguments, group by NT domain
    data_files = group_input_filepaths(args.filepaths)
    
    debug(data_files, 'Input filenames grouped by domain and type')
    
    # Add an extra newline for readability
    log('[+] Finished organizing input files...\n')
    
    # Loop through all of the files now that they are grouped
    for nt_domain in data_files:
        log('[*] Parsing %s domain...' % nt_domain, 0)
        
        # Explicitly parse credential data because it won't match any of the file types iterated through below
        if 'credentials' in data_files[nt_domain]:
            for file_dict in sorted(data_files[nt_domain]['credentials'], key = lambda i: i['date']):
                filepath = file_dict['path']
                type = file_dict['type']
                
                if type == 'credentials':
                    parse_credentials(filepath)
                elif type == 'hashdump':
                    parse_hashdump(filepath, nt_domain)
                elif type == 'lsadump':
                    parse_lsadump(filepath, nt_domain)
                elif type == 'cs_export':
                    # Parse Cobalt Strike credentials export
                    parse_cs_export(filepath, nt_domain)
                elif type == 'dcsync':
                    parse_dcsync(filepath, nt_domain)
                elif type == 'logonpasswords':
                    parse_logonpasswords(filepath, nt_domain)
        
        # IMPORTANT: Loop through in the specified order so GPO and DNS data are parsed before computers
        # This is necessary so the computer and OU objects can be enhanced
        # If you add new data types to the FILE_TYPE_MAP, you must add them to this list as well, in order for the script to parse them
        for type in ['dns', 'gpos', 'groups', 'ous', 'computers', 'users']:
            if type in data_files[nt_domain]:
                # Loop through all files of the given type, sorted by date
                for file_dict in sorted(data_files[nt_domain][type], key = lambda i: i['date']):
                    filepath = file_dict['path']
                    
                    if type == 'dns':
                        parse_dnscmd(filepath, nt_domain)
                    else:
                        # Parse Active Directory objects (e.g., dsquery output)
                        parse_ad_objects(type, filepath, nt_domain, FILE_TYPE_MAP[type])
        
        # Add an extra newline for readability
        log('[+] Finished parsing the %s domain\n' % nt_domain, 0)
    
    log('[*] Parsing complete; writing output...', 0)
    
    debug(data_objects, 'All parsed data')
    
    # Write out parsed data
    for nt_domain in data_objects:
        for type in FILE_TYPE_MAP:
            if type in data_objects[nt_domain]:
                write_output(nt_domain, type)
    
    debug(ntlm_plaintext_map, 'Final NTLM to plaintext mapping')
    
    # Output plaintext wordlist
    write_wordlist()
    
    end_time = datetime.now()
    
    log('[+] Done!', 0)
    # Add an extra newline for readability
    log('')
    log('[+] End Time: %s' % end_time.strftime(CONFIG_DATA['LOGGING']['TIMEFORMAT_LOG']))
    log('[+] Time Elapsed: %s' % str(end_time - start_time))


if __name__ == "__main__":
    main()