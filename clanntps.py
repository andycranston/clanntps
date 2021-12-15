#! /usr/bin/python3
#
# @(!--#) @(#) clanntps.py, sversion 0.1.0, fversion 013, 16-june-2021
#
# a NTP server for closed LANS
#
# for Linux - dameon with at or nohup
#

#
# Links
#
#   https://www.meinbergglobal.com/english/info/ntp-packet.htm
#   https://tools.ietf.org/html/rfc1305
#   https://www.unixtimestamp.com/
#

##############################################################################

#
# imports
#


import sys
import os
import argparse
import time
import datetime
import socket
import syslog
import math

##############################################################################

#
# constants
#

DEFAULT_LOG_FILE_NAME = 'clanntps.log'
DEFAULT_LOG_LEVEL = 0

MAX_PACKET_SIZE = 32768

MIN_VALID_NTPV3_PACKET_LENGTH = 48

##############################################################################

def bytes2hexstring(bytes):
    hs = ''

    for byte in bytes:
        if hs != '':
            hs += ':'
        hs += '{:02X}'.format(byte)

    return hs

##############################################################################

def ntptime():
    ntp = bytearray(8)

    utc = time.time()

    utcint = (int(math.floor(utc)) & 0xFFFFFFFF) + 2208988800

    ntp[0] = (utcint & 0xFF000000) >> 24
    ntp[1] = (utcint & 0x00FF0000) >> 16
    ntp[2] = (utcint & 0x0000FF00) >> 8
    ntp[3] = (utcint & 0x000000FF)

    utcfrac = utc - math.floor(utc)

    binary = ''

    for i in range(0, 32):
        mult2 = 2.0 * utcfrac

        ### print(utcfrac, mult2)

        if mult2 >= 1.0:
            binary += '1'
        else:
            binary += '0'

        utcfrac = mult2 - math.floor(mult2)

    i = 0

    for byte in range(4, 8):
        v = 0

        m = 128

        for bit in range(0, 8):
            if binary[i] == '1':
                v = v + m
            i +=1
            m = m // 2

        ntp[byte] = v

    return ntp

##############################################################################

def listenloop(listensocket):
    global loglevel

    syslog.syslog('begin listen loop')
    
    while True:
        inpacket, address = listensocket.recvfrom(MAX_PACKET_SIZE)

        receivetime = ntptime()

        leninpacket = len(inpacket)

        syslog.syslog('packet receive - length {} - address {} - port {}'.format(leninpacket, address[0], address[1]))
        
        if leninpacket == 0:
            syslog.syslog('packet received but it does not contain any data bytes')
            continue

        syslog.syslog(bytes2hexstring(inpacket))

        if leninpacket != 48:
            syslog.syslog('packet not correct length (should be 48 but got {})'.format(leninpacket))
            continue

        versionnumber = (inpacket[0] & 0x38) >> 3
        
        if (versionnumber != 3) and (versionnumber != 4):
            syslog.syslog('packet version not supported (should be 3 or 4 but got {})'.format(versionnumber))
            continue

        # create empty outpacket
        outpacket = bytearray(48)
        
        # set leap indicator (LI), version and mode
        if versionnumber == 3:
            # LI = 00, version = 3, mode = 4
            outpacket[0] = 0x1C
        elif versionnumber == 4:
            # LI = 00, version = 4, mode = 4
            outpacket[0] = 0x24

        # set stratum
        outpacket[1] = 4

        # set poll
        outpacket[2] = 6

        # set precision
        outpacket[3] = 256 - 45

        # set root delay
        outpacket[4] = 0
        outpacket[5] = 0
        outpacket[6] = 0
        outpacket[7] = 0

        # set root dispersion
        outpacket[8]  = 0
        outpacket[9]  = 0
        outpacket[10] = 0
        outpacket[11] = 0

        # set reference ID to 'Andy'
        outpacket[12] = ord('A')
        outpacket[13] = ord('n')
        outpacket[14] = ord('d')
        outpacket[15] = ord('y')

        # set reference timestamp to be receive time without the fractional part
        outpacket[16:20] = receivetime[0:4]
        outpacket[20]    = 0
        outpacket[21]    = 0
        outpacket[22]    = 0
        outpacket[23]    = 0
        
        # copy transmit timestamp from inpacket to originator timestamp in outpacket
        outpacket[24:32] = inpacket[40:48]

        # set receivetime
        outpacket[32:40] = receivetime

        # transmit time
        outpacket[40:48] =  ntptime()

        # send the response
        listensocket.sendto(outpacket, address)

        # log the send
        syslog.syslog('packet sent')
        syslog.syslog(bytes2hexstring(outpacket))

##############################################################################

def main():
    global progame
    
    parser = argparse.ArgumentParser()
    
    parser.add_argument('--bind', help='IP address to bind to', required=True)

    args = parser.parse_args()

    syslog.openlog(progname, logoption=syslog.LOG_PID, facility=syslog.LOG_LOCAL0)

    syslog.syslog('starting')
        
    syslog.syslog('creating socket')

    listensocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    syslog.syslog('binding socket')

    try:
        listensocket.bind((args.bind, 123))
    except IOError:
        message = 'IOError while trying to bind to IP address {}'.format(args.bindip)

        syslog.syslog(message)

        print('{}: {}'.format(progname, message), file=sys.stderr)

        sys.exit(1)

    listenloop(listensocket)

    return 0    

##############################################################################

progname = os.path.basename(sys.argv[0])

logfile = None

loglevel = 0

sys.exit(main())

# end of file
