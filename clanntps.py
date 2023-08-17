#! /usr/bin/python3
#
# @(!--#) @(#) clanntps.py, sversion 0.2.0, fversion 016, 17-august-2023
#
# a NTP server for closed LANS
#
# for Linux - dameon with at or nohup
#
# added a skew file '/usr/local/etc/clanntps.skew'
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
import socket
import syslog
import math

##############################################################################

#
# constants
#

MAX_PACKET_SIZE = 32768
SKEW_FILE_NAME = '/usr/local/etc/clanntps.skew'

##############################################################################

def bytes2hexstring(bytes):
    hs = ''

    for byte in bytes:
        if hs != '':
            hs += ':'
        hs += '{:02X}'.format(byte)

    return hs

##############################################################################

def ntptime(skewoffset):
    ntp = bytearray(8)

    utc = time.time()

    utcint = (int(math.floor(utc)) & 0xFFFFFFFF) + 2208988800

    utcint = utcint + skewoffset

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

def listenloop(listensocket, skewips):
    syslog.syslog('begin listen loop')
    
    while True:
        inpacket, address = listensocket.recvfrom(MAX_PACKET_SIZE)

        if address[0] in skewips:
            skewoffset = skewips[address[0]]
        else:
            skewoffset = 0

        receivetime = ntptime(skewoffset)

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
        outpacket[40:48] =  ntptime(skewoffset)

        # send the response
        listensocket.sendto(outpacket, address)

        # log the send
        syslog.syslog('packet sent - length {} - address {} - port {}'.format(len(outpacket), address[0], address[1]))
        syslog.syslog(bytes2hexstring(outpacket))

##############################################################################

def validint(s):
    if s == '':
        return False

    if (s[0] == '-') or (s[0] == '+'):
        s = s[1:]

    if s == '':
        return False

    for c in s:
        if not (c.isdigit()):
            return False

    return True

##############################################################################

def main():
    global progame
    
    parser = argparse.ArgumentParser()
    
    parser.add_argument('--bind',
                        required=True,
                        help='IP address to bind to') 

    parser.add_argument('--skew',
                        default=SKEW_FILE_NAME,
                        help='name of skew file') 

    args = parser.parse_args()

    syslog.openlog(progname, logoption=syslog.LOG_PID, facility=syslog.LOG_LOCAL0)

    syslog.syslog('starting')
        
    skewips = {}

    try:
        skewfile = open(args.skew, 'r', encoding='utf-8')

        linenum = 0

        for line in skewfile:
            linenum += 1

            line = line.strip()

            if line == '':
                continue

            if line[0] == '#':
                continue

            words = line.split()

            if words[0] == 'skew':
                if len(words) >= 3:
                    ipaddress = words[1]
                    offset = words[2]

                    if not validint(offset):
                        syslog.syslog('line {} in skew file "{}" has invalid offset of "{}"'.format(linenum, args.skew, offset))
                        continue

                    offset = int(offset)

                    skewips[ipaddress] = offset

        skewfile.close()
    except IOError:
        syslog.syslog('ignoring skew file "{}" as it cannot be opened for reading'.format(args.skew))

    if len(skewips) > 0:
        for ip in skewips:
            syslog.syslog('skewing time for IP {} by {} seconds'.format(ip, skewips[ip]))

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

    listenloop(listensocket, skewips)

    return 0    

##############################################################################

progname = os.path.basename(sys.argv[0])

sys.exit(main())

# end of file
