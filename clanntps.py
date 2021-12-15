#! /usr/bin/python3
#
# @(!--#) @(#) clanntps.py, sversion 0.1.0, fversion 012, 16-june-2021
#
# a NTP server for closed LANS
#
# use Ctrl+Break instead of Ctrl^C to interrupt
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

def logmessage(message):
    global progname
    global logfile
    
    if logfile != None:
        timestamp ='{:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now())
        
        print('{}: {} - {}'.format(progname, timestamp, message), file=logfile)
        
        logfile.flush()
        
##############################################################################

def showpacket(bytes):
    bpr = 16              # bpr is Bytes Per Row
    numbytes = len(bytes)

    if numbytes == 0:
        print("<empty packet>")
    else:
        i = 0
        while i < numbytes:
            if (i % bpr) == 0:
                print("{:04d} :".format(i), sep='', end='')

            print(" {:02X}".format(bytes[i]), sep='', end='')

            if ((i + 1) % bpr) == 0:
                print()

            i = i + 1

    if (numbytes % bpr) != 0:
        print()

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

    logmessage('begin listen loop')
    
    while True:
        inpacket, address = listensocket.recvfrom(MAX_PACKET_SIZE)

        receivetime = ntptime()

        if loglevel >= 1:
            showpacket(inpacket)

        leninpacket = len(inpacket)
        
        if leninpacket == 0:
            logmessage('packet received but it does not contain any data bytes')
            continue

        if leninpacket != 48:
            logmessage('packet not correct length (should be 48 but got {})'.format(leninpacket))
            continue

        versionnumber = (inpacket[0] & 0x38) >> 3
        
        if (versionnumber != 3) and (versionnumber != 4):
            logmessage('packet version not supported (should be 3 or 4 but got {})'.format(versionnumber))
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

        if loglevel >= 1:
            showpacket(outpacket)

        # send the response
        listensocket.sendto(outpacket, address)

##############################################################################

def main():
    global progame
    global logfile
    
    parser = argparse.ArgumentParser()
    
    parser.add_argument('--bindip',   help='IP address to bind to', required=True)
    parser.add_argument('--logfile',  help='log file name', default=DEFAULT_LOG_FILE_NAME)
    parser.add_argument('--loglevel', help='logging level', default=DEFAULT_LOG_LEVEL)

    args = parser.parse_args()

    bindip = args.bindip    
    
    logfilename = args.logfile
    
    try:
        loglevel = int(args.loglevel)
    except ValueError:
        print('{}: argument to --loglevel option must be an integer'.format(progname), file=sys.stderr)
        sys.exit(1)
        
    print('{}: bind IP address: {}, log filename: {}, log level: {}'.format(progname, bindip, logfilename, loglevel))
    
    try:
        logfile = open(logfilename, 'a+')
    except IOError:
        print('{}: unable to open log file "{}" for writing with append - exiting'.format(progname, logfilename), file=sys.stderr)
        sys.exit(1)
    
    logmessage('starting')
        
    logmessage('creating socket')
    listensocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    logmessage('socket created ok')
    
    logmessage('binding socket to IP {}'.format(bindip))
    try:
        listensocket.bind((bindip, 123))
    except IOError:
        message = 'IOError while trying to bind to IP address {} - is "Windows Time" service running?'.format(bindip)
        print('{}: {}'.format(progname, message), file=sys.stderr)
        logmessage(message)
        sys.exit(1)
    logmessage('socket bound ok')
        
    logmessage('calling listensocket() function')
    listenloop(listensocket)

    ### listensocket.close()
    
    return 0    

##############################################################################

progname = os.path.basename(sys.argv[0])

logfile = None

loglevel = 0

sys.exit(main())

# end of file
