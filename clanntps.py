#! /usr/bin/python3
#
# @(!--#) @(#) clanntps.py, sversion 0.1.0, fversion 008, 13-june-2021
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

def bytes2text(ba):
    text = ''
    
    for i in range(0, len(ba)):
        byte = ba[i]
        text += '{:02X}'.format(byte)
        
    return text

##############################################################################

def bytes2int(ba):
    v = 0
    
    for i in range(0, len(ba)):
        v = v << 8
        b = ba[i]
        v += b
    
    return v

##############################################################################

def int2fourbytes(v):
    ba = bytearray(4)
    
    ba[0] = (v & 0xFF000000) >> 24
    ba[1] = (v & 0x00FF0000) >> 16
    ba[2] = (v & 0x0000FF00) >> 8
    ba[3] = (v & 0x000000FF) >> 0
    
    return ba

##############################################################################

def float2binarystring(f):
    binarystring = ''
    negativepower = 1.0

    for i in range(0, 16):
        negativepower = negativepower / 2.0

        if f > negativepower:
            binarystring += '1'
            f = f - negativepower
        else:
            binarystring += '0'

    return binarystring

##############################################################################

def binarystring2int(binarystring):
    v = 0

    for i in range(0, len(binarystring)):
        v = v * 2
        if binarystring[i] == '1':
            v += 1

    return v

##############################################################################

def ntptimenowbytes():
        utcnow = time.time()
        utcsecondsnow = int(math.floor(utcnow))
        utcfractionnow = utcnow - float(utcsecondsnow)
        inbinary = float2binarystring(utcfractionnow)
        
        bytes = bytearray(8)
        
        bytes[0:4] = int2fourbytes(utcsecondsnow + 2208988800)
        bytes[4] = binarystring2int(inbinary[0:8])
        bytes[5] = binarystring2int(inbinary[8:16])

        return bytes        

##############################################################################

def listenloop(listensocket):
    logmessage('begin listen loop')
    
    while True:
        packet, address = listensocket.recvfrom(MAX_PACKET_SIZE)
        
        receiventp = ntptimenowbytes()
        
        if loglevel >= 1:
            showpacket(packet)

        lenpacket = len(packet)
        
        if lenpacket == 0:
            logmessage('packet received but it does not contain any data bytes')
            continue
            
        flags = packet[0]
        
        leapindicator = (flags & 0xC0) >> 6
        versionnumber = (flags & 0x38) >> 3
        mode          = (flags & 0x03) >> 0
        
        if (versionnumber != 3) and (versionnumber != 4):
            logmessage('packet received but version number is not 3 or 4')
            continue
        
        if lenpacket < MIN_VALID_NTPV3_PACKET_LENGTH:
            logmessage('packet received but is too short to be a valid NTP packet')
            continue
        
        stratum         = packet[1]
        pollinterval    = packet[2]
        clientprecision = packet[3]
        
        rootdelaybytes      = packet[4:8]
        rootdispersionbytes = packet[8:12]
        referenceidbytes    = packet[12:16]
        referencetimebytes  = packet[16:24]
        origintimebytes     = packet[24:32]
        receivetimebytes    = packet[32:40]
        transmittimebytes   = packet[40:48]
        
        if loglevel >= 1:
            logmessage('Reference time .....: {}'.format(bytes2int(referencetimebytes[0:4])))
            logmessage('Origin time ........: {}'.format(bytes2int(origintimebytes[0:4])))
            logmessage('Receive time .......: {}'.format(bytes2int(receivetimebytes[0:4])))
            logmessage('Transmit time ......: {}'.format(bytes2int(transmittimebytes[0:4])))
        
        fourzeroes = bytearray(4)
        
        transmitseconds = bytes2int(transmittimebytes[0:4])
        
        utcnow = time.time()
        
        ntpsecondsnow = int(math.floor(utcnow)) + 2208988800
        
        logmessage('NTP Seconds now: {}'.format(ntpsecondsnow))
        
        ntpsecondsnowbytes = int2fourbytes(ntpsecondsnow)
        
        logmessage('HEX STRING: {}'.format(bytes2text(ntpsecondsnowbytes)))
        
        ntpsecondsnowminus30bytes = int2fourbytes(ntpsecondsnow - 30)
        
        response = bytearray(MIN_VALID_NTPV3_PACKET_LENGTH)
        
        if versionnumber == 3:
            response[0] = 0x1C
        elif versionnumber == 4:
            response[0] = 0x24
        
        response[1] = 3
        response[2] = 4
        response[3] = clientprecision
        
        response[4:8]   = rootdelaybytes
        response[8:12]  = rootdispersionbytes
        
        response[12] = 128
        response[13] = 138
        response[14] = 141
        response[15] = 172
        
        response[16:24] = receiventp
        
        response[18] = response[18] - 1
        if response[18] == 255:
            response[17] = response[17] - 1
            if response[17] == 255:
                response[16] = response[16] - 1
        
        response[24:32] = packet[40:48]

        response[32:40] = receiventp

        response[40:48] = ntptimenowbytes()

        if loglevel >= 1:
            showpacket(response)

        ### print(address)
        
        listensocket.sendto(response, address)

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
