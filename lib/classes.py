import socket
import struct
import sys

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
    def __init__(self):
        self.sock = None
        self.knownHosts = []
    def run(self, ip):
        ssdpPort = 1900				# This is defined by the SSDP spec, do not change
        serverName = "EvilSSDP!"
        mcastGroup='239.255.255.250'	# This is defined by the SSDP spec, do not change
        serverAddress = ('', ssdpPort)
        knownHosts = []
        
        # Create the socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Bind to the server address
        self.sock.bind(serverAddress)
        
        # Tell the operating system to add the socket to
        # the multicast group on for the interface on the specific IP.
        group = socket.inet_aton(mcastGroup)
        mreq = struct.pack('4s4s', group, socket.inet_aton(ip))
        self.sock.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_ADD_MEMBERSHIP,
            mreq)
        
        # Receive/respond loop
        while True:
            data, address = self.sock.recvfrom(1024)
            self.process_data(data,address)

    def process_data(self, data, address):
        (ip,port) = address
        if 'M-SEARCH' in str(data):
            if address[0] not in self.knownHosts:
                print(noteBox + "Received an M-SEARCH query from new host {} on port {}".format(ip, port))
                print("    " + okBox + "Subsequent requests from this host will be processed but not printed here.")
                self.knownHosts.append(address[0]) 
            self.sock.sendto(b'ack', address) 
        
class DeviceDescriptor:
    def __init__(self, ip):
        return
