import socket
import struct
import sys


class SSDPListener:
    def __init__(self):
        self.sock = None
    def run(self, ip):
        ssdpPort = 1900				# This is defined by the SSDP spec, do not change
        serverName = "EvilSSDP!"
        mcastGroup='239.255.255.250'	# This is defined by the SSDP spec, do not change
        server_address = ('', ssdpPort)
        
        # Create the socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Bind to the server address
        sock.bind(server_address)
        
        # Tell the operating system to add the socket to
        # the multicast group on for the interface on the specific IP.
        group = socket.inet_aton(mcastGroup)
        mreq = struct.pack('4s4s', group, socket.inet_aton(ip))
        sock.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_ADD_MEMBERSHIP,
            mreq)
        
        # Receive/respond loop
        while True:
            print('\nwaiting to receive message')
            data, address = sock.recvfrom(1024)
        
            print('received {} bytes from {}'.format(
                len(data), address))
            print(data)
        
            print('sending acknowledgement to', address)
            sock.sendto(b'ack', address) 
        
class DeviceDescriptor:
    def __init__(self, ip):
        return
