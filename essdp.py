#!/usr/bin/env python3

from lib.classes import SSDPListener
from lib.classes import DeviceDescriptor
from multiprocessing import Process
import os,sys,re,argparse,socketserver;

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

# Handle arguments before moving on....
parser = argparse.ArgumentParser()
parser.add_argument('interface', type=str, help='Network interface to listen on.', action='store')
parser.add_argument('-p', '--port', type=str, help='Port for HTTP server. Defaults to 8888.', action='store')
parser.add_argument('-n', '--name', type=str, help='Name of the Media Server. Defaults to ePNP Media.', action='store')
args = parser.parse_args()

interface = args.interface
if args.port:
    localPort = int(args.port)
else:
    localPort = 8888
serverName = args.name or 'ePNP Media'

# Set up some nice colors
class bcolors:
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    ORANGE = '\033[93m'
    ENDC = '\033[0m'
okBox = bcolors.BLUE + '[*] ' + bcolors.ENDC
NoteBox = bcolors.GREEN + '[+] ' + bcolors.ENDC
warnBox = bcolors.ORANGE + '[!] ' + bcolors.ENDC


def get_ip(interface):
    try:
        localIp = re.findall(r'inet (.*?)/', os.popen('ip addr show ' + interface).read())[0]
        broadcast = re.findall(r'brd (.*?) ', os.popen('ip addr show ' + interface).read())[0]
        return localIp
    except Exception:
        print(warnBox + "Could not get network interface info. Please check and try again.")
        sys.exit()

def serve_descriptor(localIp, localPort):
    print(okBox + "Serving device descriptor using {} at {} on port {}".format(interface, localIp, localPort))
    descriptor = socketserver.TCPServer((localIp, localPort), DeviceDescriptor)
    descriptor.serve_forever()

def listen_msearch(localIp):
   print(okBox + "Listening for MSEARCH queries using {}.".format(interface))
   listener = SSDPListener(localIp, localPort, serverName)
   listener.run()

def main():
   localIp = get_ip(interface)
   Process(target=serve_descriptor, args=(localIp, localPort)).start()
   listen_msearch(localIp)


if __name__ == "__main__":
    main()

