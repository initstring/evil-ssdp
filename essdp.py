from lib.classes import SSDPListener
from lib.classes import DeviceDescriptor
import os,sys,re,argparse;

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
args = parser.parse_args()
interface = args.interface

# Set up some nice colors
class bcolors:
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    ENDC = '\033[0m'
okBox = bcolors.OKGREEN + '[+] ' + bcolors.ENDC
warnBox = bcolors.WARNING + '[!] ' + bcolors.ENDC


def get_ip(i):
    try:
        ip = re.findall(r'inet (.*?)/', os.popen('ip addr show wlp58s0').read())[0]
        broadcast = re.findall(r'brd (.*?) ', os.popen('ip addr show wlp58s0').read())[0]
        return ip,broadcast
    except Exception:
        print(warnBox + "Could not get network interface info. Please check and try again.")
        sys.exit()


def main():
   ip,broadcast = get_ip(interface)
   print(okBox + "Listening for MSEARCH queries using {} at {}".format(interface, broadcast))
   listener = SSDPListener(ip)
   descriptor = DeviceDescriptor(ip)

if __name__ == "__main__":
    main()

