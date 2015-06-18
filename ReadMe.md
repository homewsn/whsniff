### A packet converter for sniffing IEEE 802.15.4 wireless sensor networks

This repository is a part of the [HomeWSN](http://homewsn.github.io) project.

Whsniff is a command line utility that interfaces TI CC2531 USB dongle with Wireshark for capturing and displaying IEEE 802.15.4 traffic at 2.4 GHz.

This utility only works on Linux (including OpenWrt). For Windows download and install the [SmartRF Packet Sniffer](http://www.ti.com/tool/packet-sniffer) from TI website.

Whsniff reads the packets from TI CC2531 USB dongle with [`sniffer_fw_cc2531` firmware](http://www.ti.com/tool/packet-sniffer), converts to the PCAP format and writes to the standard output(stdout).


##### Building

* Install `libusb-1.0-0-dev`:
```sh
$ sudo apt-get install libusb-1.0-0-dev
```

* Build release version:
```sh
$ cd path/to/whsniff/Makefile
$ make release
```


##### How to use (Locally)

* Connect CC2531 USB dongle to your Linux PC.

* Open a terminal session on the desktop where you have Wireshark installed and enter the following commands:
```sh
$ wireshark -k -i <( path/to/whsniff -c channel_number )
or
$ path/to/whsniff -c 25 | wireshark -k -i -
or
$ mkfifo /tmp/pipes/whsniff
$ path/to/whsniff -c 25 > /tmp/pipes/whsniff
```

* You can also save the output to a file to analyze it later using wireshark:
```sh
$ path/to/whsniff -c 25 > filename.pcap
```


##### How to use (Remotely)

* Connect CC2531 USB dongle to remote Linux PC or OpenWrt device, then start whsniff remotely with ssh from the desktop where you have Wireshark installed.

* For Linux open a terminal session on the desktop and enter the following command:
```sh
$ ssh root@192.168.1.202 "whsniff -c 25" | wireshark -k -i -
```
where `192.168.1.202` is an IP address of the computer where dongle is connected.

* For Windows install PuTTY with extension `plink.exe` from [PuTTY Download Page](http://www.chiark.greenend.org.uk/~sgtatham/putty/download.html), then open a command prompt window and enter the following command:
```sh
> "C:\Program Files\PuTTY\plink.exe" -ssh -pw password root@192.168.1.202 whsniff -c 25 | "C:\Program Files\Wireshark\wireshark.exe" -k -i -
```
where `password` is a root password and `192.168.1.202` is an IP address of the computer where dongle is connected.


##### License

[GNU GPL v 2.0](http://www.gnu.org/licenses/gpl-2.0.html)