### A packet converter for sniffing IEEE 802.15.4 wireless sensor networks

This repository is a part of the [HomeWSN](http://homewsn.github.io) project.

Whsniff is a command line utility that interfaces TI CC2531 USB dongle with Wireshark for capturing and displaying IEEE 802.15.4 traffic at 2.4 GHz.

This utility only works on Linux (including OpenWrt). For Windows download and install the [SmartRF Packet Sniffer](http://www.ti.com/tool/packet-sniffer) from TI website.

Whsniff reads the packets from TI CC2531 USB dongle with [`sniffer_fw_cc2531` firmware](http://www.ti.com/tool/packet-sniffer), converts to the PCAP format and writes to the standard output(stdout).


##### Building (Linux)

* Install `libusb-1.0-0-dev`:
```sh
$ sudo apt-get install libusb-1.0-0-dev
```
* Download [the latest release](https://github.com/homewsn/whsniff/releases) in tarball from github and untar it. Then build and install whsniff.
```sh
$ curl -L https://github.com/homewsn/whsniff/archive/v1.1.tar.gz | tar zx
$ cd whsniff-1.1
$ make
$ sudo make install
```

##### Building (macOS)

* Install `libusb` via [Homebrew](https://brew.sh) (or your preferred package manager):
```sh
$ brew install libusb
```
* Download [the latest release](https://github.com/homewsn/whsniff/releases) in tarball from github and untar it. Then build and install whsniff.
```sh
$ curl -L https://github.com/homewsn/whsniff/archive/v1.1.tar.gz | tar zx
$ cd whsniff-1.1
$ make
$ sudo make install
```

##### Building (OpenWrt)

* Install [OpenWrt buildroot](http://wiki.openwrt.org/doc/howto/buildroot.exigence).
* Add the following line to the `feeds.conf.default` in the OpenWrt buildroot:
```sh
src-git homewsn https://github.com/homewsn/homewsn.openwrt.packages.git
```
* This feed should be included and enabled by default in the OpenWrt buildroot. To install all its package definitions, run:
```sh
$ ./scripts/feeds update homewsn
$ ./scripts/feeds install -a -p homewsn
```
* The packages should now appear in menuconfig. You can find whsniff in the Network menu.


##### How to use (Locally)

* Connect CC2531 USB dongle to your Linux or macOS computer.
* Open a terminal session on the desktop where you have Wireshark installed and enter the following commands:
```sh
$ wireshark -k -i <( path/to/whsniff -c channel_number )
or
$ path/to/whsniff -c channel_number | wireshark -k -i -
or
$ mkfifo /tmp/pipes/whsniff
$ path/to/whsniff -c channel_number > /tmp/pipes/whsniff
```
* You can also save the output to a file to analyze it later using Wireshark:
```sh
$ path/to/whsniff -c channel_number > filename.pcap
```
* If you see something like `libusb: error [_get_usbfs_fd] libusb couldn't open USB device /dev/bus/usb/001/006: Permission denied` you can give the write permission for everyone (or use another solution):
```sh
$ sudo chmod a+w /dev/bus/usb/001/006
```

##### How to use (Remotely)

* Connect CC2531 USB dongle to remote Linux PC or OpenWrt device, then start whsniff remotely with ssh from the desktop where you have Wireshark installed.
* For Linux open a terminal session on the desktop and enter the following command:
```sh
$ ssh root@192.168.1.202 "whsniff -c 18" | wireshark -k -i -
```
where `192.168.1.202` is an IP address of the computer where dongle is connected and `18` is a channel number.
* For Windows install PuTTY with extension `plink.exe` from [PuTTY Download Page](http://www.chiark.greenend.org.uk/~sgtatham/putty/download.html), then open a command prompt window and enter the following command:
```sh
> "C:\Program Files\PuTTY\plink.exe" -ssh -pw password root@192.168.1.202 whsniff -c 18 | "C:\Program Files\Wireshark\wireshark.exe" -k -i -
```
where `password` is a root password, `192.168.1.202` is an IP address of the computer where dongle is connected and `18` is a channel number.


##### License

[GNU GPL v 2.0](http://www.gnu.org/licenses/gpl-2.0.html)
