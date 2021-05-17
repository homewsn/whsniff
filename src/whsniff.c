/*
* Copyright (c) 2015-2020 Vladimir Alemasov
* All rights reserved
*
* This program and the accompanying materials are distributed under
* the terms of GNU General Public License version 2
* as published by the Free Software Foundation.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*/

#include <stdlib.h>			/* exit */
#include <stdio.h>			/* printf */
#include <signal.h>			/* signal_handler */
#include <string.h>			/* memset */
#include <unistd.h>			/* getopt, optarg */
#include <stdint.h>			/* uint8_t ... uint64_t */
#include <time.h>			/* time */
#include <libusb-1.0/libusb.h>

#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif

#if defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#include <machine/endian.h>
#define htole16(x) OSSwapHostToLittleInt16(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)
#else
#include <endian.h>                     /* htole16, htole32, le32toh */
#endif

#define BUF_SIZE	256		// buffers size
#define TIMEOUT		200		// USB timeout in ms

#pragma pack(push, 1)

// https://wiki.wireshark.org/Development/LibpcapFileFormat
typedef struct pcap_hdr_s
{
	uint32_t magic_number;		/* magic number */
	uint16_t version_major;		/* major version number */
	uint16_t version_minor;		/* minor version number */
	int32_t thiszone;			/* GMT to local correction */
	uint32_t sigfigs;			/* accuracy of timestamps */
	uint32_t snaplen;			/* max length of captured packets, in octets */
	uint32_t network;			/* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s
{
	uint32_t ts_sec;			/* timestamp seconds */
	uint32_t ts_usec;			/* timestamp microseconds */
	uint32_t incl_len;			/* number of octets of packet saved in file */
	uint32_t orig_len;			/* actual length of packet */
} pcaprec_hdr_t;

typedef struct usb_header
{
	uint8_t type;				// 0 - data, 1 - tick counter
	uint16_t le_usb_len;		// little-endian usb packet length
} usb_header_type;

typedef struct usb_data_header
{
	usb_header_type usb_header;
	uint32_t le_timestamp;		// little-endian timestamp in microseconds * 32
	uint8_t wpan_len;			// wpan packet length
} usb_data_header_type;

typedef struct usb_tick_header
{
	usb_header_type usb_header;
	uint8_t tick;				// tick counter
} usb_tick_header_type;

typedef struct usb_sniffing_device {
	libusb_device_handle *handle;
	uint8_t bus_number;
	uint8_t device_address;
	uint8_t channel;
} usb_sniffing_device_type;

typedef struct prg_options {
	uint8_t restart_hourly;
	uint8_t restart_daily;
	uint8_t channel;
	uint8_t keep_original_fcs;
	uint8_t dump_to_file;
	uint8_t specific_device;
	uint8_t bus_num, dev_num;
} prg_options_type;

#pragma pack(pop)

static const pcap_hdr_t pcap_hdr = {
	.magic_number = 0xA1B2C3D4,	// native byte ordering
	.version_major = 2,			// current version is 2.4
	.version_minor = 4,
	.thiszone = 0,				// GMT
	.sigfigs = 0,				// zero value for sig figs as standard
	.snaplen = 128,				// max 802.15.4 packet length
	.network = 195				// IEEE 802.15.4
};

/* variable used to flag when a signal was received */
static volatile unsigned int signal_exit = 0;

static prg_options_type prg_options = {
	.restart_daily = 0,
	.restart_hourly = 0,
	.channel = 0,
	.keep_original_fcs = 0,
	.dump_to_file = 0,
	.specific_device = 0,
	.bus_num = 0,
	.dev_num = 0
};

static usb_sniffing_device_type usb_sniffing_device = {
	.handle = NULL,
	.bus_number = 0,
	.device_address = 0,
	.channel = 0
};
//--------------------------------------------
static uint16_t update_crc_ccitt(uint16_t crc, uint8_t c);
static uint16_t ieee802154_crc16(uint8_t *tvb, uint32_t offset, uint32_t len);


//--------------------------------------------
static int packet_handler(unsigned char *buf, int cnt, uint8_t keep_original_fcs, FILE * file)
{
	usb_header_type *usb_header;
	usb_data_header_type *usb_data_header;
	usb_tick_header_type *usb_tick_header;
	pcaprec_hdr_t pcaprec_hdr;
	uint16_t usb_len;
	static time_t timestamp_epoch;
	static uint64_t timestamp_offset;
	static uint64_t timestamp_tick;
	uint64_t timestamp_us;
	uint16_t fcs;
	uint16_t le_fcs;

	if (sizeof(usb_header_type) > cnt)
		return -1;
	usb_header = (usb_header_type *)buf;
	usb_len = le16toh(usb_header->le_usb_len);
	if (usb_len + sizeof(usb_header_type) > cnt)
		return -1;

	switch (usb_header->type)
	{
		case 0:
			if (sizeof(usb_data_header_type) > cnt)
				return -1;
			usb_data_header = (usb_data_header_type *)buf;
			if (usb_data_header->wpan_len + sizeof(usb_data_header_type) > cnt)
				return -1;

			if (usb_data_header->wpan_len < 5)
			{
				break;
			}

			// SmartRF™ Packet Sniffer User’s Manual (SWRU187G)
			// Timestamp:
			// 64 bit counter value. To calculate the time in microseconds this value must be divided by a number
			// depending on the clock speed used to drive the counter tics on the target. (E.g. CC2430EM -> 32,
			// CCxx10 -> 26, SmartRF05EB + CC2520EM -> 24).
			// CC2531EMK sniffer software: 32-bit value must be divided by 32

			// host timestamp in microseconds
			timestamp_us = (timestamp_tick + le32toh(usb_data_header->le_timestamp)) / 32;

			if (!timestamp_offset)
			{
				timestamp_epoch = time(NULL);
				timestamp_offset = timestamp_us;
			}
			timestamp_us -= timestamp_offset;

			// native(host) byte ordering, see pcap_hdr.magic_number
			pcaprec_hdr.ts_sec = (uint32_t)(timestamp_us / 1000000);
			pcaprec_hdr.ts_usec = (uint32_t)(timestamp_us - (uint64_t)(pcaprec_hdr.ts_sec) * 1000000);
			pcaprec_hdr.ts_sec += (uint32_t)timestamp_epoch;
			pcaprec_hdr.incl_len = (uint32_t)usb_data_header->wpan_len;
			pcaprec_hdr.orig_len = (uint32_t)usb_data_header->wpan_len;

			fwrite(&pcaprec_hdr, sizeof(pcaprec_hdr), 1, file);

			// SmartRF™ Packet Sniffer User’s Manual (SWRU187G)
			// FCS:
			// The checksum of the frame has been replaced by the radio chip in the following way:
			// BYTE 1: RSSI and if Correlation used, this byte is also used to calculate the LQI value.
			// BYTE 2: Bit 7: Indicate CRC OK or not.
			// Bit 6-0: If Correlation used: Correlation value.
			// If Correlation not used: LQI.

			if (keep_original_fcs)
				fwrite(&buf[sizeof(usb_data_header_type)], 1, usb_data_header->wpan_len, file);
			else
			{
				fwrite(&buf[sizeof(usb_data_header_type)], 1, usb_data_header->wpan_len - 2, file);
				fcs = 0;
				if (buf[sizeof(usb_data_header_type) + usb_data_header->wpan_len - 1] & 0x80)
				{
					// CRC OK
					fcs = ieee802154_crc16((uint8_t *)&buf[sizeof(usb_data_header_type)], 0, usb_data_header->wpan_len - 2);
				}
				le_fcs = htole16(fcs);

				fwrite(&le_fcs, sizeof(le_fcs), 1, file);
			}
			fflush(file);

			break;

		case 1:
			if (sizeof(usb_tick_header_type) > cnt)
				return -1;
			usb_tick_header = (usb_tick_header_type *)buf;
			if (usb_tick_header->tick == 0x00)
				timestamp_tick += 0xFFFFFFFF;
			break;

		default:
			break;
	}

	return usb_len + sizeof(usb_header_type);
}

//--------------------------------------------
void signal_handler(int sig)
{
	signal_exit = 1;
}

//--------------------------------------------
void print_usage()
{
    printf("Usage: whsniff -c <channel> [-s <bus>:<dev>] [-k] [-f] [-h] [-d] [-l]\n");
    printf("\n");
    printf("Where\n");
    printf("\t-c <channel> - Zigbee channel number (11 to 26)\n");
    printf("\t-s <bus>:<dev> - attach to specific device Bus:Device as listed in lsusb\n");
    printf("\t-k - keep the original FCS sent by the CC2531\n");
    printf("\t-f - dump to file instead of stdout (handy for long sniffs with -h/-d options)\n");
    printf("\t-h - start a new dump file evey hour (used with -f)\n");
    printf("\t-d - start a new dump file evey day (used with -f)\n");
    printf("\t-l - list the recognized devices\n");
}


/* Initialises the USB sniffer device
 * @param specific_device flag to indicate if a specific device should be used. Otherwise, first found.
 * @param snif_dev the usb_sniffing_device used to pull parameters for initialisation
 * @return the function execution status 
 */
int8_t init_usb_sniffer(uint8_t specific_device, usb_sniffing_device_type *snif_dev)
{
	int res;
	libusb_device_handle *handle;
	libusb_device *usb_device;
	uint8_t bus_number, device_address;
	static unsigned char usb_buf[BUF_SIZE];

	res = libusb_init(NULL);
	if (res < 0)
	{
		fprintf(stderr, "ERROR: Could not initialize libusb: %s\n",libusb_error_name(res));
		return res;
	}
#if LIBUSB_API_VERSION >= 0x01000106
	libusb_set_option(NULL, LIBUSB_OPTION_LOG_LEVEL, 3);
#else
	libusb_set_debug(NULL, 3);
#endif

	// find first unused device
	int found_device = 0;
	libusb_device **list = NULL;
	ssize_t count = libusb_get_device_list(NULL, &list);

	// cycle through all USB devices to find the first CC2531 or the requested one
	for (size_t idx = 0; idx < count; ++idx)
	{
		usb_device = list[idx];
		struct libusb_device_descriptor t_desc;
		libusb_get_device_descriptor(usb_device, &t_desc);
		bus_number = libusb_get_bus_number(usb_device);
		device_address = libusb_get_device_address(usb_device);

		if (t_desc.idVendor == 0x0451 && t_desc.idProduct == 0x16ae &&	// is it a TI CC2531 device
			 ( (specific_device == 0)		// No specific device requested, take first one
				||
			   (specific_device == 1 		// Only interested in a specific CC2531
			   		&& bus_number == snif_dev->bus_number
			   		&& device_address == snif_dev->device_address )
			 )
		   )
		{
			snif_dev->bus_number = bus_number;
			snif_dev->device_address = device_address;
			fprintf(stderr, "Found device %04x:%04x (bcdDevice: %04x) on Bus %03d, Device %03d\n", t_desc.idVendor, t_desc.idProduct, t_desc.bcdDevice, bus_number, device_address);

			res = libusb_open(usb_device, &handle);
			if (res != 0)
			{
				fprintf(stderr, "--> unable to open device: %s\n",libusb_error_name(res));
				continue;
			}
			if (handle == NULL)
			{
				fprintf(stderr, "ERROR: Could not open CC2531 USB Dongle with sniffer firmware. Not found or not accessible.\n");
				continue;
			}
			usb_sniffing_device.handle = handle;

			if (libusb_kernel_driver_active(handle, 0))
			{
				res = libusb_detach_kernel_driver(handle, 0);
				if (res < 0)
				{
					fprintf(stderr, "ERROR: Could not detach kernel driver from CC2531 USB Dongle: %s\n", libusb_error_name(res));
					libusb_close(handle);
					continue;
				}
			}

			res = libusb_set_configuration(handle, 1);
			if (res < 0)
			{
				fprintf(stderr, "--> unable to set configuration for device: %s\n", libusb_error_name(res));
				libusb_close(handle);
				continue;
			}
			res = libusb_claim_interface(handle, 0);
			if (res < 0)
			{
				fprintf(stderr, "--> unable to claim interface for device: %s\n",libusb_error_name(res));
				libusb_close(handle);
				continue;
			}
			found_device = 1;
			break;
		}
	}
	libusb_free_device_list(list, count);
	if (!found_device)
	{
		fprintf(stderr, "ERROR: No working device found.\n");
		return -1;
	}


	// get identity from firmware command
	res = libusb_control_transfer(handle, 0xc0, 192, 0, 0, (unsigned char *)&usb_buf, BUF_SIZE, TIMEOUT);
	// power on radio, wIndex = 4
	res = libusb_control_transfer(handle, 0x40, 197, 0, 4, NULL, 0, TIMEOUT);
	// check if powered up
	for (;;)
	{
		res = libusb_control_transfer(handle, 0xc0, 198, 0, 0, (unsigned char *)&usb_buf, 1, TIMEOUT);
		if (usb_buf[0] == 0x04)
			break;
		usleep(10000);
	}
	// unknown command
	res = libusb_control_transfer(handle, 0x40, 201, 0, 0, NULL, 0, TIMEOUT);

	// set channel command
	usb_buf[0] = snif_dev->channel;
	res = libusb_control_transfer(handle, 0x40, 210, 0, 0, (unsigned char *)&usb_buf, 1, TIMEOUT);
	usb_buf[0] = 0x00;
	res = libusb_control_transfer(handle, 0x40, 210, 0, 1, (unsigned char *)&usb_buf, 1, TIMEOUT);

	// start sniffing
	res = libusb_control_transfer(handle, 0x40, 208, 0, 0, NULL, 0, TIMEOUT);

	return 0;
}

/* closes the USB sniffing device previously opened, with appropriate commands sent to device. 
 * @param handle pointer to the usb_device
 */
void close_usb_sniffer(libusb_device_handle *handle)
{
	int res;

	// stop sniffing
	res = libusb_control_transfer(handle, 0x40, 209, 0, 0, NULL, 0, TIMEOUT);
	// power off radio, wIndex = 0
	res = libusb_control_transfer(handle, 0x40, 197, 0, 0, NULL, 0, TIMEOUT);

	// clearing
	res = libusb_release_interface(handle, 0);
	
	//dummy stmt to remove warning unsused-but-set
	res+=0;
	
	libusb_close(handle);
	libusb_exit(NULL);
}

/* lists all the USB devices, similarly as lsusb, in order to attach to a specific device
 */
void list_devices()
{
	int res;
	// USB device identifier used by lsusb command
	uint8_t bus_number, device_address;

	res = libusb_init(NULL);
	if (res < 0)
	{
		fprintf(stderr, "ERROR: Could not initialize libusb: %s\n", libusb_error_name(res));
		return;
	}


	int found_device = 0;
	libusb_device **list = NULL;
	ssize_t count = libusb_get_device_list(NULL, &list);
	for (size_t idx = 0; idx < count; ++idx)
	{
		libusb_device *device = list[idx];
		struct libusb_device_descriptor t_desc;
		libusb_get_device_descriptor(device, &t_desc);
		bus_number = libusb_get_bus_number(device);
		device_address = libusb_get_device_address(device);

		if (t_desc.idVendor == 0x0451 && t_desc.idProduct == 0x16ae)
		{
			fprintf(stdout, "Found device %04x:%04x (bcdDevice: %04x) on Bus %03d, Device %03d\n", t_desc.idVendor, t_desc.idProduct, t_desc.bcdDevice, bus_number, device_address);
			found_device = 1;
		}
	}

	if (!found_device)
		fprintf(stderr, "ERROR: No working device found.\n");

}

//--------------------------------------------
FILE * restart_pcap_file(FILE * prev_file)
{
	static int last_hour = -1;
	static int last_day = -1;
	static int stdout_header_written = 0;

	FILE * file = prev_file;

	// print PCAP header to stdout only once
	if (file == stdout)
	{
		if (!stdout_header_written)
		{
			// Write PCAP header
			fwrite(&pcap_hdr, sizeof(pcap_hdr), 1, file);
			fflush(file);

			stdout_header_written = 1;
		}

		return file;
	}

	time_t t = time(NULL);
	struct tm tm = *localtime(&t);

	// No need to restart if hour has not yet changed
	if (prg_options.restart_hourly && last_hour == tm.tm_hour)
		return file;

	// No need to restart if day has not yet changed
	if (prg_options.restart_daily && last_day == tm.tm_mday)
		return file;

	// Store last hour/day
	last_hour = tm.tm_hour;
	last_day = tm.tm_mday;

	// Close previous file
	if (file)
		fclose(file);

	// ... and open a new one
	char filename[100];
	sprintf(filename, "whsniff_B%03d-D%03d_%04d-%02d-%02d_%02d-%02d-%02d.pcap", 
		usb_sniffing_device.bus_number, usb_sniffing_device.device_address, 
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, 
		tm.tm_hour, tm.tm_min, tm.tm_sec);

	fprintf(stderr, "Sniffing to %s\n", filename);
	file = fopen(filename, "wb");

	// Write PCAP header
	fwrite(&pcap_hdr, sizeof(pcap_hdr), 1, file);
	fflush(file);

	return file;
}

//--------------------------------------------
int main(int argc, char *argv[])
{

	int option;

	static unsigned char usb_buf[BUF_SIZE];
	static int usb_cnt;
	static unsigned char recv_buf[2 * BUF_SIZE];
	static int recv_cnt;

	FILE * file = NULL;

	// ctrl-c
	signal(SIGINT, signal_handler);
	// killall whsniff
	signal(SIGTERM, signal_handler);
	// pipe closed
	signal(SIGPIPE, signal_handler);

	option = 0;
	while ((option = getopt(argc, argv, "c:s:kfhdl")) != -1)
	{
		switch (option)
		{
			case 'c':
				prg_options.channel = (uint8_t)atoi(optarg);
				if (prg_options.channel < 11 || prg_options.channel > 26)
				{
					exit(EXIT_FAILURE);
				}
				break;
			case 's':
				prg_options.specific_device = 1;

				// Option parsing taken from lsusb source and updated to only accept bus:dev format
				char *cp = strchr(optarg, ':');
				if (cp) {
					*cp++ = 0;
					if (*optarg)
						prg_options.bus_num = strtoul(optarg, NULL, 10);
					if (*cp)
						prg_options.dev_num = strtoul(cp, NULL, 10);
				} 
				else {
					print_usage();
					exit(EXIT_FAILURE);
				}
				break;
			case 'k':
				prg_options.keep_original_fcs = 1;
				break;
			case 'f':
				prg_options.dump_to_file = 1;
				break;
			case 'h':
				prg_options.restart_hourly = 1;
				break;
			case 'd':
				prg_options.restart_daily = 1;
				break;
			case 'l':
				list_devices();
				exit(EXIT_SUCCESS);
			default:
				print_usage();
				exit(EXIT_FAILURE);
		}
	}
	// check the mandatory options
	if (!prg_options.channel)
	{
		print_usage();
		exit(EXIT_FAILURE);
	}

	usb_sniffing_device.channel = prg_options.channel;
	usb_sniffing_device.bus_number = prg_options.bus_num;
	usb_sniffing_device.device_address = prg_options.dev_num;

	init_usb_sniffer(prg_options.specific_device, &usb_sniffing_device);

	libusb_device_handle *handle = usb_sniffing_device.handle;
	if (NULL == handle)
	{
		printf("Cannot initialize USB sniffer device\n");
		exit(EXIT_FAILURE);
	}

	// Continously captures packets until interruped by a signal
	while (!signal_exit)
	{
		// restart new PCAP file (if needed)
		file = restart_pcap_file(prg_options.dump_to_file ? file /*Open new file*/ : stdout);

		// Receive and process a piece of data from USB
		int res = libusb_bulk_transfer(handle, 0x83, (unsigned char *)&usb_buf, BUF_SIZE, &usb_cnt, 10000);

		if (usb_cnt + recv_cnt > 2 * BUF_SIZE)
		{
			// overflow error
			fprintf(stderr,"ERROR: Buffer overflow.\n");
			break;
		}
		if (res < 0)
		{
			if (res == LIBUSB_ERROR_TIMEOUT)
				continue;
			// libusb error
			fprintf(stderr,"ERROR: %s.\n", libusb_error_name(res));
			break;
		}

		memcpy(&recv_buf[recv_cnt], &usb_buf[0], usb_cnt);
		recv_cnt += usb_cnt;

		for (;;)
		{
			res = packet_handler(&recv_buf[0], recv_cnt, prg_options.keep_original_fcs, file);
			if (res < 0)
				break;
			recv_cnt -= res;
			if (recv_cnt == 0)
				break;
			memmove(&recv_buf[0], &recv_buf[res], recv_cnt);
		}
	}

	close_usb_sniffer(handle);
	if (file)
		fclose(file);

	exit(EXIT_SUCCESS);
}

//-------------------------------------------------------------------------
// The following code has been partially taken from patch
// for Wireshark packet-ieee802154.c
// Copyright (c) 2007 Owen Kirby
//-------------------------------------------------------------------------
// CRC16 is calculated using the x^16 + x^12 + x^5 + 1 polynomial
// as specified by ITU-T, and is calculated over the IEEE 802.15.4
// packet (excluding the FCS) as transmitted over the air. Note,
// that because the least significan bits are transmitted first, this
// will require reversing the bit-order in each byte. Also, unlike
// most CRC algorithms, IEEE 802.15.4 uses an initial value of 0x0000
// instead of the more common 0xffff.
//-------------------------------------------------------------------------

// Precomputed partial CRC table.
static const uint16_t crc_tabccitt[256] = {
	0x0000,  0x1021,  0x2042,  0x3063,  0x4084,  0x50a5,  0x60c6,  0x70e7,
	0x8108,  0x9129,  0xa14a,  0xb16b,  0xc18c,  0xd1ad,  0xe1ce,  0xf1ef,
	0x1231,  0x0210,  0x3273,  0x2252,  0x52b5,  0x4294,  0x72f7,  0x62d6,
	0x9339,  0x8318,  0xb37b,  0xa35a,  0xd3bd,  0xc39c,  0xf3ff,  0xe3de,
	0x2462,  0x3443,  0x0420,  0x1401,  0x64e6,  0x74c7,  0x44a4,  0x5485,
	0xa56a,  0xb54b,  0x8528,  0x9509,  0xe5ee,  0xf5cf,  0xc5ac,  0xd58d,
	0x3653,  0x2672,  0x1611,  0x0630,  0x76d7,  0x66f6,  0x5695,  0x46b4,
	0xb75b,  0xa77a,  0x9719,  0x8738,  0xf7df,  0xe7fe,  0xd79d,  0xc7bc,
	0x48c4,  0x58e5,  0x6886,  0x78a7,  0x0840,  0x1861,  0x2802,  0x3823,
	0xc9cc,  0xd9ed,  0xe98e,  0xf9af,  0x8948,  0x9969,  0xa90a,  0xb92b,
	0x5af5,  0x4ad4,  0x7ab7,  0x6a96,  0x1a71,  0x0a50,  0x3a33,  0x2a12,
	0xdbfd,  0xcbdc,  0xfbbf,  0xeb9e,  0x9b79,  0x8b58,  0xbb3b,  0xab1a,
	0x6ca6,  0x7c87,  0x4ce4,  0x5cc5,  0x2c22,  0x3c03,  0x0c60,  0x1c41,
	0xedae,  0xfd8f,  0xcdec,  0xddcd,  0xad2a,  0xbd0b,  0x8d68,  0x9d49,
	0x7e97,  0x6eb6,  0x5ed5,  0x4ef4,  0x3e13,  0x2e32,  0x1e51,  0x0e70,
	0xff9f,  0xefbe,  0xdfdd,  0xcffc,  0xbf1b,  0xaf3a,  0x9f59,  0x8f78,
	0x9188,  0x81a9,  0xb1ca,  0xa1eb,  0xd10c,  0xc12d,  0xf14e,  0xe16f,
	0x1080,  0x00a1,  0x30c2,  0x20e3,  0x5004,  0x4025,  0x7046,  0x6067,
	0x83b9,  0x9398,  0xa3fb,  0xb3da,  0xc33d,  0xd31c,  0xe37f,  0xf35e,
	0x02b1,  0x1290,  0x22f3,  0x32d2,  0x4235,  0x5214,  0x6277,  0x7256,
	0xb5ea,  0xa5cb,  0x95a8,  0x8589,  0xf56e,  0xe54f,  0xd52c,  0xc50d,
	0x34e2,  0x24c3,  0x14a0,  0x0481,  0x7466,  0x6447,  0x5424,  0x4405,
	0xa7db,  0xb7fa,  0x8799,  0x97b8,  0xe75f,  0xf77e,  0xc71d,  0xd73c,
	0x26d3,  0x36f2,  0x0691,  0x16b0,  0x6657,  0x7676,  0x4615,  0x5634,
	0xd94c,  0xc96d,  0xf90e,  0xe92f,  0x99c8,  0x89e9,  0xb98a,  0xa9ab,
	0x5844,  0x4865,  0x7806,  0x6827,  0x18c0,  0x08e1,  0x3882,  0x28a3,
	0xcb7d,  0xdb5c,  0xeb3f,  0xfb1e,  0x8bf9,  0x9bd8,  0xabbb,  0xbb9a,
	0x4a75,  0x5a54,  0x6a37,  0x7a16,  0x0af1,  0x1ad0,  0x2ab3,  0x3a92,
	0xfd2e,  0xed0f,  0xdd6c,  0xcd4d,  0xbdaa,  0xad8b,  0x9de8,  0x8dc9,
	0x7c26,  0x6c07,  0x5c64,  0x4c45,  0x3ca2,  0x2c83,  0x1ce0,  0x0cc1,
	0xef1f,  0xff3e,  0xcf5d,  0xdf7c,  0xaf9b,  0xbfba,  0x8fd9,  0x9ff8,
	0x6e17,  0x7e36,  0x4e55,  0x5e74,  0x2e93,  0x3eb2,  0x0ed1,  0x1ef0
};

// Table of bytes with reverse bits
// Necessary for CRC generation because the CRC is generated from the bits ordered as
// they are transmitted over the air. But, IEEE 802.15.4 transmits the least signficant
// bits first.
static const uint8_t rev_bitorder_table[256] = {
	0x00, 0x80, 0x40, 0xc0, 0x20, 0xa0, 0x60, 0xe0, 0x10, 0x90, 0x50, 0xd0, 0x30, 0xb0, 0x70, 0xf0,
	0x08, 0x88, 0x48, 0xc8, 0x28, 0xa8, 0x68, 0xe8, 0x18, 0x98, 0x58, 0xd8, 0x38, 0xb8, 0x78, 0xf8,
	0x04, 0x84, 0x44, 0xc4, 0x24, 0xa4, 0x64, 0xe4, 0x14, 0x94, 0x54, 0xd4, 0x34, 0xb4, 0x74, 0xf4,
	0x0c, 0x8c, 0x4c, 0xcc, 0x2c, 0xac, 0x6c, 0xec, 0x1c, 0x9c, 0x5c, 0xdc, 0x3c, 0xbc, 0x7c, 0xfc,
	0x02, 0x82, 0x42, 0xc2, 0x22, 0xa2, 0x62, 0xe2, 0x12, 0x92, 0x52, 0xd2, 0x32, 0xb2, 0x72, 0xf2,
	0x0a, 0x8a, 0x4a, 0xca, 0x2a, 0xaa, 0x6a, 0xea, 0x1a, 0x9a, 0x5a, 0xda, 0x3a, 0xba, 0x7a, 0xfa,
	0x06, 0x86, 0x46, 0xc6, 0x26, 0xa6, 0x66, 0xe6, 0x16, 0x96, 0x56, 0xd6, 0x36, 0xb6, 0x76, 0xf6,
	0x0e, 0x8e, 0x4e, 0xce, 0x2e, 0xae, 0x6e, 0xee, 0x1e, 0x9e, 0x5e, 0xde, 0x3e, 0xbe, 0x7e, 0xfe,
	0x01, 0x81, 0x41, 0xc1, 0x21, 0xa1, 0x61, 0xe1, 0x11, 0x91, 0x51, 0xd1, 0x31, 0xb1, 0x71, 0xf1,
	0x09, 0x89, 0x49, 0xc9, 0x29, 0xa9, 0x69, 0xe9, 0x19, 0x99, 0x59, 0xd9, 0x39, 0xb9, 0x79, 0xf9,
	0x05, 0x85, 0x45, 0xc5, 0x25, 0xa5, 0x65, 0xe5, 0x15, 0x95, 0x55, 0xd5, 0x35, 0xb5, 0x75, 0xf5,
	0x0d, 0x8d, 0x4d, 0xcd, 0x2d, 0xad, 0x6d, 0xed, 0x1d, 0x9d, 0x5d, 0xdd, 0x3d, 0xbd, 0x7d, 0xfd,
	0x03, 0x83, 0x43, 0xc3, 0x23, 0xa3, 0x63, 0xe3, 0x13, 0x93, 0x53, 0xd3, 0x33, 0xb3, 0x73, 0xf3,
	0x0b, 0x8b, 0x4b, 0xcb, 0x2b, 0xab, 0x6b, 0xeb, 0x1b, 0x9b, 0x5b, 0xdb, 0x3b, 0xbb, 0x7b, 0xfb,
	0x07, 0x87, 0x47, 0xc7, 0x27, 0xa7, 0x67, 0xe7, 0x17, 0x97, 0x57, 0xd7, 0x37, 0xb7, 0x77, 0xf7,
	0x0f, 0x8f, 0x4f, 0xcf, 0x2f, 0xaf, 0x6f, 0xef, 0x1f, 0x9f, 0x5f, 0xdf, 0x3f, 0xbf, 0x7f, 0xff
};
#define REV_BITS(byte) rev_bitorder_table[byte]

//-------------------------------------------------------------------------
// Computes the 16-bit CCITT CRC according to the previous CRC, and the byte to add
// This function was adapted from Lammert Bies's free software library
// http://www.lammertbies.nl/comm/software/index.html
// Also, the crc table this function refers to was generated using
// functions from Lammert Bies's free software library and the CCITT
// polynomial of x^16 + x^12 + x^5 + x (0x1021)
static uint16_t update_crc_ccitt(uint16_t crc, uint8_t c)
{
	uint16_t tmp, short_c;
	short_c  = 0x00ff & (uint16_t)c;
	tmp = (crc >> 8) ^ short_c;
	crc = (crc << 8) ^ crc_tabccitt[tmp];
	return crc;
}

//-------------------------------------------------------------------------
// Computes the 16-bit CRC according to the CCITT/ITU-T Standard
// NOTE: bit-reversal within bytes is necessary because IEEE 802.15.4
// CRC is calculated on the packet in the order the bits are
// being sent, which is least-significan bit first.
static uint16_t ieee802154_crc16(uint8_t *tvb, uint32_t offset, uint32_t len)
{
	uint32_t cnt;
	uint16_t crc = 0x0000;
	for (cnt = 0; cnt < len; cnt++)
	{
		crc = update_crc_ccitt(crc, REV_BITS(tvb[offset + cnt]));
	}
	// Need to reverse the 16-bit field so that it agrees with the spec.
	return REV_BITS((crc & 0xff00) >> 8) + (REV_BITS(crc & 0x00ff) << 8);
}
