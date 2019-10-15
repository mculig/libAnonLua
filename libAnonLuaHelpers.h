/*
 * libAnonLuaHelpers.h
 *
 *  Created on: Sep 19, 2019
 *      Author: mislav
 */

#ifndef LIBANONLUAHELPERS_H_
#define LIBANONLUAHELPERS_H_

#include "stdio.h"
#include "stdint.h"
#include "string.h"
#include "arpa/inet.h"
#include "stdarg.h"
/*
 * Returns the offset, in bytes, from the beginning of the IPv6 header to the beginning of the provided next header.
 * The next header can be either an IPv6 extension header or the next protocol payload.
 * Returns: Next header offset or -1 in case of failure to find the desired header
 */
uint32_t ipv6_next_header_offset(const char* packet, int protocol_number);

//Helper function to calculate the internet checksum. This algorithm is used for TCP, UDP, ICMP, ICMPv6 and IPv4 checksums
//Calculating the checksum is different for different cases so separate functions will handle that. Here we'll only have the central logic
uint16_t calculate_internet_checksum(const char *data, int length);

//Returns an ipv4 or ipv6 address in human readable form
int humanForm(const char* address, int length, char* result);

//Closes count files using fclose, tests if the pointers are null to avoid segfaults
int closeFiles(int count, ...);

#endif /* LIBANONLUAHELPERS_H_ */
