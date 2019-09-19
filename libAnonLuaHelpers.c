/*
 * libAnonLuaHelpers.c
 *
 *  Created on: Sep 19, 2019
 *      Author: mislav
 */

#include "libAnonLuaHelpers.h"

/*
 * Returns the offset, in bytes, from the beginning of the IPv6 header to the beginning of the provided next header.
 * The next header can be either an IPv6 extension header or the next protocol payload.
 * Returns: Next header offset or -1 in case of failure to find the desired header
 */
uint32_t ipv6_next_header_offset(const char* packet, int protocol_number) {
	uint32_t header_offset = 40;
	uint8_t next_header;
	uint8_t header_length; //Header length is in octets, not bytes, so when converting we will multiply with 8
	uint16_t payload_length;
	//Verify we're an IPv6 packet
	if ((*packet >> 4) != 6)
		return -1; //If the value of the first 4 bits isn't 6, we're not dealing with IPv6, return a failure
	memcpy(&payload_length, packet + 4, 2); //First get the payload length. This is the length of the IPv6 payload sans header IN OCTETS
	next_header = *(packet + 6);
	while (next_header != protocol_number) {
		memcpy(&next_header, packet + header_offset, 1);
		memcpy(&header_length, packet + header_offset + 1, 1);
		if ((header_offset - 40 + 1 + header_length * 8) >= payload_length * 8)
			return -1; //If our offset minus header reaches the end of the payload, then we have no further headers and didn't find what we want
		header_offset += 1 + header_length * 8;
	}
	return header_offset;
}

//Helper function to calculate the internet checksum. This algorithm is used for TCP, UDP, ICMP, ICMPv6 and IPv4 checksums
//Calculating the checksum is different for different cases so separate functions will handle that. Here we'll only have the central logic
uint16_t calculate_internet_checksum(const char *data, int length) {
	int i;
	uint16_t result = 0;
	uint16_t tmp_val = 0;
	uint32_t tmp_res = 0;

	for (i = 0; i < length; i += 2) {
		memcpy(&tmp_val, data + i, 2);
		tmp_res += tmp_val;
	}
	//The checksum is calculated by adding 16-bit words together and adding any overflow into the least significant bit
	//When working with 32-bits, this overflow can simply be left alone and then later added back up
	//That's faster than checking every time
	//The 17th bit would have the value 65536 so we simply check if we're greater or equal to that value
	//If we are, we subtract 65535, which is equivalent to unsetting bit 17, then adding 1
	while (tmp_res >= 65536)
		tmp_res -= 65535;

	result += tmp_res;
	result = ~result;

	return result;
}
