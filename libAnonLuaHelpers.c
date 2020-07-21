/*
 * libAnonLuaHelpers.c
 *
 *  Created on: Sep 19, 2019
 *      Author: mislav
 */

#include "libAnonLuaHelpers.h"

//Switch a 128-bit address to host order
void ntoh_128(uint32_t *address) {
	int i;
	uint8_t byte_buffer;
	uint8_t *addr;
	uint16_t test = 0x0102;
	uint8_t *testptr;

	testptr = (uint8_t *) &test;

	if (testptr[0] == 0x01) //Endianness test. See which byte was written first
		return;

	addr = (uint8_t *) address;

	for (i = 0; i < 8; i++) {
		byte_buffer = addr[i];
		addr[i] = addr[15 - i];
		addr[15 - i] = byte_buffer;
	}
}
//These functions are the same. Even arpa/inet does it this way which can be seen in arpa/inet.c source
void hton_128(uint32_t *address) {
	ntoh_128(address);
}

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
	payload_length=payload_length>>8 | payload_length<<8; //Replace the two bytes because we use different byte order
	next_header = *(packet + 6);
	while (next_header != protocol_number) {
		memcpy(&next_header, packet + header_offset, 1);
		memcpy(&header_length, packet + header_offset + 1, 1);
		if ((header_offset - 40 + 8 + header_length * 8) >= payload_length * 8)
			return -1; //If our offset minus header reaches the end of the payload, then we have no further headers and didn't find what we want
		header_offset += 8 + header_length * 8;
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

/*
 *Helper function to transform an IPv4 or IPv6 address into human-readable form
 */
int humanForm(const char* address, size_t length, char* result)
{
	struct in_addr ipv4;
	struct in6_addr ipv6;
	if(length==4)
	{
		memcpy(&ipv4, address, 4);
		inet_ntop(AF_INET, &ipv4, result, INET_ADDRSTRLEN);
		return 1;
	}
	else if(length==16)
	{
		memcpy(&ipv6, address, 16);
		inet_ntop(AF_INET6, &ipv6, result, INET6_ADDRSTRLEN);
		return 1;
	}
	else
	{
		printf("Error transforming address to human-readable form: Input length does not match IPv4 or IPv6 length!\n");
		return -1;
	}
}

/*
 * Helper function to check if an IPv4 address is in a subnet
 * Address is assumed to be an array of bytes in network order, cidr_subnet is a string with a subnet in CIDR notation, i.e. 192.168.1.0/24
 */
int	ipv4_in_subnet(const char* address, const char* cidr_subnet)
{
	uint32_t test_address;
	uint32_t network_address;
	uint32_t subnet_mask;
	char *network_address_char;
	uint8_t cidr_subnet_network_length;
	uint8_t cidr_subnet_mask_bit_count=0;
	int i;

	//Get the length of the network part of cidr_subnet. If / is found at spot 5, there are 5 characters before /, namely 0-4
	cidr_subnet_network_length = strchr(cidr_subnet, '/') - cidr_subnet;
	network_address_char = (char *) malloc(cidr_subnet_network_length+1); //+1 so we can add the \0 character

	memcpy(&test_address, address, 4);

	memcpy(network_address_char, cidr_subnet, cidr_subnet_network_length);
	network_address_char[cidr_subnet_network_length]='\0';

	inet_pton(AF_INET, network_address_char, &network_address); //Network address should now contain bytes representing the address in the CIDR notation subnet in network order

	free(network_address_char); //We don't need you anymore. Thank you for your service.

	//Get the number of bits in the subnet mask
	for(i=cidr_subnet_network_length+1; i<strlen(cidr_subnet); i++)
	{
		cidr_subnet_mask_bit_count*=10;
		cidr_subnet_mask_bit_count+=cidr_subnet[i]-48; //Convert char to number
	}

	//Set the subnet mask
	subnet_mask=0xFFFFFFFF<<(32-cidr_subnet_mask_bit_count);
	subnet_mask=htonl(subnet_mask);

	network_address=network_address & subnet_mask; //Make sure the network address really is a network address by anding it with the subnet_mask

	if((test_address & subnet_mask) == network_address)
		return 1;

	return -1;
}

/*
 * Helper function to check if an IPv46address is in a subnet
 * Address is assumed to be an array of bytes in network order, cidr_subnet is a string with a subnet in CIDR notation, i.e. fe80::01/64
 */
int	ipv6_in_subnet(const char* address, const char* cidr_subnet)
{
	struct in6_addr test_address;
	struct in6_addr network_address;
	struct in6_addr subnet_mask;
	char *network_address_char;
	uint8_t cidr_subnet_network_length;
	uint8_t cidr_subnet_mask_bit_count=0;
	int i;

	//Get the length of the network part of cidr_subnet. If / is found at spot 5, there are 5 characters before /, namely 0-4
	cidr_subnet_network_length = strchr(cidr_subnet, '/') - cidr_subnet;
	network_address_char = (char *) malloc(cidr_subnet_network_length+1); //+1 so we can add the \0 character

	memcpy(&test_address, address, 16);

	memcpy(network_address_char, cidr_subnet, cidr_subnet_network_length);
	network_address_char[cidr_subnet_network_length]='\0';

	inet_pton(AF_INET6, network_address_char, &network_address); //Network address should now contain bytes representing the address in the CIDR notation subnet in network order

	free(network_address_char); //We don't need you anymore. Thank you for your service.

	//Get the number of bits in the subnet mask
	for(i=cidr_subnet_network_length+1; i<strlen(cidr_subnet); i++)
	{
		cidr_subnet_mask_bit_count*=10;
		cidr_subnet_mask_bit_count+=cidr_subnet[i]-48; //Convert char to number
	}

	i=0;
	while(cidr_subnet_mask_bit_count>8)
	{
		subnet_mask.__in6_u.__u6_addr8[i]=0xFF;
		cidr_subnet_mask_bit_count-=8;
		i++;
	}
	subnet_mask.__in6_u.__u6_addr8[i]=0xFF<<(8-cidr_subnet_mask_bit_count);
	i++;
	while(i<16)
	{
		subnet_mask.__in6_u.__u6_addr8[i]=0;
		i++;
	}

	//Make sure the network address really is a network address by anding it with the subnet_mask
	for(i=0;i<4;i++)
		network_address.__in6_u.__u6_addr32[i] = network_address.__in6_u.__u6_addr32[i] & subnet_mask.__in6_u.__u6_addr32[i];


	//Here the logic is the reverse from the logic in the ipv4 method. If any 32-bit block of the IPv6 doesn't match the network address when the mask is applied
	//then we know the whole doesn't match and return -1 immediately. Checking if it all does match would require a variable, but 1 failure is enough for it not to match
	for(i=0;i<4;i++)
		if((test_address.__in6_u.__u6_addr32[i] & subnet_mask.__in6_u.__u6_addr32[i]) != network_address.__in6_u.__u6_addr32[i])
			return -1;

	return 1;
}

/*
 * Variadic function to check pointers and close files
 * Returns count of closed files
 */
int closeFiles(int count, ...)
{
	va_list ap;
	int i;
	int closed=0;
	FILE *fp;

	va_start(ap, count);

	for(i=0;i<count;i++)
	{
		fp=va_arg(ap,FILE*);
		if(fp!=NULL)
		{
			fclose(fp);
			closed++;
		}
	}

	va_end(ap);
	return closed;
}

