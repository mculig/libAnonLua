/*
 * libAnonLua.c
 *
 *  Created on: Jul 7, 2019
 *      Author: Mislav Culig
 */

#include "lua5.2/lua.h"
#include "lua5.2/lualib.h"
#include "lua5.2/lauxlib.h"

#include "arpa/inet.h"
#include "stdint.h"
#include "time.h"
#include "string.h"
#include "stdlib.h"

//Crypto stuff
#include "openssl/conf.h"
#include "openssl/evp.h"
#include "openssl/err.h"

//Our own libraries
#include "pcapngw.h"
#include "linktype.h"
#include "cryptoPAN.h"
#include "libAnonLuaHelpers.h"

//Create a new pcapng file with a Section Header Block and a section length of 0
//Status 1=success, -1=failure
//Usage in Lua: create_filesystem(path)
static int create_filesystem(lua_State *L) {
	int status = -1;
	const char *path;

	//Get the file path
	path = luaL_checkstring(L, 1);

	//Create the filesystem
	status = create_pcapng_filesystem(path);

	//Push our result to the stack so failure or success can be verified in Lua
	lua_pushinteger(L, status);
	return 1;
}

//Add an interface description block. This adds a new interface to a section
//Status 1=success, -1=failure
//Usage in Lua: add_interface(path, linktype)
static int add_interface(lua_State *L) {
	int status = -1;
	const char *path;
	int link_type;

	//Get the file path
	path = luaL_checkstring(L, 1);
	//Get the link type
	link_type = luaL_checknumber(L, 2);

	status = add_IDB(path, link_type);

	lua_pushinteger(L, status);

	return 1;
}

//Write a packet to our filesystem
//Status 1=success, -1=failure
//Usage in Lua: write_packet(path, packet_bytes, packet_size, IDB ID)
static int write_packet(lua_State *L) {
	int status = -1;
	const char *packet_bytes;
	uint32_t packet_size;
	const char *path;
	int interface_id;

	//Get the file path
	path = luaL_checkstring(L, 1);
	//Check if the contents are light userdata
	packet_bytes = luaL_checkstring(L, 2);
	//packet = luaL_checkstring(L, 2);
	//Get the length
	packet_size = luaL_checknumber(L, 3);
	//Get the interface ID
	interface_id = luaL_checknumber(L, 4);

	status = add_EPB(path, packet_bytes, packet_size, interface_id);

	lua_pushinteger(L, status);
	return 1;
}

//Black marker takes a string if RAW bytes, its length, and the number of bits to set to 0 from the left or right
//Usage in  Lua: black_marker(ip_address, bits to mask)
static int black_marker(lua_State *L) {

	int bytes_to_mask = 0;
	int bits_to_mask = 0;
	uint8_t mask = 0xFF;
	const char *bytes;
	char *masked_bytes;
	int bytes_length;
	int mask_length;
	int direction = 0;
	int start_byte = 0;
	int last_byte = 0;
	int end_byte = 0;
	int i;

	//Get the values we need from Lua
	bytes = luaL_checkstring(L, 1);
	bytes_length = luaL_checknumber(L, 2);
	mask_length = luaL_checknumber(L, 3);
	direction = luaL_checknumber(L, 4);

	//Create a space in memory for the modified value
	masked_bytes = (char*) malloc(bytes_length);

	//Copy the value over
	memcpy(masked_bytes, bytes, bytes_length);

	//Get the number of bytes to completely mask and number of bits of the last byte to mask
	bytes_to_mask = mask_length / 8;
	bits_to_mask = mask_length % 8;

	//Set the appropriate bytes to mask
	if (direction == 0) {
		start_byte = bytes_length - bytes_to_mask;
		end_byte = bytes_length - 1;
		last_byte = start_byte - 1;
		//Generate the bit mask. This is used to mask the final byte which isn't fully zeroed out
		for (i = 0; i < bits_to_mask; i++)
			mask ^= (0x01 << i);
	} else {
		start_byte = 0;
		end_byte = bytes_to_mask - 1;
		last_byte = end_byte + 1;
		//If we're going from left the bit mask must be generated differently
		for (i = 0; i < bits_to_mask; i++)
			mask ^= (0x80 >> i);
	}
	//Mask bytes with 0. Bytes fully within the mask are simply zeroed out
	for (i = start_byte; i <= end_byte; i++)
		*(masked_bytes + i) = 0x00;
	//Apply the mask to the final byte.
	if (bits_to_mask > 0)
		*(masked_bytes + last_byte) &= mask;

	lua_pushlstring(L, masked_bytes, bytes_length);

	//Free memory
	free(masked_bytes);

	return 1;
}

//Calculates a correct ipv4 checksum from an IPv4 header and returns the checksum and the correct header
//Usage in Lua: calculate_ipv4_checksum(IPv4_header)
static int calculate_ipv4_checksum(lua_State *L) {
	const char *header;
	char *data;
	uint8_t length;
	char checksum[2];
	int checksum_offset = 10; //This is where in the header we'll find the checksum.
	uint16_t result = 0;
	//Get the header
	header = luaL_checkstring(L, 1);
	//Version and Internet Header Length are in the 1st byte. Length is the lower 4 bits, so the mask 0x0F gets rid of the top 4 bits
	length = *header & 0x0F;
	//The Internet Header Length is a Length in 32-bit words, we need bytes so we're multiplying by 4
	length *= 4;

	//Allocate memory for our header since we receive it as a constant char and need to change the checksum to be 0
	data = (char *) malloc(length);

	//Copy our entire header over
	memcpy(data, header, length);

	//Zero-out the checksum
	memset(data + checksum_offset, 0x00, 2);

	//Calculate the result
	result = calculate_internet_checksum(data, length);

	//Set our checksum into the actual packet
	memcpy(data + checksum_offset, &result, 2);

	//Copy the result into our checksum string
	memcpy(checksum, &result, 2);

	//Push our checksum and the data to the stack
	lua_pushlstring(L, checksum, 2);
	lua_pushlstring(L, data, length);

	//Free memory
	free(data);

	return 2;
}

//Calculates a correct TCP/UDP checksum for a TCP/UDP datagram in an IPv4/IPv6 packet
//Usage in Lua: calculate_tcp_udp_checksum(packet)
static int calculate_tcp_udp_checksum(lua_State *L) {

	const char *packet;

	uint8_t protocol_version;

	uint8_t ipv4_header_length; //With IPv4 things are simple. Header length is the length of the IPv4 header

	uint8_t ipv6_next_header; //With IPv6 we don't have header length, but we have next header so we can parse until we find the payload

	//This plays a dual role. For IPv4 a total length including header and payload is present.
	//For IPv6 the payload length is the length excluding the IPv6 header, but including extension headers
	uint16_t length;

	//Pointers for the pseudo_header and the whole datagram (with correct checksum)
	char *pseudo_header;
	char *datagram;

	//Offsets from the start of the header for various IPv4 fields.
	const int ipv4_total_length_offset = 2;
	const int ipv4_protocol_offset = 9;
	const int ipv4_source_address_offset = 12;
	const int ipv4_destination_address_offset = 16;

	//Offsets from the start of the header for various IPv6 fields.
	const int ipv6_source_address_offset = 8;
	const int ipv6_destination_address_offset = 24;
	const int ipv6_payload_length_offset = 4;
	const int ipv6_next_header_offset = 6;

	//Offset within the IPv6 payload that we're currently parsing at
	int ipv6_payload_parsing_offset = 40; //This is initially set to 40 as the fixed part of an IPv6 header is 40 bytes
	//Length of extension header we intend to skip
	int ipv6_extension_header_length = 0;
	//Remaining length of the payload after the options we've parsed
	uint16_t ipv6_remaining_payload_length = 0;

	//Offset of the checksum from the start of the TCP and UDP datagrams
	const int tcp_checksum_offset = 16;
	const int udp_checksum_offset = 6;

	const uint8_t protocol_tcp = 6; //Protocol=6 for TCP
	const uint8_t protocol_udp = 17; //Protocol=17 for UDP
	uint8_t protocol = 0; //Generic protocol to set

	uint16_t datagram_length = 0; //This will be equal to IPv4 total length minus IHL*4
	uint16_t datagram_length_reversed = 0; //This will be the reversed-byte-order tcp_length we write into the pseudo-header which is in network byte order
	int pseudo_header_length = 0;
	char checksum[2];
	uint16_t result = 0;

	//Get the packet
	packet = luaL_checkstring(L, 1);

	//Figure out if we're IPv4 or IPv6
	protocol_version = *packet & 0xF0; //Version is the 1st 4 bits in both
	protocol_version = protocol_version >> 4;

	if (protocol_version == 4) {

		//We're dealing with IPv4

		//Get the header length in bytes. IHL is the lower 4 bits of the byte and is in 32-bit words so we mask, then multiply by 4
		ipv4_header_length = *packet & 0x0F;
		ipv4_header_length *= 4;

		//Get the protocol from the IPv4 header
		memcpy(&protocol, packet + ipv4_protocol_offset, 1);

		//Due to data being in network byte order we need to move the bytes around to get a proper total length
		memcpy(&length, packet + ipv4_total_length_offset, 1);
		length = length >> 8;
		memcpy(&length, packet + ipv4_total_length_offset + 1, 1);
		datagram_length = length - ipv4_header_length; //We can get the TCP header length by now subtracting the ipv4 header length from the total length
		datagram_length_reversed = datagram_length >> 8; //We generate the reversed length here for the purpose of writing it into the pseudo_header
		datagram_length_reversed += datagram_length << 8;

		//Allocate bytes for the IPv4 pseudo-header (12) + TCP header and data (tcp_length) + padding if needed to contain a multiple of 16-bit fields
		pseudo_header_length = 12 + datagram_length
				+ (12 + datagram_length) % 2;
		pseudo_header = (char *) malloc(pseudo_header_length);
		memset(pseudo_header, 0x00, pseudo_header_length); //Set it all to 0 so we don't have to worry later

		//Allocate bytes for the datagram
		datagram = (char *) malloc(datagram_length);
		//Copy the actual datagram
		memcpy(datagram, packet + ipv4_header_length, datagram_length);

		//Copy the appropriate values into the pseudo_header
		memcpy(pseudo_header, packet + ipv4_source_address_offset, 4); //Source address
		memcpy(pseudo_header + 4, packet + ipv4_destination_address_offset, 4); //Destination address
		memcpy(pseudo_header + 9, &protocol, 1); //Protocol. Byte before is all zeros
		memcpy(pseudo_header + 10, &datagram_length_reversed, 2); //datagram length, but byte-order needs to be reversed from little-endian machine to big-endian network order
		memcpy(pseudo_header + 12, packet + ipv4_header_length,
				datagram_length); //Rest of the TCP packet
		//We need to erase the checksum in different places depending if it's UDP or TCP
		if (protocol == protocol_tcp)
			memset(pseudo_header + 28, 0x00, 2); //Erase the existing TCP checksum
		else if (protocol == protocol_udp)
			memset(pseudo_header + 18, 0x00, 2); //Erase the existing UDP checksum

		//Calculate the checksum
		result = calculate_internet_checksum(pseudo_header,
				pseudo_header_length);

		//Copy the result into our checksum string
		memcpy(checksum, &result, 2);
		if (protocol == protocol_tcp)
			memcpy(datagram + tcp_checksum_offset, checksum, 2); //Copy the checksum into the TCP frame
		else if (protocol == protocol_udp)
			memcpy(datagram + udp_checksum_offset, checksum, 2); //Copy the checksum into the UDP frame

	} else if (protocol_version == 6) {

		//We're dealing with IPv6

		//Due to data being in network byte order we need to move the bytes around to get a proper payload length
		memcpy(&length, packet + ipv6_payload_length_offset, 1); //IPv6 payload length. This includes extension headers that must be parsed
		length = length >> 8;
		memcpy(&length, packet + ipv6_payload_length_offset + 1, 1);
		//Get the next header
		memcpy(&ipv6_next_header, packet + ipv6_next_header_offset, 1);

		ipv6_remaining_payload_length = length; //The remaining payload length we'll use when skipping extension headers, if needed

		//While the next header isn't TCP or UDP we need to iterate through extension headers
		//We don't recognize or care for the type of extension header
		//But this does mean we have to introduce checks so we don't end up going outside of our memory space
		//Misunderstanding data as a TCP or UDP next header and returning a bogus result isn't that much of a concern
		//If a user passes an IPv6 packet without a payload the result would be useless anyway

		while (ipv6_next_header != protocol_tcp
				&& ipv6_next_header != protocol_udp) {
			//If we're neither TCP nor UDP; we need to skip ahead

			//Read the next header
			memcpy(&ipv6_next_header, packet + ipv6_payload_parsing_offset, 1);
			//Read the length of the extension header
			memcpy(&ipv6_extension_header_length,
					packet + ipv6_payload_parsing_offset + 1, 1); //This length is the length without the next header field

			if (ipv6_remaining_payload_length
					<= (ipv6_extension_header_length + 1)) {
				//If there is less or equal bytes left than what we perceive to be the extension header length, we can end our parsing. We haven't found a TCP or UDP header
				ipv6_next_header = 0;
				break;
			} else {
				//Subtract the length of the extension header from the remaining payload length. Add 1 for the next header field that isn't included in the length of the header
				ipv6_remaining_payload_length -= (ipv6_extension_header_length
						+ 1);
			}
			if (ipv6_remaining_payload_length < 8) {
				//Less than 8 bytes is too small even for UDP. We can give up here. Setting the next header to 0 makes sure the conditions below aren't satisfied for tcp or udp
				ipv6_next_header = 0;
				break;
			}

			//Assuming we haven't had a reason to break before, we continue our loop by skipping forward to the next header
			ipv6_payload_parsing_offset += ipv6_extension_header_length + 1; //Again we must add 1 to the skip for the next header field that isn't part of the header length
		}

		if (ipv6_next_header == 0) {

			//Set the result to something obviously and verifyably wrong like in case we receive a non-IP header
			//The 0 here is the one we set manually above to make sure we trigger this
			checksum[0] = 0;
			checksum[1] = '\0';
			datagram_length = 1;
			pseudo_header = (char*) malloc(1);
			datagram = (char*) malloc(1);
			*datagram = '\0';
		} else {

			datagram_length = ipv6_remaining_payload_length;
			datagram_length_reversed = datagram_length >> 8; //We generate the reversed length here for the purpose of writing it into the pseudo_header
			datagram_length_reversed += datagram_length << 8;

			pseudo_header_length = 40 + ipv6_remaining_payload_length
					+ (40 + ipv6_remaining_payload_length) % 2; //Length of the pseudo_header
			pseudo_header = (char *) malloc(pseudo_header_length);
			memset(pseudo_header, 0x00, pseudo_header_length); //Set it all to 0 so we don't have to worry later

			memcpy(pseudo_header, packet + ipv6_source_address_offset, 16); //Copy source address
			memcpy(pseudo_header + 16, packet + ipv6_destination_address_offset,
					16); //Copy destination address
			//Lenght is a 4-byte field in the pseudo-header, probably to accomodate jumbo packets. We're not doing those and our length is 2 bytes
			//Since wire in network byte order, the 1st two bytes are our reversed datagram length, the 2nd two are zeroes.
			memcpy(pseudo_header + 32, &datagram_length_reversed, 2);
			memset(pseudo_header + 34, 0x00, 2); //Zero the higher bytes of the field
			memset(pseudo_header + 36, 0x00, 3); //Write the three bytes of zeroes that follow
			memcpy(pseudo_header + 39, &ipv6_next_header, 1); //Write the next header
			memcpy(pseudo_header + 40, packet + ipv6_payload_parsing_offset,
					ipv6_remaining_payload_length); //Copy the remaining payload
			//Zero-out the appropriate spot for the checksum
			if (ipv6_next_header == protocol_tcp)
				memset(pseudo_header + 56, 0x00, 2); //Erase the existing TCP checksum
			else if (ipv6_next_header == protocol_udp)
				memset(pseudo_header + 46, 0x00, 2); //Erase the existing UDP checksum

			for (result = 0; result < pseudo_header_length; result++) {
				printf("%x\n", *(pseudo_header + result));
			}

			//Create the datagram
			datagram = (char *) malloc(datagram_length); //Create the datagram
			memcpy(datagram, packet + ipv6_payload_parsing_offset,
					ipv6_remaining_payload_length); //Copy the datagram

			//Calculate the checksum
			result = calculate_internet_checksum(pseudo_header,
					pseudo_header_length);

			printf("Checksum: %x\n", result);

			//Copy the result into our checksum string
			memcpy(checksum, &result, 2);
			if (ipv6_next_header == protocol_tcp)
				memcpy(datagram + tcp_checksum_offset, checksum, 2); //Copy the checksum into the TCP frame
			else if (ipv6_next_header == protocol_udp)
				memcpy(datagram + udp_checksum_offset, checksum, 2); //Copy the checksum into the UDP frame
		}

	} else {
		//This should handle if we receive a non-IP header
		checksum[0] = 0;
		checksum[1] = '\0';
		datagram_length = 1;
		pseudo_header = (char*) malloc(1);
		datagram = (char*) malloc(1);
		*datagram = '\0';
	}

	lua_pushlstring(L, checksum, 2); //Push the checksum onto the Lua stack
	lua_pushlstring(L, datagram, datagram_length); //Push the datagram onto the Lua stack

	//Free memory
	free(pseudo_header);
	free(datagram);

	return 2;
}

/* Calculate the checksum of an ICMP packet
 * Usage in Lua: calculate_icmp_checksum(icmp bytes, icmp length)
 */
static int calculate_icmp_checksum(lua_State *L) {
	const char *icmp_orig;
	char *icmp_recalculated;
	int length;
	uint16_t result;
	char checksum[2];

	//Get the original icmp and its length
	icmp_orig = luaL_checkstring(L, 1);
	length = luaL_checknumber(L, 2);

	//Allocate space, copy ICMP packet, set checksum to 0
	icmp_recalculated = (char *) malloc(length);
	memcpy(icmp_recalculated, icmp_orig, length);
	memset(icmp_recalculated + 2, 0x00, 2);

	//Calculate checksum and copy it into new icmp header
	result = calculate_internet_checksum(icmp_recalculated, length);
	memcpy(checksum, &result, 2);
	memcpy(icmp_recalculated + 2, checksum, 2);

	lua_pushlstring(L, checksum, 2); //Push the checksum onto the Lua stack
	lua_pushlstring(L, icmp_recalculated, length); //Push the recalculated icmp packet onto the Lua stack
	free(icmp_recalculated);
	return 2;
}

/*
 * Calculate the checksum of an ICMPv6 packet
 * Usage in Lua: calculate_icmpv6_checksum(packet bytes)
 */
static int calculate_icmpv6_checksum(lua_State *L) {
	const char *packet_orig;
	char *packet_recalc;
	unsigned char *pseudo_header;
	int length;
	uint16_t result;
	char checksum[2];
	uint32_t offset;
	uint32_t icmpv6_length;
	uint32_t icmpv6_length_big_endian;

	//Get the packet and length from Lua
	packet_orig = luaL_checkstring(L, 1);
	length = luaL_checknumber(L, 2);

	//Allocate space, copy packet
	packet_recalc = (char *) malloc(length);
	memcpy(packet_recalc, packet_orig, length);

	//Get the offset of ICMPv6 from the beginning of the IPv6 packet
	offset = ipv6_next_header_offset(packet_orig, 58); //Get the offset of ICMPv6 (protocol number 58)
	icmpv6_length = length - offset;
	icmpv6_length_big_endian = htonl(icmpv6_length);

	//Create the pseudo-header (plus payload. We call it pseudo-header but really it also includes the payload)
	pseudo_header = (unsigned char *) malloc(icmpv6_length + 40);
	memcpy(pseudo_header, packet_orig + 8, 32); //Copy source and destination address
	memcpy(pseudo_header + 32, &icmpv6_length_big_endian, 4); //Set the ICMPv6 length
	memset(pseudo_header + 36, 0x00, 3); //3 bytes of zeroes
	memset(pseudo_header + 39, 58, 1); //1-byte protocol number for ICMPv6
	memcpy(pseudo_header + 40, packet_orig+offset, length - offset); //Copy the rest of the ICMPv6 payload
	memset(pseudo_header + 42, 0x00, 2); //Set the 2-byte checksum in the ICMPv6 payload to 0

	//Calculate the checksum
	result = calculate_internet_checksum((char*) pseudo_header,
			length - offset + 40);
	//Copy the calculated checksum into the ICMPv6 checksum field
	memcpy(packet_recalc + offset + 2, &result, 2);
	//Copy the result into the checksum string
	memcpy(checksum, &result, 2);

	//Push results to Lua stack
	lua_pushlstring(L, checksum, 2);
	lua_pushlstring(L, packet_recalc, length);

	//Free memory
	free(packet_recalc);
	free(pseudo_header);

	return 2;
}

//Little helper for cleanup calls for libcrypto
static void crypto_cleanup() {
	//libcrypto cleanup. See https://wiki.openssl.org/index.php/Libcrypto_API
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
	return;
}
//Calculate the HMAC of a field and return field-length bytes
//Usage in Lua: HMAC(bytes, bytes_length, salt, iterations)
static int HMAC(lua_State *L) {
	int status = -1;
	const char *bytes;
	const char *salt;
	int length;
	int iterations;
	char *result;

	//Get the arguments from Lua
	bytes = luaL_checkstring(L, 1);
	length = luaL_checknumber(L, 2);
	salt = luaL_checkstring(L, 3);
	iterations = luaL_checknumber(L, 4);

	//Create the output array
	result = (char *) malloc(length);

	//According to OpenSSL wiki libcrypto stuff needs to first be initialized. See https://wiki.openssl.org/index.php/Libcrypto_API
	//OPENSSL_config() is deprecated and instead the docs suggest using CONF_modules_load directly. This differs from the stuff on the wiki
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	if (CONF_modules_load(NULL, NULL, 0) <= 0) {
		crypto_cleanup();
		lua_pushinteger(L, status);
		lua_pushlstring(L, '\0', 1);
		free(result);
		return 2;
	}
	//PKCS5_PBKDF2_HMAC really wants unsigned char pointers instead of just char pointers. Honestly there is no difference here for us because we're just using them as bytes
	//Just casting these to unsigned char * to satisfy the compiler should have 0 consequences on the result
	if (PKCS5_PBKDF2_HMAC(bytes, length, (unsigned char *) salt, strlen(salt),
			iterations, EVP_sha256(), length, (unsigned char *) result) <= 0) {
		crypto_cleanup();
		lua_pushinteger(L, status);
		lua_pushlstring(L, '\0', 1);
		free(result);
		return 2;
	}
	crypto_cleanup();
	status = 1;
	//Push the status and result
	lua_pushinteger(L, status);
	lua_pushlstring(L, result, length);
	free(result);
	return 2;
}

//Here be our cryptoPAN implementation

/*
 * Sets up what we need for the cryptoPAN algorithm
 * Usage in Lua: init_cryptoPAN(output_file)
 */
static int init_cryptoPAN(lua_State *L) {
	const char *filename;
	int status = -1;
	char state[64]; //32-byte AES256 KEY, 16-byte IV, 16-byte PAD sufficient for padding both IPv6 and IPv4

	filename = luaL_checkstring(L, 1);

	status = cryptoPAN_init(filename, state);
	lua_pushnumber(L, status);
	if (status == -1)
		lua_pushlstring(L, '\0', 1);
	else
		lua_pushlstring(L, state, STATE_SIZE);
	return 2;
}

/*
 *  Returns an IPv4 address anonymized using the cryptoPAN algorithm
 *  Usage in Lua: cryptoPAN_anonymize_ipv4(state, address)
 */
static int cryptoPAN_anonymize_ipv4(lua_State *L) {
	int status = -1;

	const unsigned char *state;

	const char *address;
	uint32_t address_int;
	char anon_address[4];

	const unsigned char *key; //[32] AES256 KEY
	const unsigned char *iv; //[16] AES256 IV
	const unsigned char *pad; //[16]Padding bytes

	state = (unsigned char *) luaL_checkstring(L, 1);
	address = luaL_checkstring(L, 2);

	//Set up pointers to key, iv and pad, which are parts of state
	key = state;
	iv = state + 32;
	pad = (state + 48);

	//Get the address to our integer address
	memcpy(&address_int, address, 4);

	//Use our cryptoPAN function
	status = cryptoPAN_ipv4(address_int, (uint32_t *) anon_address, pad, key,
			iv);

	lua_pushnumber(L, status);
	if (status == -1)
		lua_pushlstring(L, '\0', 1);
	else
		lua_pushlstring(L, anon_address, 4);
	return 2;
}

/*
 * Returns an IPv6 address anonymized using the cryptoPAN algorithm
 * Usage in Lua: cryptoPAN_anonymize_ipv6(state, address)
 */

static int cryptoPAN_anonymize_ipv6(lua_State *L) {
	int status = -1;

	const unsigned char *state;

	const char *address;
	uint32_t address_int[4];
	char anon_address[16];

	const unsigned char *key; //[32] AES256 KEY
	const unsigned char *iv; //[16] AES256 IV
	const unsigned char *pad; //[16]Padding bytes

	state = (unsigned char *) luaL_checkstring(L, 1);
	address = luaL_checkstring(L, 2);

	//Set up pointers to key, iv and pad, which are parts of state
	key = state;
	iv = state + 32;
	pad = (state + 48);

	//Get the address to our integer address
	memcpy(&address_int, address, 16);

	//Use our cryptoPAN function
	status = cryptoPAN_ipv6(address_int, (uint32_t *) anon_address, pad, key,
			iv);
	lua_pushnumber(L, status);
	if (status == -1)
		lua_pushlstring(L, '\0', 1);
	else
		lua_pushlstring(L, anon_address, 16);
	return 2;
}

/*
 *
 *  Here is the Lua stuff!
 *
 */

//To register library with lua
static const struct luaL_Reg library[] = { { "create_filesystem",
		create_filesystem }, { "add_interface", add_interface }, {
		"write_packet", write_packet }, { "black_marker", black_marker }, {
		"calculate_ipv4_checksum", calculate_ipv4_checksum }, {
		"calculate_tcp_udp_checksum", calculate_tcp_udp_checksum }, {
		"calculate_icmp_checksum", calculate_icmp_checksum }, {
		"calculate_icmpv6_checksum", calculate_icmpv6_checksum },
		{ "HMAC", HMAC }, { "init_cryptoPAN", init_cryptoPAN }, {
				"cryptoPAN_anonymize_ipv4", cryptoPAN_anonymize_ipv4 }, {
				"cryptoPAN_anonymize_ipv6", cryptoPAN_anonymize_ipv6 }, { NULL,
				NULL } };

//Function to register library
int luaopen_libAnonLua(lua_State *L) {
	luaL_newlib(L, library);
	setHeaderLinkTypeValues(L); //Load the link types from the CSV.
	return 1;
}
