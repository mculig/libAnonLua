/*
 * Lua_library.c
 *
 *  Created on: Jul 7, 2019
 *      Author: mislav
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

//Block types
#define SHB_TYPE 0x0A0D0D0A
#define SHB_BOM 0x1A2B3C4D
#define IDB_TYPE 0x00000001
#define EPB_TYPE 0x00000006

//Offset from beginning of SHB to section length segment
#define SECTION_LENGTH_BEGIN 16

//Minimum lengths of blocks (no options/payload)
#define SHB_MIN_LENGTH 28
#define IDB_MIN_LENGTH 20
#define EPB_MIN_LENGTH 32

//Structures for file system
//SHB. A pcapng file can contain multiple and must always start with one
typedef struct section_header_block {
	uint32_t block_type;
	uint32_t block_length;
	uint32_t byte_order_magic;
	uint16_t major_version;
	uint16_t minor_version;
	uint64_t section_length; //This should be a signed 64 bit integer where -1 means not specified. Unsigned may rise issues past a certain size. Should explore!
//Options - added separately as they aren't static
//Block length - added separately after options are added
} SHB;
//IDB. A EPB must point to a valid Interface Description Block, so we need to add one
typedef struct interface_description_block {
	uint32_t block_type;
	uint32_t block_length;
	uint16_t link_type;
	uint16_t reserved;
	uint32_t SnapLen;
//Options - added separately as they aren't static
//Block length - added separately after options are added
} IDB;
//EPB. Enhanced Packet Blocks contain our captured data
typedef struct enhanced_packet_block {
	uint32_t block_type;
	uint32_t block_length;
	uint32_t interface_id;
	uint32_t timestamp_high;
	uint32_t timestamp_low;
	uint32_t captured_packet_length;
	uint32_t original_packet_length;
//Packet data is appended to the block past this point. That will be handled in the writer as no static length exist
//Options - added separately as they aren't static
//Block length - added separately after options are added
} EPB;
//Option blocks
typedef struct option {
	uint16_t optcode;
	uint16_t length;
} option;

//Create a new pcapng file with a Section Header Block and a section length of 0
//Status 1=success, -1=failure
//Usage in Lua: create_filesystem(path)
static int create_filesystem(lua_State *L) {
	int status = -1;
	const char *path;
	FILE* file;
	SHB shb = { SHB_TYPE, SHB_MIN_LENGTH, SHB_BOM, 1, 0, 0 };

	//Get the file path
	path = luaL_checkstring(L, 1);
	//Try to open the file
	file = fopen(path, "wb");
	//Check if it worked. Return if not
	if (file != NULL)
		status = 1;
	else
		return 1;
	//Write our SHB to the file
	fwrite(&shb, sizeof(shb), 1, file);
	//Blocks end with variable length options followed by another block_length. For now, no options, so we end with length
	fwrite(&(shb.block_length), sizeof(shb.block_length), 1, file);
	//Close the file
	fclose(file);
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
	int linktype;
	IDB idb = { IDB_TYPE, IDB_MIN_LENGTH, 0, 0, 0 };
	FILE *file;
	uint32_t shb_check;
	uint32_t block_length;
	uint64_t section_length;

	//Get the file path
	path = luaL_checkstring(L, 1);
	//Get the link type
	linktype = luaL_checknumber(L, 2);
	//Set the link type
	idb.link_type = linktype;

	//Try to open the file
	file = fopen(path, "r+");
	//Check if it worked. Return if not
	if (file != NULL)
		status = 1;
	else
		return 1;

	//Read the 1st 32 bits, the block type should be there and should match the shb type.
	fread(&shb_check, sizeof(shb_check), 1, file);
	//If there was a reading error or the read returned something other than the SHB, we have a bad file
	if (ferror(file) || shb_check != SHB_TYPE) {
		status = -1;
		return 1;
	}
	//Read the length of the block. This may vary so we can't just blindly skip ahead
	fread(&block_length, sizeof(block_length), 1, file);
	//Skip to the section length
	fseek(file, 8, SEEK_CUR);
	//Read the length of the section.
	fread(&section_length, sizeof(section_length), 1, file);
	//Skip to end of section
	fseek(file, block_length + section_length, SEEK_SET);

	//Write the IDB
	fwrite(&idb, sizeof(idb), 1, file);
	//Blocks end with variable length options followed by another block_length. For now, no options, so we end with length
	fwrite(&(idb.block_length), sizeof(idb.block_length), 1, file);

	//Increment our section length
	section_length += idb.block_length;

	//Seek to the SHB section length and write the new length
	fseek(file, SECTION_LENGTH_BEGIN, SEEK_SET);
	fwrite(&section_length, sizeof(section_length), 1, file);

	//Close the file
	fclose(file);

	lua_pushinteger(L, status);

	return 1;
}

//Write a packet to our filesystem
//Status 1=success, -1=failure
//Usage in Lua: write_packet(path, packet_bytes, packet_size, IDB ID)
static int write_packet(lua_State *L) {
	int status = -1;
	const char *packet;
	uint32_t packet_length;
	const char *path;
	FILE* file;
	uint32_t shb_check;
	uint32_t block_length;
	uint64_t section_length;
	uint32_t interface_id;
	int padding_length = 0;
	uint8_t pad = 0;
	struct timespec system_time;
	uint64_t time_micros;
	EPB epb;

	//Get the file path
	path = luaL_checkstring(L, 1);
	//Check if the contents are light userdata
	packet = luaL_checkstring(L, 2);
	//packet = luaL_checkstring(L, 2);
	//Get the length
	packet_length = luaL_checknumber(L, 3);
	//Get the interface ID
	interface_id = luaL_checknumber(L, 4);
	//Try to open the file
	file = fopen(path, "r+");

	//Check if it worked. Return if not
	if (file != NULL)
		status = 1;
	else
		return 1;

	//Read the 1st 32 bits, the block type should be there and should match the shb type.
	fread(&shb_check, sizeof(shb_check), 1, file);
	//If there was a reading error or the read returned something other than the SHB, we have a bad file
	if (ferror(file) || shb_check != SHB_TYPE) {
		status = -1;
		return 1;
	}
	//Read the length of the block. This may vary so we can't just blindly skip ahead
	fread(&block_length, sizeof(block_length), 1, file);
	//Skip to the section length
	fseek(file, 8, SEEK_CUR);
	//Read the length of the section.
	fread(&section_length, sizeof(section_length), 1, file);
	//Skip to end of section
	fseek(file, block_length + section_length, SEEK_SET);

	//Before setting up the EPB we need to check to see if we need padding so we can add that to the total size
	if (packet_length % 4 != 0) {
		padding_length = 4 - (packet_length % 4);
	}

	//Set up the EPB
	epb.block_type = EPB_TYPE;
	epb.block_length = EPB_MIN_LENGTH + packet_length + padding_length;
	//We create only 1 interface when setting up the file so interface_id stays 0 and points to that interface
	epb.interface_id = interface_id;
	//Get the current time. timespec_get is C11 and will get time in seconds and nanoseconds, rounded to the system clock resolution. Best option. Getting good time in C isn't easy
	timespec_get(&system_time, TIME_UTC);
	//Now we need time in microseconds. For that we multiply time in seconds x 10^6 and add nanoseconds divided by 10^3
	time_micros=1000000L * system_time.tv_sec + system_time.tv_nsec / 1000; //I hope this works
	epb.timestamp_low = time_micros & 0x00000000FFFFFFFF;
	epb.timestamp_high = time_micros >> 32;

	epb.captured_packet_length = packet_length;
	epb.original_packet_length = packet_length;
	//Add EPB length to section_length
	section_length += epb.block_length;
	//Now our EPB is ready and we can write it
	fwrite(&(epb), sizeof(epb), 1, file);
	//Write the packet portion
	fwrite(packet, packet_length, 1, file);
	//Write the padding portion
	if (padding_length != 0)
		fwrite(&pad, sizeof(pad), padding_length, file);
	//For now we don't have options so we just write the length again
	fwrite(&(epb.block_length), sizeof(epb.block_length), 1, file);
	//Seek to the SHB section length and write the new length
	fseek(file, SECTION_LENGTH_BEGIN, SEEK_SET);
	fwrite(&section_length, sizeof(section_length), 1, file);

	//Close the file
	fclose(file);

	lua_pushinteger(L, status);
	return 1;
}

//Black marker takes a string if RAW bytes, its length, and the number of bits to set to 0 starting from the bottom
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

//Calculates a correct ipv4 checksum from an IPv4 header
//Usage in Lua: calculate_ipv4_checksum(IPv4_header)
static int calculate_ipv4_checksum(lua_State *L) {
	const char *header;
	uint8_t length;
	char checksum[2];
	int checksum_offset = 10; //This is where in the header we'll find the checksum.
	uint32_t tmp_res = 0;
	uint16_t tmp_val = 0;
	uint16_t result = 0;
	int i;
	//Get the header
	header = luaL_checkstring(L, 1);
	//Version and Internet Header Length are in the 1st byte. Length is the lower 4 bits, so the mask 0x0F gets rid of the top 4 bits
	length = *header & 0x0F;
	//The Internet Header Length is a Length in 32-bit words, we need bytes so we're multiplying by 4
	length *= 4;

	for (i = 0; i < length; i += 2) {
		//We skip adding the checksum bytes because the checksum is considered zero for this purpose
		if (i == checksum_offset)
			continue;
		memcpy(&tmp_val, header + i, 2);
		tmp_res += tmp_val;
		//The checksum is calculated by adding 16-bit words together and adding any overflow into the least significant bit
		//Here we do this by checking if the value exceeds or is equal to the value of 2^16, which would mean bit 17 is set
		//If it is, we subtract 65536 from the 32-bit integer, which is equivalent to unsetting bit 17 and then adding 1
		//This can still result in bit 17 being set, so it needs to be done twice to make sure, but not more than that.
		if (tmp_res >= 65536)
			tmp_res -= 65535;
		if (tmp_res >= 65536)
			tmp_res -= 65535;
	}
	//When we're done adding all the 16-bit words together, we need to produce their complement.
	//We add the value of tmp to the result which is appropriately sized, then invert it
	result += tmp_res;
	result = ~result;

	//Copy the result into our checksum string
	memcpy(checksum, &result, 2);

	lua_pushlstring(L, checksum, 2);

	return 1;
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
	length=luaL_checknumber(L,2);
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
	if (PKCS5_PBKDF2_HMAC(bytes, length, (unsigned char *) salt,
			strlen(salt), iterations, EVP_sha256(), length,
			(unsigned char *) result) <= 0) {
		crypto_cleanup();
		lua_pushinteger(L, status);
		lua_pushlstring(L, '\0', 1);
		free(result);
		return 2;
	}
	crypto_cleanup();
	status=1;
	//Push the status and result
	lua_pushinteger(L, status);
	lua_pushlstring(L, result, length);
	free(result);
	return 2;
}



//To register library with lua
static const struct luaL_Reg library[] = { { "create_filesystem",
		create_filesystem }, { "add_interface", add_interface }, {
		"write_packet", write_packet }, { "black_marker", black_marker }, {
		"calculate_ipv4_checksum", calculate_ipv4_checksum }, { "HMAC", HMAC },
		{ NULL, NULL } };

//Function to register library
int luaopen_libMasterarbeit(lua_State *L) {
	luaL_newlib(L, library);
	return 1;
}
