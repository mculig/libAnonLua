/*
 * pcapngw.h
 *
 *  Created on: Sep 13, 2019
 *      Author: mislav
 */

#ifndef PCAPNGW_H_
#define PCAPNGW_H_

#include "stdio.h"
#include "stdint.h"
#include "time.h"
#include "stdint.h"
#include "string.h"

//Block types
#define SHB_TYPE 0x0A0D0D0A
#define SHB_BOM 0x1A2B3C4D
#define IDB_TYPE 0x00000001
#define EPB_TYPE 0x00000006

//Option types
#define OPT_COMMENT_TYPE 0x0001

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


//Functions

int create_pcapng_filesystem(const char* path);

int add_IDB(const char* path, int interface_type);

int add_EPB(const char *path, const char *packet_bytes, uint32_t packet_size, int IDB_ID, uint8_t use_own_timestamp, uint64_t timestamp, const char *comment_value, size_t comment_length);

#endif /* PCAPNGW_H_ */
