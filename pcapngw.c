/*
 * pcapngw.c
 *
 *  Created on: Sep 13, 2019
 *      Author: mislav
 */

#include "pcapngw.h"

int create_pcapng_filesystem(const char* path) {
	FILE* file;
	SHB shb = { SHB_TYPE, SHB_MIN_LENGTH, SHB_BOM, 1, 0, 0 };
	//Try to open the file
	file = fopen(path, "wb");
	//Check if it worked. Return if not
	if (file == NULL)
		return -1;
	//Write our SHB to the file
	fwrite(&shb, sizeof(shb), 1, file);
	//Blocks end with variable length options followed by another block_length. For now, no options, so we end with length
	fwrite(&(shb.block_length), sizeof(shb.block_length), 1, file);
	//Close the file
	fclose(file);
	return 1;
}

int add_IDB(const char* path, int interface_type) {
	IDB idb = { IDB_TYPE, IDB_MIN_LENGTH, interface_type, 0, 0 };
	FILE *file;
	uint32_t shb_check;
	uint32_t block_length;
	uint64_t section_length;

	//Try to open the file
	file = fopen(path, "r+");
	//Check if it worked. Return if not
	if (file == NULL)
		return -1;

	//Read the 1st 32 bits, the block type should be there and should match the shb type.
	fread(&shb_check, sizeof(shb_check), 1, file);
	//If there was a reading error or the read returned something other than the SHB, we have a bad file
	if (ferror(file) || shb_check != SHB_TYPE) {
		return -1;
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

	return 1;

}

int add_EPB(const char *path,const char *packet_bytes, int packet_size, int IDB_ID) {

	FILE* file;
	uint32_t shb_check;
	uint32_t block_length;
	uint64_t section_length;
	int padding_length = 0;
	uint8_t pad = 0;
	struct timespec system_time;
	uint64_t time_micros;
	EPB epb;

	//Try to open the file
	file = fopen(path, "r+");

	//Check if it worked. Return if not
	if (file == NULL)
		return -1;

	//Read the 1st 32 bits, the block type should be there and should match the shb type.
	fread(&shb_check, sizeof(shb_check), 1, file);
	//If there was a reading error or the read returned something other than the SHB, we have a bad file
	if (ferror(file) || shb_check != SHB_TYPE) {
		return -1;
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
	if (packet_size % 4 != 0) {
		padding_length = 4 - (packet_size % 4);
	}

	//Set up the EPB
	epb.block_type = EPB_TYPE;
	epb.block_length = EPB_MIN_LENGTH + packet_size + padding_length;
	//We create only 1 interface when setting up the file so interface_id stays 0 and points to that interface
	epb.interface_id = IDB_ID;
	//Get the current time. timespec_get is C11 and will get time in seconds and nanoseconds, rounded to the system clock resolution. Best option. Getting good time in C isn't easy
	timespec_get(&system_time, TIME_UTC);
	//Now we need time in microseconds. For that we multiply time in seconds x 10^6 and add nanoseconds divided by 10^3
	time_micros = 1000000L * system_time.tv_sec + system_time.tv_nsec / 1000; //I hope this works
	epb.timestamp_low = time_micros & 0x00000000FFFFFFFF;
	epb.timestamp_high = time_micros >> 32;

	epb.captured_packet_length = packet_size;
	epb.original_packet_length = packet_size;
	//Add EPB length to section_length
	section_length += epb.block_length;
	//Now our EPB is ready and we can write it
	fwrite(&(epb), sizeof(epb), 1, file);
	//Write the packet portion
	fwrite(packet_bytes, packet_size, 1, file);
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

	return 1;

}
