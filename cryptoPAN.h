/*
 * cryptoPAN.h
 *
 *  Created on: Sep 10, 2019
 *      Author: mislav
 */

#ifndef CRYPTOPAN_H_
#define CRYPTOPAN_H_

#include "openssl/evp.h"
#include "string.h"
#include "arpa/inet.h"
#include "stdio.h"
#include "libAnonLuaHelpers.h"

#define STATE_SIZE 64

int cryptoPAN_init(const char *filename, char *state);

int cryptoPAN_ipv4(uint32_t orig_addr, uint32_t *anon_addr,
		const unsigned char *m_pad, const unsigned char *key,
		const unsigned char *iv);

void ntoh_128(uint32_t *address);
void hton_128(uint32_t *address);

int cryptoPAN_ipv6(uint32_t *orig_addr, uint32_t *anon_addr,
		const unsigned char *m_pad, const unsigned char *key, const unsigned char *iv);

#endif /* CRYPTOPAN_H_ */
