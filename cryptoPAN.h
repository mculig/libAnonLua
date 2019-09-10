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

void cryptoPAN_ipv4(uint32_t orig_addr, uint32_t *anon_addr, const unsigned char *m_pad, EVP_CIPHER_CTX *ctx);

void ntoh_128(uint32_t *address);
void hton_128(uint32_t *address);

void cryptoPAN_ipv6(uint32_t *orig_addr,uint32_t *anon_addr,  const unsigned char *m_pad, EVP_CIPHER_CTX *ctx);


#endif /* CRYPTOPAN_H_ */
