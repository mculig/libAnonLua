# libAnonLua
A Lua library for network trace anonymization with support for creating pcapng files.

**Note:** All strings of bytes (string_raw) accepted by functions are assumed to be strings holding raw bytes such as returned by Wireshark's tvb:range(a,b):bytes():raw() and **NOT** textual representations of these bytes (such as hex) 

## Currently supported methods:

**create_filesystem(string path)**

Creates a pcapng file at path with a Section Header Block

**Returns:** 1 on success, -1 on failure

---

**add_interface(string path, LINKTYPE type)**

Adds an Interface Description Block to the pcapng file located at path with the link type set to LINKTYPE. Linktypes can be found at https://www.tcpdump.org/linktypes.html

Example: add_interface("file.pcapng", libAnonLua.LINKTYPE_ETHERNET)

**Returns:** 1 on success, -1 on failure

---

**write_packet(string path, string_raw packet_bytes, integer packet_size, integer IDB ID)**

Adds an Enhanced Packet Block to the pcapng file located at path with the interface ID set to IDB ID with a packet payload containing packet_bytes

**Returns:** 1 on success, -1 on failure

---

**black_marker(string_raw bytes, int bytes_length, int mask_length, int direction)**

Sets the mask_length least significant (direction=0) or most significant(direction=1) bits to 0

**Returns:** Masked field as a string of RAW bytes

---

**calculate_ipv4_checksum(string_raw header)**

Calculates the correct checksum for the provided (whole) ipv4 header. The header needs to be in the form of RAW bytes as a string. These can be fetched from a ByteArray in the Wireshark API by using ByteArray:raw()

**Returns:** Checksum (2-byte raw string), Provided header with correct checksum (raw string)

---

**calculate_tcp_udp_checksum(string_raw IP_packet)**

Calculates the correct TCP or UDP checksum based on the provided (whole) IPv4 or IPv6 packet. The entirety of the packet, including payload (TCP/UDP header and data) is necessary to calculate this checksum. 

**Returns:** Checksum (2-byte raw string), Provided TCP/UDP header with correct checksum (raw string) + payload (whole TCP/UDP segment)

---

**HMAC(string_raw bytes, int bytes_length, string salt, int iterations)**

Calculates a SHA256 PBKDF2 HMAC with iterations iterations of the provided bytes that is bytes_length long and salted with salt. 

**Returns:** Status (-1 FAIL, 1 SUCCESS) and a string of bytes that is the output of the PBKDF2 HMAC function in case of success, or an empty string (‘\0’) on failure.

---

**init_cryptoPAN(string filename)**

Initializes the cryptoPAN algorithm. If the provided file exists 64 bytes are read from the file and returned as a string. If the file doesn't exist, then 64 pseudorandom bytes are read from /dev/urandom and written into a new file at filename, then returned as a string. These 64 bytes are used as the KEY, IV and PAD for the AES256 algorithm used by **cryptoPAN_anonymize_ipv4** and **cryptoPAN_anonymize_ipv6**

**Returns:** Status(-1 FAIL, 1 SUCCESS) and a string of 64 bytes from the file at filename or /dev/urandom, or an empty string ('\0') on failure.

---

**cryptoPAN_anonymize_ipv4(string_raw state, string_raw IPv4_address)**

Anonymizes the provided IPv4 address using the cryptoPAN algorithm.

**Returns:** Status (-1 FAIL, 1 SUCCESS) and the IPv4 address, or an empty string ('\0') on failure.

---

**cryptoPAN_anonymize_ipv6(string_raw state, string_raw IPv6_address)**

Anonymizes the provided IPv6 address using the cryptoPAN algorithm.

**Returns:** Status (-1 FAIL, 1 SUCCESS) and the IPv6 address, or an empty string ('\0') on failure.


