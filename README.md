# libAnonLua
A Lua library for network trace anonymization with support for creating pcapng files.

**Note:** All strings of bytes accepted by functions are assumed to be strings holding raw bytes such as returned by Wireshark's tvb:range(a,b):bytes():raw() and **NOT** textual representations of these bytes (such as hex) 

## Currently supported methods:

**create_filesystem(string path)**

Creates a pcapng file at path with a Section Header Block

**Returns:** 1 on success, -1 on failure

---

**add_interface(string path, string LINKTYPE_ name)**

Adds an Interface Description Block to the pcapng file located at path with the link type set to the type corresponding to LINKTYPE_name. Linktypes can be found at https://www.tcpdump.org/linktypes.html

**Returns:** 1 on success, -1 on failure

---

**write_packet(string path, string packet_bytes, integer packet_size, integer IDB ID)**

Adds an Enhanced Packet Block to the pcapng file located at path with the interface ID set to IDB ID with a packet payload containing packet_bytes

**Returns:** 1 on success, -1 on failure

---

**black_marker(string bytes, int bytes_length, int mask_length, int direction)**

Sets the mask_length least significant (direction=0) or most significant(direction=1) bits to 0

**Returns:** Masked field as a string of RAW bytes

---

**calculate_ipv4_checksum(string header)**

Calculates the correct checksum for the provided (whole) ipv4 header. The header needs to be in the form of RAW bytes as a string. These can be fetched from a ByteArray in the Wireshark API by using ByteArray:raw()

**Returns:** Checksum (2-byte raw string), Provided header with correct checksum (raw string)

---

**calculate_tcp_checksum_ipv4(string IP_packet)**

Calculates the correct TCP checksum based on the provided (whole) IPv4 packet. The entirety of the packet, including payload (TCP header and TCP data) is necessary to calculate this checksum. 

**Returns:** Checksum (2-byte raw string), Provided header with correct checksum (raw string)

---

**HMAC(string bytes, int bytes_length, string salt, int iterations)**

Calculates a SHA256 PBKDF2 HMAC with iterations iterations of the provided bytes that is bytes_length long and salted with salt. 

**Returns:** Status (-1 FAIL, 1 SUCCESS) and a string of bytes that is the output of the PBKDF2 HMAC function in case of success, or an empty string (‘\0’) on failure.
