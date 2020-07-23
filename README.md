# libAnonLua
A Lua library for network trace anonymization with support for creating pcapng files.

## Required libraries

libAnonLua currently requires the following libraries in order to compile:

* liblua5.2-dev
* zlib1g-dev
* libssl-dev

These libraries may be named differently depending on your distribution

## Currently supported methods:

**Note:** All strings of bytes (string_raw) accepted by functions are assumed to be strings holding raw bytes such as returned by Wireshark's tvb:range(a,b):bytes():raw() and **NOT** textual representations of these bytes (such as hex) 

**create_filesystem(string path)**

Creates a pcapng file at path with a Section Header Block

**Returns:** 1 on success, -1 on failure

---

**add_interface(string path, LINKTYPE type)**

Adds an Interface Description Block to the pcapng file located at path with the link type set to LINKTYPE. Linktypes can be found at https://www.tcpdump.org/linktypes.html

Example: add_interface("file.pcapng", libAnonLua.LINKTYPE_ETHERNET)

**Returns:** Interface Description Block ID on success, -1 on failure

---

**write_packet(string path, string_raw packet_bytes, integer IDB ID, [double timestamp])**

Adds an Enhanced Packet Block to the pcapng file located at path with the interface ID set to IDB ID with a packet payload containing packet_bytes
An optional timestamp (in seconds) can be supplied. The timestamp is converted to nanoseconds via multiplication, then written to the file.
If a timestamp isn't provided, the current system time is used. 
This is done as a means of compatibility with Wireshark, where the timestamp (in seconds) can be retrieved using pinfo.abs_ts
An error of approximately 100ns was observed when testing, likely due to rounding. 

**Returns:** 1 on success, -1 on failure

---

**black_marker(string_raw bytes, int mask_length, int direction)**

Sets the mask_length least significant (direction=0 or libAnonLua.black_marker_LSB) or most significant(direction=1 or libAnonLua.black_marker_MSB) bits to 0

**Returns:** Masked field as a string of RAW bytes

---

**apply_mask(string_raw bytes, string_raw mask)**

Applies the provided mask to the provided bytes.

**Returns:** Masked field as a string of RAW bytes

---


**get_port_range(string_raw portNumber)**

Returns a value indicating the range a TCP or UDP port number came from

0 = Well-known ports
1024 = Registered ports
49152 = Ephemeral ports

**Returns:** Port range as string of RAW bytes

---

**calculate_eth_fcs(string_raw frame)**

Calculates the correct frame check sequence (FCS) for the provided ethernet frame using zlib's crc32() function. Returns the calculated checksum and the frame with the checksum appended at the end.
This function assumes the provided frame does NOT already have a FCS. If your capture card provides the FCS then you should remove the FCS before passing the frame to this function

**Returns:** Checksum (4-byte raw string), provided frame with correct checksum appended (raw string) 

---

**calculate_ipv4_checksum(string_raw header)**

Calculates the correct checksum for the provided (whole) ipv4 header. The header needs to be in the form of RAW bytes as a string. These can be fetched from a ByteArray in the Wireshark API by using ByteArray:raw()

**Returns:** Checksum (2-byte raw string), provided header with correct checksum (raw string)

---

**calculate_tcp_udp_checksum(string_raw IP_packet)**

Calculates the correct TCP or UDP checksum based on the provided (whole) IPv4 or IPv6 packet. The entirety of the packet, including payload (TCP/UDP header and data) is necessary to calculate this checksum. 

**Returns:** Checksum (2-byte raw string), Provided TCP/UDP header with correct checksum (raw string) + payload (whole TCP/UDP segment)

---

**calculate_icmp_checksum(string_raw ICMP_packet)**

Calculates the correct ICMP checksum based on the provided ICMP packet.

**Returns:** Checksum (2-byte raw string), Provided ICMP packet with correct checksum (raw string)

---

**calculate_icmpv6_checksum(string_raw IPv6_packet)**

Calculates the correct ICMPv6 checksum based on the provided (whole) IPv6 packet. ICMPv6 uses a pseudo-header like TCP and UDP to calculate the checksum, therefore the whole IPv6
packet is necessary to calculate the correct checksum.

**Returns:** Checksum (2-byte raw string), Provided IPv6 packet with correct ICMPv6 checksum (raw string)

---


**HMAC(string_raw bytes, string salt, int iterations)**

Calculates a SHA256 PBKDF2 HMAC with iterations iterations of the provided bytes that is bytes_length long and salted with salt. 

**Returns:** A string of bytes that is the output of the PBKDF2 HMAC function

---

**init_cryptoPAN(string filename)**

Initializes the cryptoPAN algorithm. If the provided file exists 64 bytes are read from the file. If the file doesn't exist, then 64 pseudorandom bytes are read from /dev/urandom and written into a new file at filename. These 64 bytes are used as the KEY, IV and PAD for the AES256 algorithm used by **cryptoPAN_anonymize_ipv4** and **cryptoPAN_anonymize_ipv6**

**Returns:** Status(-1 FAIL, 1 SUCCESS)

---

**cryptoPAN_anonymize_ipv4(string_raw IPv4_address)**

Anonymizes the provided IPv4 address using the cryptoPAN algorithm.

**Returns:** Status (-1 FAIL, 1 SUCCESS) and the IPv4 address, or an empty string ('\0') on failure.

---

**cryptoPAN_anonymize_ipv6(string_raw IPv6_address)**

Anonymizes the provided IPv6 address using the cryptoPAN algorithm.

**Returns:** Status (-1 FAIL, 1 SUCCESS) and the IPv6 address, or an empty string ('\0') on failure.

---

**ntop(string_raw address)**

Returns a human readable version of an IPv4 or IPv6 address as a string.

**Returns:** A human readable string representing an IPv4 or IPv6 address, or an empty string ('\0') on failure.

---

**ip_in_subnet(string_raw address, string CIDR_notation)**

Verifies if the provided address (in network order) is in the subnet provided in CIDR_notation as a string, i.e. 192.168.2.0/24 or ff80::0/64

**Returns:** Boolean indicating address is in subnet (true) or not (false)




