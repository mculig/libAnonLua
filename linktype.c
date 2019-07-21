/*
 * linktype.c
 *
 *  Created on: Jul 20, 2019
 *      Author: mislav
 */

#include "linktype.h"
#include "string.h"


//Apparently the proper way to do this in C is indeed an ugly if-else ladder. Sucks :(
int headerLinkTypeValue(const char *name) {
	if (strcmp(name, "LINKTYPE_NULL") == 0)
		return 0;
	else if (strcmp(name, "LINKTYPE_ETHERNET") == 0)
		return 1;
	else if (strcmp(name, "LINKTYPE_AX25") == 0)
		return 3;
	else if (strcmp(name, "LINKTYPE_IEEE802_5") == 0)
		return 6;
	else if (strcmp(name, "LINKTYPE_ARCNET_BSD") == 0)
		return 7;
	else if (strcmp(name, "LINKTYPE_SLIP") == 0)
		return 8;
	else if (strcmp(name, "LINKTYPE_PPP") == 0)
		return 9;
	else if (strcmp(name, "LINKTYPE_FDDI") == 0)
		return 10;
	else if (strcmp(name, "LINKTYPE_PPP_HDLC") == 0)
		return 50;
	else if (strcmp(name, "LINKTYPE_PPP_ETHER") == 0)
		return 51;
	else if (strcmp(name, "LINKTYPE_ATM_RFC1483") == 0)
		return 100;
	else if (strcmp(name, "LINKTYPE_RAW") == 0)
		return 101;
	else if (strcmp(name, "LINKTYPE_C_HDLC") == 0)
		return 104;
	else if (strcmp(name, "LINKTYPE_IEEE802_11") == 0)
		return 105;
	else if (strcmp(name, "LINKTYPE_FRELAY") == 0)
		return 107;
	else if (strcmp(name, "LINKTYPE_LOOP") == 0)
		return 108;
	else if (strcmp(name, "LINKTYPE_LINUX_SLL") == 0)
		return 113;
	else if (strcmp(name, "LINKTYPE_LTALK") == 0)
		return 114;
	else if (strcmp(name, "LINKTYPE_PFLOG") == 0)
		return 117;
	else if (strcmp(name, "LINKTYPE_IEEE802_11_PRISM") == 0)
		return 119;
	else if (strcmp(name, "LINKTYPE_IP_OVER_FC") == 0)
		return 122;
	else if (strcmp(name, "LINKTYPE_SUNATM") == 0)
		return 123;
	else if (strcmp(name, "LINKTYPE_IEEE802_11_RADIOTAP") == 0)
		return 127;
	else if (strcmp(name, "LINKTYPE_ARCNET_LINUX") == 0)
		return 129;
	else if (strcmp(name, "LINKTYPE_APPLE_IP_OVER_IEEE1394") == 0)
		return 138;
	else if (strcmp(name, "LINKTYPE_MTP2_WITH_PHDR") == 0)
		return 139;
	else if (strcmp(name, "LINKTYPE_MTP2") == 0)
		return 140;
	else if (strcmp(name, "LINKTYPE_MTP3") == 0)
		return 141;
	else if (strcmp(name, "LINKTYPE_SCCP") == 0)
		return 142;
	else if (strcmp(name, "LINKTYPE_DOCSIS") == 0)
		return 143;
	else if (strcmp(name, "LINKTYPE_LINUX_IRDA") == 0)
		return 144;
	else if (strcmp(name, "LINKTYPE_USER0") == 0)
		return 147;
	else if (strcmp(name, "LINKTYPE_USER1") == 0)
		return 148;
	else if (strcmp(name, "LINKTYPE_USER2") == 0)
		return 149;
	else if (strcmp(name, "LINKTYPE_USER3") == 0)
		return 150;
	else if (strcmp(name, "LINKTYPE_USER4") == 0)
		return 151;
	else if (strcmp(name, "LINKTYPE_USER5") == 0)
		return 152;
	else if (strcmp(name, "LINKTYPE_USER6") == 0)
		return 153;
	else if (strcmp(name, "LINKTYPE_USER7") == 0)
		return 154;
	else if (strcmp(name, "LINKTYPE_USER8") == 0)
		return 155;
	else if (strcmp(name, "LINKTYPE_USER9") == 0)
		return 156;
	else if (strcmp(name, "LINKTYPE_USER10") == 0)
		return 157;
	else if (strcmp(name, "LINKTYPE_USER11") == 0)
		return 158;
	else if (strcmp(name, "LINKTYPE_USER12") == 0)
		return 159;
	else if (strcmp(name, "LINKTYPE_USER13") == 0)
		return 160;
	else if (strcmp(name, "LINKTYPE_USER14") == 0)
		return 161;
	else if (strcmp(name, "LINKTYPE_USER15") == 0)
		return 162;
	else if (strcmp(name, "LINKTYPE_IEEE802_11_AVS") == 0)
		return 163;
	else if (strcmp(name, "LINKTYPE_BACNET_MS_TP") == 0)
		return 165;
	else if (strcmp(name, "LINKTYPE_PPP_PPPD") == 0)
		return 166;
	else if (strcmp(name, "LINKTYPE_GPRS_LLC") == 0)
		return 169;
	else if (strcmp(name, "LINKTYPE_GPF_T") == 0)
		return 170;
	else if (strcmp(name, "LINKTYPE_GPF_F") == 0)
		return 171;
	else if (strcmp(name, "LINKTYPE_LINUX_LAPD") == 0)
		return 177;
	else if (strcmp(name, "LINKTYPE_MFR") == 0)
		return 182;
	else if (strcmp(name, "LINKTYPE_BLUETOOTH_HCI_H4") == 0)
		return 187;
	else if (strcmp(name, "LINKTYPE_USB_LINUX") == 0)
		return 189;
	else if (strcmp(name, "LINKTYPE_PPI") == 0)
		return 192;
	else if (strcmp(name, "LINKTYPE_IEEE802_15_4_WITHFCS") == 0)
		return 195;
	else if (strcmp(name, "LINKTYPE_SITA") == 0)
		return 196;
	else if (strcmp(name, "LINKTYPE_ERF") == 0)
		return 197;
	else if (strcmp(name, "LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR") == 0)
		return 201;
	else if (strcmp(name, "LINKTYPE_AX25_KISS") == 0)
		return 202;
	else if (strcmp(name, "LINKTYPE_LAPD") == 0)
		return 203;
	else if (strcmp(name, "LINKTYPE_PPP_WITH_DIR") == 0)
		return 204;
	else if (strcmp(name, "LINKTYPE_C_HDLC_WITH_DIR") == 0)
		return 205;
	else if (strcmp(name, "LINKTYPE_FRELAY_WITH_DIR") == 0)
		return 206;
	else if (strcmp(name, "LINKTYPE_LAPB_WITH_DIR") == 0)
		return 207;
	else if (strcmp(name, "LINKTYPE_IPMB_LINUX") == 0)
		return 209;
	else if (strcmp(name, "LINKTYPE_IEEE802_15_4_NONASK_PHY") == 0)
		return 215;
	else if (strcmp(name, "LINKTYPE_USB_LINUX_MMAPPED") == 0)
		return 220;
	else if (strcmp(name, "LINKTYPE_FC_2") == 0)
		return 224;
	else if (strcmp(name, "LINKTYPE_FC_2_WITH_FRAME_DELIMS") == 0)
		return 225;
	else if (strcmp(name, "LINKTYPE_IPNET") == 0)
		return 226;
	else if (strcmp(name, "LINKTYPE_CAN_SOCKETCAN") == 0)
		return 227;
	else if (strcmp(name, "LINKTYPE_IPV4") == 0)
		return 228;
	else if (strcmp(name, "LINKTYPE_IPV6") == 0)
		return 229;
	else if (strcmp(name, "LINKTYPE_IEEE802_15_4_NOFCS") == 0)
		return 230;
	else if (strcmp(name, "LINKTYPE_DBUS") == 0)
		return 231;
	else if (strcmp(name, "LINKTYPE_DVB_CI") == 0)
		return 235;
	else if (strcmp(name, "LINKTYPE_MUX27010") == 0)
		return 236;
	else if (strcmp(name, "LINKTYPE_STANAG_5066_D_PDU") == 0)
		return 237;
	else if (strcmp(name, "LINKTYPE_NFLOG") == 0)
		return 239;
	else if (strcmp(name, "LINKTYPE_NETANALYZER") == 0)
		return 240;
	else if (strcmp(name, "LINKTYPE_NETANALYZER_TRANSPARENT") == 0)
		return 241;
	else if (strcmp(name, "LINKTYPE_IPOIB") == 0)
		return 242;
	else if (strcmp(name, "LINKTYPE_MPEG_2_TS") == 0)
		return 243;
	else if (strcmp(name, "LINKTYPE_NG40") == 0)
		return 244;
	else if (strcmp(name, "LINKTYPE_NFC_LLCP") == 0)
		return 245;
	else if (strcmp(name, "LINKTYPE_INFINIBAND") == 0)
		return 247;
	else if (strcmp(name, "LINKTYPE_SCTP") == 0)
		return 248;
	else if (strcmp(name, "LINKTYPE_USBPCAP") == 0)
		return 249;
	else if (strcmp(name, "LINKTYPE_RTAC_SERIAL") == 0)
		return 250;
	else if (strcmp(name, "LINKTYPE_BLUETOOTH_LE_LL") == 0)
		return 251;
	else if (strcmp(name, "LINKTYPE_NETLINK") == 0)
		return 253;
	else if (strcmp(name, "LINKTYPE_BLUETOOTH_LINUX_MONITOR") == 0)
		return 254;
	else if (strcmp(name, "LINKTYPE_BLUETOOTH_BREDR_BB") == 0)
		return 255;
	else if (strcmp(name, "LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR") == 0)
		return 256;
	else if (strcmp(name, "LINKTYPE_PROFIBUS_DL") == 0)
		return 257;
	else if (strcmp(name, "LINKTYPE_PKTAP") == 0)
		return 258;
	else if (strcmp(name, "LINKTYPE_EPON") == 0)
		return 259;
	else if (strcmp(name, "LINKTYPE_IPMI_HPM_2") == 0)
		return 260;
	else if (strcmp(name, "LINKTYPE_ZWAVE_R1_R2") == 0)
		return 261;
	else if (strcmp(name, "LINKTYPE_ZWAVE_R3") == 0)
		return 262;
	else if (strcmp(name, "LINKTYPE_WATTSTOPPER_DLM") == 0)
		return 263;
	else if (strcmp(name, "LINKTYPE_ISO_14443") == 0)
		return 264;
	else if (strcmp(name, "LINKTYPE_RDS") == 0)
		return 265;
	else if (strcmp(name, "LINKTYPE_USB_DARWIN") == 0)
		return 266;
	else if (strcmp(name, "LINKTYPE_SDLC") == 0)
		return 268;
	else if (strcmp(name, "LINKTYPE_LORATAP") == 0)
		return 270;
	else if (strcmp(name, "LINKTYPE_VSOCK") == 0)
		return 271;
	else if (strcmp(name, "LINKTYPE_NORDIC_BLE") == 0)
		return 272;
	else if (strcmp(name, "LINKTYPE_DOCSIS31_XRA31") == 0)
		return 273;
	else if (strcmp(name, "LINKTYPE_ETHERNET_MPACKET") == 0)
		return 274;
	else if (strcmp(name, "LINKTYPE_DISPLAYPORT_AUX") == 0)
		return 275;
	else if (strcmp(name, "LINKTYPE_LINUX_SLL2") == 0)
		return 276;
	else if (strcmp(name, "LINKTYPE_OPENVIZSLA") == 0)
		return 278;
	else if (strcmp(name, "LINKTYPE_EBHSCR") == 0)
		return 279;
	else if (strcmp(name, "LINKTYPE_VPP_DISPATCH") == 0)
		return 280;
	else if (strcmp(name, "LINKTYPE_DSA_TAG_BRCM") == 0)
		return 281;
	else if (strcmp(name, "LINKTYPE_DSA_TAG_BRCM_PREPEND") == 0)
		return 282;
	else if (strcmp(name, "LINKTYPE_IEEE802_15_4_TAP") == 0)
		return 283;
	else if (strcmp(name, "LINKTYPE_DSA_TAG_DSA") == 0)
		return 284;
	else if (strcmp(name, "LINKTYPE_DSA_TAG_EDSA") == 0)
		return 285;
	else if (strcmp(name, "LINKTYPE_ELEE") == 0)
		return 286;
	else
		return 0;
}
