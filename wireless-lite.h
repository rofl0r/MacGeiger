#ifndef WIRELESS_LITE_H
#define WIRELESS_LITE_H

/* cleaned up from linux/wireless.h */

#include <net/if.h>

#define SIOCSIWFREQ 0x8B04
#define SIOCSIWMODE 0x8B06
#define SIOCGIWMODE 0x8B07

#define IW_FREQ_FIXED 0x01

#define IW_MODE_AUTO 0
#define IW_MODE_ADHOC 1
#define IW_MODE_INFRA 2
#define IW_MODE_MASTER 3
#define IW_MODE_REPEAT 4
#define IW_MODE_SECOND 5
#define IW_MODE_MONITOR 6
#define IW_MODE_MESH 7

struct iw_quality {
	unsigned char qual;
	unsigned char level;
	unsigned char noise;
	unsigned char updated;
};

struct iw_param {
	int value;
	unsigned char fixed;
	unsigned char disabled;
	unsigned short flags;
};

struct iw_point {
	void *pointer;
	unsigned short length;
	unsigned short flags;
};

struct iw_freq {
	int m;
	short e;
	unsigned char i;
	unsigned char flags;
};

union iwreq_data {
	char name[IFNAMSIZ];
	struct iw_point	essid;
	struct iw_param	nwid;
	struct iw_freq	freq;
	struct iw_param	sens;
	struct iw_param	bitrate;
	struct iw_param	txpower;
	struct iw_param	rts;
	struct iw_param	frag;
	unsigned mode;
	struct iw_param	retry;
	struct iw_point	encoding;
	struct iw_param	power;
	struct iw_quality qual;
	struct sockaddr	ap_addr;
	struct sockaddr	addr;
	struct iw_param	param;
	struct iw_point	data;
};

struct	iwreq {
	union {
		char ifrn_name[IFNAMSIZ];
	} ifr_ifrn;
	union iwreq_data u;
};

#define IEEE80211_FCTL_VERS             0x0003
#define IEEE80211_FCTL_FTYPE            0x000c
#define IEEE80211_FCTL_STYPE            0x00f0
#define IEEE80211_FCTL_TODS             0x0100
#define IEEE80211_FCTL_FROMDS           0x0200
#define IEEE80211_FCTL_MOREFRAGS        0x0400
#define IEEE80211_FCTL_RETRY            0x0800
#define IEEE80211_FCTL_PM               0x1000
#define IEEE80211_FCTL_MOREDATA         0x2000
#define IEEE80211_FCTL_PROTECTED        0x4000
#define IEEE80211_FCTL_ORDER            0x8000

#define IEEE80211_SCTL_FRAG             0x000F
#define IEEE80211_SCTL_SEQ              0xFFF0

#define IEEE80211_FTYPE_MGMT            0x0000
#define IEEE80211_FTYPE_CTL             0x0004
#define IEEE80211_FTYPE_DATA            0x0008

#define IEEE80211_STYPE_ASSOC_REQ       0x0000
#define IEEE80211_STYPE_ASSOC_RESP      0x0010
#define IEEE80211_STYPE_REASSOC_REQ     0x0020
#define IEEE80211_STYPE_REASSOC_RESP    0x0030
#define IEEE80211_STYPE_PROBE_REQ       0x0040
#define IEEE80211_STYPE_PROBE_RESP      0x0050
#define IEEE80211_STYPE_BEACON          0x0080
#define IEEE80211_STYPE_ATIM            0x0090
#define IEEE80211_STYPE_DISASSOC        0x00A0
#define IEEE80211_STYPE_AUTH            0x00B0
#define IEEE80211_STYPE_DEAUTH          0x00C0
#define IEEE80211_STYPE_ACTION          0x00D0

#define IEEE80211_STYPE_BACK_REQ        0x0080
#define IEEE80211_STYPE_BACK            0x0090
#define IEEE80211_STYPE_PSPOLL          0x00A0
#define IEEE80211_STYPE_RTS             0x00B0
#define IEEE80211_STYPE_CTS             0x00C0
#define IEEE80211_STYPE_ACK             0x00D0
#define IEEE80211_STYPE_CFEND           0x00E0
#define IEEE80211_STYPE_CFENDACK        0x00F0

#define IEEE80211_STYPE_DATA                    0x0000
#define IEEE80211_STYPE_DATA_CFACK              0x0010
#define IEEE80211_STYPE_DATA_CFPOLL             0x0020
#define IEEE80211_STYPE_DATA_CFACKPOLL          0x0030
#define IEEE80211_STYPE_NULLFUNC                0x0040
#define IEEE80211_STYPE_CFACK                   0x0050
#define IEEE80211_STYPE_CFPOLL                  0x0060
#define IEEE80211_STYPE_CFACKPOLL               0x0070
#define IEEE80211_STYPE_QOS_DATA                0x0080
#define IEEE80211_STYPE_QOS_DATA_CFACK          0x0090
#define IEEE80211_STYPE_QOS_DATA_CFPOLL         0x00A0
#define IEEE80211_STYPE_QOS_DATA_CFACKPOLL      0x00B0
#define IEEE80211_STYPE_QOS_NULLFUNC            0x00C0
#define IEEE80211_STYPE_QOS_CFACK               0x00D0
#define IEEE80211_STYPE_QOS_CFPOLL              0x00E0
#define IEEE80211_STYPE_QOS_CFACKPOLL           0x00F0

#endif

