#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <net/if.h>
#include <stropts.h>
#include <unistd.h>

#define SIOCSIWFREQ 0x8B04
#define IW_FREQ_FIXED 0x01

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

/* returns 0 on success. */
int set_channel(const char* iface, int channel) {
	int s;
	if((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket");
		return 1;
	}

	struct iwreq req = {.u.freq.m = channel, .u.freq.flags = IW_FREQ_FIXED};
	snprintf(req.ifr_name, IFNAMSIZ, "%s", iface);

	int ret;
	if((ret = ioctl(s, SIOCSIWFREQ, &req) < 0)) perror("ioctl");
	close(s);
	return ret;
}

#ifndef LIBRARY_CODE
static int usage(char* argv0) {
	dprintf(2, "usage: %s interface channel\n", argv0);
	return 1;
}

int main(int argc, char** argv) {
	if(argc != 3) return usage(argv[0]);
	return set_channel(argv[1], atoi(argv[2]));
}
#endif

